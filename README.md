<div align="center">

# Process-Hollow

**A stealthy payload execution tool that chains Process Ghosting, Herpaderping, and PEB Masquerading.**

![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white) 
![Language](https://img.shields.io/badge/Language-C-00599C?style=for-the-badge&logo=c&logoColor=white) 
![Architecture](https://img.shields.io/badge/Architecture-x64_Only-ff69b4?style=for-the-badge&logo=amd&logoColor=white)
![Build](https://img.shields.io/badge/Build-MSVC_|_ML64-8C4FFF?style=for-the-badge&logo=visualstudio&logoColor=white)

</div>

<br/>

> [!WARNING]
> **For Authorized Red-Team Research Only**  
> This project was built for educational purposes and authorized penetration testing. The developer is not responsible for any malicious use.

##  core features

This tool is designed to bypass user-land hooks and evade EDR/AV scanners while maintaining a perfectly clean footprint in Task Manager. It implements a unique "Triple Combo" strategy:

*    **Process Ghosting (Direct Syscalls)**  
    Creates a section from a deleted/pending-delete file. Utilizes raw x64 assembly stubs (`asm_stubs.asm`) to trigger `NtCreateSection` directly, bypassing standard `ntdll.dll` API hooks entirely.
*    **Herpaderping**  
    Replaces the decoy file on disk with a legitimate, signed Microsoft binary (like `notepad.exe`). When an AV scans the file backing the process, it sees a clean, signed binary, while the payload executes in memory.
*    **PEB Masquerading & Icon Grafting**  
    Spoofs the PEB so the process appears as a harmless system process (e.g., `svchost.exe`) in Task Manager. It automatically pulls modern Store App icons via `SHGetFileInfo` and injects them into the decoy file, ensuring there are no suspicious "blank" icons.

---

##  build instructions

To utilize the direct assembly syscalls, **Visual Studio** with the "Desktop development with C++" workload is required (specifically for `ml64.exe`).

<details>
<summary><b>Click to expand compilation steps</b></summary>

1. Open the **x64 Native Tools Command Prompt for VS**.
2. Navigate to the project directory.
3. Run the automated build script:
   ```cmd
   build.bat
   ```

> [!NOTE]
> *You can compile with GCC/MinGW, but the tool will fall back to standard `ntdll` API calls instead of direct assembly syscalls, resulting in a loss of some stealth capabilities against aggressive user-land hooks.*

</details>

---

##  Usage

> [!IMPORTANT]
> **Only x64 payloads are supported.** 32-bit payloads will cause memory access violations due to PEB mismatching.

```cmd
ghost.exe <payload_path> [masquerade_target]
```

### Examples

**1. Default Masquerade** (Appears as `svchost.exe`)
```cmd
ghost.exe payload.exe
```

**2. Custom Masquerade** (Appears as `explorer.exe`)
```cmd
ghost.exe payload.exe explorer.exe
```

**3. Custom Masquerade** (Appears as `RuntimeBroker.exe`)
```cmd
ghost.exe payload.exe RuntimeBroker.exe
```

---
<div align="center">
  <i>Developed With ❤️ By ifrit.</i>
</div>
