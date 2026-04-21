#include <windows.h>

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR cmd, int show)
{
    (void)hi; (void)hp; (void)cmd; (void)show;

    char msg[256];
    DWORD pid = GetCurrentProcessId();

    wsprintfA(msg,
        "Process Ghosting SUCCESS!\n\n"
        "PID  : %lu\n"
        "This process was spawned from a ghost image.\n"
        "No CREATE_SUSPENDED. No disk artifact.",
        pid);

    MessageBoxA(NULL, msg, "[ GHOST ]", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
    return 0;
}
