#include <windows.h>
#include <stdio.h>

/*
 * loader.exe — starts the real exe suspended, injects hook.dll,
 * then resumes. classic DLL injection via CreateRemoteThread.
 *
 * Usage: place in same folder as the real exe.
 *   real exe: galaxy-nebulizer_1.exe  (original, unchanged)
 *   this:     galaxy-nebulizer_patched.exe  (the launcher)
 *   also:     hook.dll + VMProtectSDK64.dll
 */

int main(void) {
    char exe_path[MAX_PATH];
    char dll_path[MAX_PATH];
    char dir[MAX_PATH];

    /* get our own directory */
    GetModuleFileNameA(NULL, dir, MAX_PATH);
    char* slash = strrchr(dir, '\\');
    if (slash) *(slash + 1) = 0;

    /* target exe */
    snprintf(exe_path, MAX_PATH, "%sgalaxy-nebulizer_1.exe", dir);
    snprintf(dll_path, MAX_PATH, "%shook.dll", dir);

    /* verify files exist */
    if (GetFileAttributesA(exe_path) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxA(NULL, "galaxy-nebulizer_1.exe not found!\nPlace this launcher in the same folder.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    if (GetFileAttributesA(dll_path) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxA(NULL, "hook.dll not found!\nPlace hook.dll in the same folder.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    /* start process suspended */
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(exe_path, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, dir, &si, &pi)) {
        MessageBoxA(NULL, "Failed to start galaxy-nebulizer_1.exe", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    /* allocate memory in target for DLL path */
    size_t dll_path_len = strlen(dll_path) + 1;
    LPVOID remote_buf = VirtualAllocEx(pi.hProcess, NULL, dll_path_len,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        MessageBoxA(NULL, "VirtualAllocEx failed", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    /* write DLL path into target */
    WriteProcessMemory(pi.hProcess, remote_buf, dll_path, dll_path_len, NULL);

    /* get LoadLibraryA address (same in all processes) */
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC load_lib = GetProcAddress(k32, "LoadLibraryA");

    /* inject: create remote thread calling LoadLibraryA(dll_path) */
    HANDLE remote_thread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                               (LPTHREAD_START_ROUTINE)load_lib,
                                               remote_buf, 0, NULL);
    if (!remote_thread) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        MessageBoxA(NULL, "CreateRemoteThread failed", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    /* wait for injection to complete */
    WaitForSingleObject(remote_thread, 5000);
    CloseHandle(remote_thread);

    /* free the remote buffer */
    VirtualFreeEx(pi.hProcess, remote_buf, 0, MEM_RELEASE);

    /* resume the main thread */
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
