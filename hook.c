#include <windows.h>
#include <string.h>

static void patch_bytes(void* addr, const void* buf, size_t len) {
    DWORD old;
    VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old);
    memcpy(addr, buf, len);
    VirtualProtect(addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
}

static void inline_hook(void* target, void* detour) {
    unsigned char code[12] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xE0
    };
    *(UINT_PTR*)(code + 2) = (UINT_PTR)detour;
    patch_bytes(target, code, 12);
}

/* stubs — all licensing calls return "valid / success" */
static int  __cdecl s_SetSerial(const char* s)       { return 0; }
static int  __cdecl s_GetState(void)                  { return 0; }
static BOOL __cdecl s_GetData(void* d, int sz)        { if(d&&sz>0) memset(d,0,sz); return TRUE; }
static int  __cdecl s_GetHWID(char* b, int sz)        { if(b&&sz>0){strncpy(b,"AAAA-BBBB",sz-1);b[sz-1]=0;} return 9; }
static int  __cdecl s_Activate(const char* c,char* s,int sz) { if(s&&sz>0) s[0]=0; return 0; }
static int  __cdecl s_Deactivate(const char* s,char* o,int sz) { return 0; }
static BOOL __cdecl s_IsProtected(void)               { return TRUE; }
static BOOL __cdecl s_IsValidCRC(void)                { return TRUE; }
static BOOL __cdecl s_IsDebugger(void)                { return FALSE; }
static BOOL __cdecl s_IsVM(void)                      { return FALSE; }
static void __cdecl s_Begin(const char* n)            {}
static void __cdecl s_End(void)                       {}
static const char*    __cdecl s_DecryptA(const char* s)    { return s; }
static const wchar_t* __cdecl s_DecryptW(const wchar_t* s) { return s; }
static BOOL __cdecl s_FreeStr(void* s)                { return TRUE; }
static int  __cdecl s_Offline(const char* c,char* b,int sz) { if(b&&sz>0) b[0]=0; return 0; }

static void hook_module(HMODULE vmp) {
    struct { const char* name; void* detour; } tbl[] = {
        {"VMProtectSetSerialNumber",              s_SetSerial},
        {"VMProtectGetSerialNumberState",          s_GetState},
        {"VMProtectGetSerialNumberData",           s_GetData},
        {"VMProtectGetCurrentHWID",                s_GetHWID},
        {"VMProtectActivateLicense",               s_Activate},
        {"VMProtectDeactivateLicense",             s_Deactivate},
        {"VMProtectIsProtected",                   s_IsProtected},
        {"VMProtectIsValidImageCRC",               s_IsValidCRC},
        {"VMProtectIsDebuggerPresent",             s_IsDebugger},
        {"VMProtectIsVirtualMachinePresent",       s_IsVM},
        {"VMProtectBegin",                         s_Begin},
        {"VMProtectBeginMutation",                 s_Begin},
        {"VMProtectBeginUltra",                    s_Begin},
        {"VMProtectBeginUltraLockByKey",           s_Begin},
        {"VMProtectBeginVirtualization",           s_Begin},
        {"VMProtectBeginVirtualizationLockByKey",  s_Begin},
        {"VMProtectEnd",                           s_End},
        {"VMProtectDecryptStringA",                s_DecryptA},
        {"VMProtectDecryptStringW",                s_DecryptW},
        {"VMProtectFreeString",                    s_FreeStr},
        {"VMProtectGetOfflineActivationString",    s_Offline},
        {"VMProtectGetOfflineDeactivationString",  s_Offline},
    };
    for (int i = 0; i < sizeof(tbl)/sizeof(tbl[0]); i++) {
        FARPROC a = GetProcAddress(vmp, tbl[i].name);
        if (a) inline_hook((void*)a, tbl[i].detour);
    }
}

static DWORD WINAPI watcher(LPVOID p) {
    for (int i = 0; i < 600; i++) {
        HMODULE m = GetModuleHandleA("VMProtectSDK64.dll");
        if (!m) m = GetModuleHandleA("VMProtectSDK64");
        if (m) { hook_module(m); return 0; }
        Sleep(50);
    }
    return 1;
}

__declspec(dllexport) void __cdecl Init(void) {}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        HMODULE m = GetModuleHandleA("VMProtectSDK64.dll");
        if (m) {
            hook_module(m);
        } else {
            CreateThread(NULL, 0, watcher, NULL, 0, NULL);
        }
    }
    return TRUE;
}
