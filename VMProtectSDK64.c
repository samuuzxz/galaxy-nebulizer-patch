#include <windows.h>
#include <string.h>

// VMP Serial Number States
#define SERIAL_STATE_SUCCESS 0

// VMP Licensing return codes
#define VMP_OK 0

// HWID buffer
static const char FAKE_HWID[] = "AAAA-BBBB-CCCC-DDDD";

// Serial number data structure (VMP SDK layout)
#pragma pack(push, 1)
typedef struct {
    int    nState;
    wchar_t wUserName[256];
    wchar_t wEMail[256];
    DWORD  dwExpDate;
    DWORD  dwMaxBuildDate;
    int    bRunningTimeLimit;
    BYTE   bUserData[255];
    int    nUserDataLength;
} VMProtectSerialNumberData;
#pragma pack(pop)

__declspec(dllexport) int __cdecl VMProtectSetSerialNumber(const char* serial) {
    return VMP_OK;
}

__declspec(dllexport) int __cdecl VMProtectGetSerialNumberState(void) {
    return SERIAL_STATE_SUCCESS;
}

__declspec(dllexport) BOOL __cdecl VMProtectGetSerialNumberData(VMProtectSerialNumberData* data, int size) {
    if (data && size >= (int)sizeof(VMProtectSerialNumberData)) {
        memset(data, 0, sizeof(VMProtectSerialNumberData));
        data->nState = SERIAL_STATE_SUCCESS;
        wcscpy(data->wUserName, L"Licensed");
        wcscpy(data->wEMail, L"licensed@local");
        data->dwExpDate = 0xFFFFFFFF;
        data->dwMaxBuildDate = 0xFFFFFFFF;
    }
    return TRUE;
}

__declspec(dllexport) int __cdecl VMProtectGetCurrentHWID(char* hwid, int size) {
    if (hwid && size > 0) {
        strncpy(hwid, FAKE_HWID, size - 1);
        hwid[size - 1] = 0;
        return (int)strlen(FAKE_HWID);
    }
    return (int)strlen(FAKE_HWID);
}

__declspec(dllexport) int __cdecl VMProtectActivateLicense(const char* code, char* serial, int size) {
    if (serial && size > 0) {
        strncpy(serial, "ACTIVATED", size - 1);
        serial[size - 1] = 0;
    }
    return VMP_OK;
}

__declspec(dllexport) int __cdecl VMProtectDeactivateLicense(const char* serial, char* out, int size) {
    return VMP_OK;
}

__declspec(dllexport) int __cdecl VMProtectGetOfflineActivationString(const char* code, char* buf, int size) {
    if (buf && size > 0) buf[0] = 0;
    return VMP_OK;
}

__declspec(dllexport) int __cdecl VMProtectGetOfflineDeactivationString(const char* serial, char* buf, int size) {
    if (buf && size > 0) buf[0] = 0;
    return VMP_OK;
}

__declspec(dllexport) BOOL __cdecl VMProtectIsProtected(void) {
    return TRUE;
}

__declspec(dllexport) BOOL __cdecl VMProtectIsValidImageCRC(void) {
    return TRUE;
}

__declspec(dllexport) BOOL __cdecl VMProtectIsDebuggerPresent(void) {
    return FALSE;
}

__declspec(dllexport) BOOL __cdecl VMProtectIsVirtualMachinePresent(void) {
    return FALSE;
}

__declspec(dllexport) void __cdecl VMProtectBegin(const char* name) {}
__declspec(dllexport) void __cdecl VMProtectBeginMutation(const char* name) {}
__declspec(dllexport) void __cdecl VMProtectBeginUltra(const char* name) {}
__declspec(dllexport) void __cdecl VMProtectBeginUltraLockByKey(const char* name) {}
__declspec(dllexport) void __cdecl VMProtectBeginVirtualization(const char* name) {}
__declspec(dllexport) void __cdecl VMProtectBeginVirtualizationLockByKey(const char* name) {}
__declspec(dllexport) void __cdecl VMProtectEnd(void) {}

__declspec(dllexport) const char* __cdecl VMProtectDecryptStringA(const char* s) {
    return s;
}

__declspec(dllexport) const wchar_t* __cdecl VMProtectDecryptStringW(const wchar_t* s) {
    return s;
}

__declspec(dllexport) BOOL __cdecl VMProtectFreeString(void* str) {
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}
