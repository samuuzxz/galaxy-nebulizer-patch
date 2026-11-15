# Galaxy Nebulizer — VMProtect License Bypass

Removes the VMProtect SDK licensing check from `galaxy-nebulizer.exe`.

## How it works

The binary is packed with VMProtect and uses `VMProtectSDK64.dll` for license validation. The PE import table is stripped by VMP, so a standard DLL stub alone won't load.

This patch:
1. **Injects a new import table** into the empty `.idata` section of the EXE, forcing Windows to load `hook.dll` at startup
2. **hook.dll** watches for VMP's runtime to load `VMProtectSDK64.dll`, then inline-hooks all 22 SDK functions with trampolines (`mov rax, addr; jmp rax`)
3. **VMProtectSDK64.dll** (stub) exports all expected functions returning success/valid — VMP's runtime loads it by name

All licensing calls (`SetSerialNumber`, `GetSerialNumberState`, `GetSerialNumberData`, etc.) return 0 / TRUE / valid state.

## Build (requires mingw cross-compiler)

```bash
# Install mingw
apt install gcc-mingw-w64-x86-64

# Build stub DLL
x86_64-w64-mingw32-gcc -shared -o VMProtectSDK64.dll VMProtectSDK64.c -Wl,--kill-at -s

# Build hook DLL
x86_64-w64-mingw32-gcc -shared -o hook.dll hook.c -s

# Patch the EXE (place galaxy-nebulizer.exe in this folder first)
python3 patch_pe.py
```

## Install

Put these 3 files in the same folder as the original EXE:
- `galaxy-nebulizer_patched.exe`
- `hook.dll`
- `VMProtectSDK64.dll`

Run `galaxy-nebulizer_patched.exe`.

If Windows Defender blocks: right-click each file → Properties → Unblock.

## Files

| File | Purpose |
|------|---------|
| `VMProtectSDK64.c` | Stub DLL source — exports all 22 VMP SDK functions |
| `hook.c` | Injected DLL — inline-hooks VMP SDK at runtime |
| `patch_pe.py` | Patches the EXE to add `hook.dll` import |
