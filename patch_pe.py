"""
Patch galaxy-nebulizer.exe:
1. Build a minimal import table for hook.dll in the empty .idata section
2. Point the PE import directory to it
"""
import struct, shutil

src = 'galaxy-nebulizer.exe'
dst = 'galaxy-nebulizer_patched.exe'
shutil.copy2(src, dst)

with open(dst, 'r+b') as f:
    data = bytearray(f.read())

pe_off = struct.unpack_from('<I', data, 0x3c)[0]
image_base = struct.unpack_from('<Q', data, pe_off + 24 + 24)[0]

# .idata section: VA=0x011a2000 RawOff=0x007b2000 RawSize=0x00009600
idata_va  = 0x011a2000
idata_raw = 0x007b2000

# Build import table at the start of .idata (it's all zeros)
# Layout:
# 0x00: IMAGE_IMPORT_DESCRIPTOR for hook.dll (20 bytes)
# 0x14: null IMAGE_IMPORT_DESCRIPTOR (20 bytes)
# 0x28: ILT entry 0 — RVA to hint/name (8 bytes)
# 0x30: ILT null terminator (8 bytes)
# 0x38: IAT entry 0 — same as ILT (8 bytes)
# 0x40: IAT null terminator (8 bytes)
# 0x48: DLL name "hook.dll\0" (16 bytes padded)
# 0x58: Hint(2) + "Init\0" + pad (8 bytes)

ilt_rva       = idata_va + 0x28
iat_rva       = idata_va + 0x38
dll_name_rva  = idata_va + 0x48
hint_name_rva = idata_va + 0x58

# IMAGE_IMPORT_DESCRIPTOR
desc = struct.pack('<IIIII', ilt_rva, 0, 0, dll_name_rva, iat_rva)
off = idata_raw
data[off:off+20] = desc
off += 20

# Null terminator descriptor
data[off:off+20] = b'\x00' * 20
off += 20

# ILT
struct.pack_into('<Q', data, idata_raw + 0x28, hint_name_rva)
struct.pack_into('<Q', data, idata_raw + 0x30, 0)

# IAT
struct.pack_into('<Q', data, idata_raw + 0x38, hint_name_rva)
struct.pack_into('<Q', data, idata_raw + 0x40, 0)

# DLL name
dll_name = b'hook.dll\x00\x00\x00\x00\x00\x00\x00\x00'
data[idata_raw + 0x48:idata_raw + 0x58] = dll_name

# Hint/Name
struct.pack_into('<H', data, idata_raw + 0x58, 0)  # Hint = 0
init_name = b'Init\x00\x00'
data[idata_raw + 0x5a:idata_raw + 0x60] = init_name

# Update PE import directory RVA and size
struct.pack_into('<I', data, pe_off + 24 + 104, idata_va)      # Import RVA
struct.pack_into('<I', data, pe_off + 24 + 108, 0x28)          # Import Size (1 desc + null = 40 bytes)

print(f"Import dir set to RVA 0x{idata_va:08x}")
print(f"hook.dll import: ILT=0x{ilt_rva:08x} IAT=0x{iat_rva:08x} Name=0x{dll_name_rva:08x}")

with open(dst, 'wb') as f:
    f.write(data)

print(f"Written {dst}")
