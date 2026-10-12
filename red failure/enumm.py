from unicorn import *
from unicorn.x86_const import *

sc = open("sc.bin", "rb").read()

BASE  = 0x400000
STACK = 0x200000
uc = Uc(UC_ARCH_X86, UC_MODE_32)

uc.mem_map(BASE, 0x30000)
uc.mem_map(STACK, 0x30000)
uc.mem_write(BASE, sc)
uc.reg_write(UC_X86_REG_ESP, STACK + 0x8000)

try:
    uc.emu_start(BASE, BASE + len(sc), count=300)
except UcError as e:
    print("stopped:", e)  

dec = bytes(uc.mem_read(BASE, len(sc)))
print(dec)
