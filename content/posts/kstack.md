+++
title = "Kstack seccon 2020"
date = "2021-03-22"
+++

So this week, I came across yet another kernel exploitation challenge and the reason I'm documenting the writeup (even if there're plenty of better ones available) is simply because I had to use multiple race conditions to get kernel instruction pointer.

# tl;dr

+ Abuse the `race condition` to leak kernel base.
+ Resuing the race condition , get write on `seq_operations` structure.
+ Write to `fd` of the `seq` structure using `setxattr`.
+ Pivot stack to userspace address since there is no SMAP.
+ Standard `commit_creds(prepare_kernel_creds(0))` ROP.

# Setting up the debug environment

+ Unpack `rootfs.cpio` with 

```sh
mkdir rootfs && cd rootfs
sudo su
cat ../rootfs.cpio | cpio --extract
```

+ Edit the `init` script , comment out the `echo 1` happening on `kptr_restrict` and `dmesg_restrict`.
+ Add the `setsid /bin/cttyhack setuidgid 0 /bin/sh` to get root for debugging.
+ Disable `kaslr` in the `runner` script.

Use this script to compile and copy exploit automatically in later stages.

```sh
#!/bin/bash

gcc -o exp exp.c --static -lpthread
cp exp rootfs
cd rootfs
find . | cpio -o -H newc > ../rootfs.cpio
cd ..
```

# Reversing

The author was benevolent enough to provide us with a self explanatory source code.

For the sake of brevity , we'll just look into the important part of it.

```c
static long proc_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  Element *tmp, *prev;
  int pid = task_tgid_nr(current);
  switch(cmd) {
  case CMD_PUSH:
    tmp = kmalloc(sizeof(Element), GFP_KERNEL);
    tmp->owner = pid;
    tmp->fd = head;
    head = tmp;
    if (copy_from_user((void*)&tmp->value, (void*)arg, sizeof(unsigned long))) {
      head = tmp->fd;
      kfree(tmp);
      return -EINVAL;
    }
    break;
  case CMD_POP:
    for(tmp = head, prev = NULL; tmp != NULL; prev = tmp, tmp = tmp->fd) {
      if (tmp->owner == pid) {
        if (copy_to_user((void*)arg, (void*)&tmp->value, sizeof(unsigned long)))
          return -EINVAL;
        if (prev) {
          prev->fd = tmp->fd;
        } else {
          head = tmp->fd;
        }
        kfree(tmp);
        break;
      }
      if (tmp->fd == NULL) return -EINVAL;
    }
    break;
  }
  return 0;
}
```
 
+ We have the `push` and `pop` operations.

### Push

+ The `push` operation first `kmalloc`s a chunk of `8` bytes.
+ It then tries to `copy_from_user` 8 bytes of data from userspace.
+ If `copy_from_user` fails , it `free`s the chunk that was allocated.

### Pop

+ Try to `copy_to_user` 8 bytes of `tmp->value`.
+ If it succeeds , the `head` pointer is appropriately set and finally `free` is called on the chunk on which `pop` was requested.

# Bug

There's no implementation bug as such in this small program , but if you see , the `ioctl` operations dont have any locks and hence we can request multiple operations at once using two threads.

# Exploit

The idea is that we execute a multi-stage exploit to successively leak and get write on a useful structure. So how do we go about doing this?

By making use of the race condition, we can actually invoke a double free.

+ If we call a `pop` operation on an untouched memory region, we can trigger a pagefault in `copy_to_user`, and this opens up a race window for exploitation.
+ So , if we can monitor this untouched memory region from another thread, we can very well handle this page fault and do some more operations until the page fault is fixed and control is transferred back to `pop` function.


```
                                            ┌───────────────────────────────────┐     ┌─────────────────────┐
                                            │                                   │     │                     │
                            ┌──────────────►│ page_fault   -> call pop on valid ├────►│ calls free(chunk)   │
                            │               │   handler            memory       │     │ after copy_from_user│
                            │               │                                   │     │                     │
                       ┌────┴──────┐        └─────────────────────────────┬─────┘     └────┬────────────────┘
                       │ page_fault│                                      │                │
                       │           │                                      │  return back   │
                       └───────────┘                                      └───────┬────────┘
                             ▲                                                    │
                             │                                                    │
                             │                                                    │ page_fault handler returns 
┌───────────────┐    ┌───────┴─────────┐                                  ┌───────▼──────────────┐
│               │    │                 │                                  │                      │
│pop(race_page) ├───►│  copy_from_user ├─────────────────────────────────►│   free(chunk)        │
│               │    │                 │                                  │                      │
└───────────────┘    │                 │                                  │                      │
                     └─────────────────┘                                  └──────────────────────┘

```

To manage page faults from userspcace , the kernel provides us with `userfaultfd`. With `userfaultfd`, we can monitor an mmaped page from another thread and handle our page faults.

# Going for leaks

The issue here is that, copy_from_user and copy_to_user write and read from the next 8 bytes of a chunk , so we can't really leak normally by getting allocation on a useful structure. Another reason is that, `copy_from` functions will null out memory. So, our ultimate option is to leak memory via race condition.

To do so, 

+ open and close a couple of `/proc/self/stat` , nothing but our `seq_operations` structure. This will make sure our next `kmalloc` allocates from a freed structure which has kernel pointers.
+ Initialize `userfaultfd` on our race page , in this case `0xf00d000`.
+ `push` a value and call pop on our race page which will cause a page fault in `copy_from_user`.
+ In the fault handler , we immediately call `pop` on a valid address and successfully leak kernel pointer. 


# Double free to RIP

After we leak , we can find a suitable stack pivot gadget from the kernel. Similarly , we can now cause a double free in heap , and using that,  we get overlapping of `seq_operations` and `setxattr` structures. The reason for chosing this overlap is that , `setxattr` lets us write 8 bytes to the fd of our chunk with it's `size` field. 

So , using this , we can overwrite the kernel function pointer at the fd of our `seq_operations` structure and get RIP by calling `read` on the file descriptor of the opened structure.

## Short Info 

I had a good time (with all due pun intended) debugging the kernel and source code auditing of `setxattr` as I had repeated kernel panics due to a silly mistake I had made in my script. But this debugging led me to another fruitful result.

Internally, `setxattr` calls `kmalloc` and `kfree` in the end after setting the fd. The `fd` pointer actually gets overwritten with a kernel executable address which points very close to a `ret` instruction. So , what happens is , when read is called on the fd , it actually executes the fd pointer first , but it returns immediately and then executes `fd + 0x18` pointer. This is the offset which actually gives us the RIP control.

Hence , the idea is to spray our gadget all over the `seq_operations` structure.

# Conclusion

The idea of the challenge was something different from a normal race condition. Kudos to the author for such a cool challenge.

[Here](https://gist.github.com/PwnVerse/a0ebb13bec35b867b70d0a2a49e91f22) is the complete exploit.
