yout: "post"
title: "pprofile Line CTF 2021" 
date: 2021-3-22
tags: [Linux Kernel,SMEP,SMAP,Modprobe Path]
---                                              

This is yet another great kernel challenge that drew my attention now and then. So, I decided to do a writeup since the bug is fairly hidden in one of the kernel functions itself.

# tl;dr

+ Trigger oob write using the `put_user_size`.
+ Overwrite `modprobe_path` into a writeable path to execute script as root without memory leak.


# Reversing

## pprofile ioctl

The module implements ioctl which lets us do 3 types of operations.

`Register`, `Remove` and `Show`.

### Register

```c
uint64_t to;
uint64_t from;
uint64_t storages[16] = {0};
char data[8];
void pprofile_ioctl(uint64_t a1,uint64_t cmd){
    if(copy_from_user(to,from,16)){
        return -1;
    }
    switch(cmd){
        case 32:
            int ret = strncpy_from_user(data,to,8);
            if(ret && ret!=9){
                if(ret >= 0){
                    int i=0;
                    while(1){
                        if(!storages[i])
                            break;
                        if(++i==16)
                            return -11;
                    }
```

+ Copy 8 bytes of data from user, check if number of bytes copied if greater than 0 and not equal to 9.
+ Get an empty slot in the storages.


```c
uint64_t *s = storages;
while(!*s || strcmp(**s,data)){
	if(&storages[16] == ++s){
		int n = strlen((char *)data);
		if(n>8)
			return -11;
		unsigned int size = n+1;
		unsigned long *kptr = kmalloc(size,GFP_KERNEL);
		if(!kptr)
			return -12;
```

+ Keep iterating until the 16th storage.
+ `kmalloc` a size of the string length of the data acquired from the userspace.

```c
if(size>=8){
	*(unsigned long *)((char *)kptr + size - 8) = 0;
	if(n>=8){
		int j=0;
		do{
			*(unsigned long *)((char *)kptr + j) = 0;
			j+=8;
		}
		while(j < (n & 0xfffffff8));
	}
}
```

+ Check if size is greater than or equal to 8, if so, null out the kmalloc memory.
+ If string length is greater than or equal to 8, in a while loop, null out memory.


```c
else if(size & 4){
	*kptr = 0;
	*(unsigned int *)((char *)kptr + size - 4) = 0;
}
else if(n!=-1){
	*(char *)kptr = 0;
	if(size & 2)
		*(unsigned short *)((char *)kptr + size - 2) = 0;
}
```

+ Check if size is inbetween 4 and 7, and if it is, 
