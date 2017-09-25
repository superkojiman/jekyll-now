---
layout: post
title: "Codefest CTF 2017: Rick's Secure Scheme writeup"
date: 2017-09-24 09:35:08 -0400
comments: true
categories: ctf
---

Last week I was invited by the [Defcon Toronto](https://twitter.com/defcon_toronto) team to play at Codefest 2017 CTF. There were some pretty good challenges, but unfortunately the CTF was plagued with frustrating issues like an unresponsive website, and no easy way to communicate with admins. 

This was the only pwnable in the CTF and it was worth 300 points. The instructions on how to submit the flag were confusing and changed at some point during the competition. Initially it said:

> Flag is 'flag{md5 of the integer value of the pass concatenated}'

At some point this changed to:

>  flag is now md5 of the secret timestamp

On top of that, when I finally did get a working solution, something on the target was broken in that it wasn't returning the secret contents. It was only a few hours later that everything started working again and I was able to score the flag. 

Anyway, moving on to exploiting the binary. Connecting to the service prints out the following menu: 

```
# nc localhost 9999
Welcome to my...
___________      .__           _________                  .__
\_   _____/_____ |__| ____    /   _____/ ______________  _|__| ____  ____
 |    __)_\____ \|  |/ ___\   \_____  \_/ __ \_  __ \  \/ /  |/ ___\/ __ \
 |        \  |_> >  \  \___   /        \  ___/|  | \/\   /|  \  \__\  ___/
/_______  /   __/|__|\___  > /_______  /\___  >__|    \_/ |__|\___  >___  >
        \/|__|           \/          \/     \/                    \/    \/

Your options:

            1. Login with the password (*).
            2. View the secret contents (#).
            3. View the usage logs.
            4. Exit.

* => It's theoretically impossible that you can login.
# => Requires login.
```

Option 2 prints out the secret contents, which I assumed to be the flag. However in order to get that, I needed to use option 1 and login with the password. As it says in the footnote of the menu, it was theoretically impossible to login. More on this in a bit. Option 3 prints out a log of successful and failed logins, along with their timestamps. This would prove to be a useful hint later on. The binary just runs on a loop until option 4 is selected and the whole thing exits. 

The binary accepts input only when asking for the password, and there was no way to overflow the buffer. So I poked around using Binary Ninja to see what it was doing. The interesting bit where it checks if the password I entered was valid or not was at 0x400dba

![](/images/2017-11-24/01.png)

It uses strncmp() to compare 100 bytes of the entered password with the password hardcoded in binary at 0x400e60. Here's the hardcoded password: 

```
pwndbg> x/100bx 0x400e60
0x400e60:       0x33    0x12    0x46    0x67    0xf6    0x2b    0x5a    0x2e
0x400e68:       0x5b    0x7e    0xd6    0xf7    0xa2    0x33    0xd5    0x7a
0x400e70:       0x87    0x39    0x5f    0x92    0x73    0xf5    0xb1    0xa5
0x400e78:       0x81    0xb0    0x6a    0x84    0x38    0xcd    0x9b    0xea
0x400e80:       0x99    0xda    0x57    0x65    0x6c    0x63    0x6f    0x6d
0x400e88:       0x65    0x20    0x74    0x6f    0x20    0x6d    0x79    0x2e
0x400e90:       0x2e    0x2e    0x00    0x00    0x00    0x00    0x00    0x00
0x400e98:       0x5f    0x5f    0x5f    0x5f    0x5f    0x5f    0x5f    0x5f
0x400ea0:       0x5f    0x5f    0x5f    0x20    0x20    0x20    0x20    0x20
0x400ea8:       0x20    0x2e    0x5f    0x5f    0x20    0x20    0x20    0x20
0x400eb0:       0x20    0x20    0x20    0x20    0x20    0x20    0x20    0x5f
0x400eb8:       0x5f    0x5f    0x5f    0x5f    0x5f    0x5f    0x5f    0x5f
0x400ec0:       0x20    0x20    0x20    0x20
```

Sending this password results in an invalid match, because by the time strncmp() is called, the entered password has been mangled. For a 300 point challenge, it can't be that easy anyway.  So what's happening? 

Right before strncmp() is called, the entered password is passed into a function 0x400a26. Here's what it looks like:

![](/images/2017-11-24/02.png)

This basically translates to the following pseudocode

```
encode_msg(char *my_password) {
    char x; 
    srand(time(0));

    for (i = 0; i <= 33; i++) {
        x = my_password[i];
        my_password[i] = x ^ rand() % 255
    }
}
```

The current time is used to seed the pseudo-random number generator. Each character in my_password is then XORd with a randomly generated number from 0x0 to 0xFF. The end result is compared with the hardcoded password. Since random numbers are used to XOR my_password, it's impossible enter the correct password such that it will match the hardcoded one after all the XOR encoding.

Or is it? 

The vulnerability here was obvious to me because I'd actually solved a similar challenge before in [TJCTF 2016](https://github.com/VulnHub/ctf-writeups/blob/e160838b06b69d1f19a94411bcbc2702bcf3dbca/2016/tjctf/guess.md). The issue is that srand(time(0)) is called everytime option 1 is selected, rather than at the start of the program. Since it uses the current time to seed the pseudo-random number generator, I could duplicate that same functionality and therefore predict the values that every call to rand() would return. This allows me to generate the correct password that would match the hardcoded password after the XOR encoding. 

Here's a C program that does just that:


```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main() {
    char *hardcoded_password = "\x33\x12\x46\x67\xf6\x2b\x5a\x2e\x5b\x7e\xd6\xf7\xa2\x33\xd5\x7a\x87\x39\x5f\x92\x73\xf5\xb1\xa5\x81\xb0\x6a\x84\x38\xcd\x9b\xea\x99\xda";
    char my_password[34];
    int i;

    srand(time(0));

    for (i = 0; i < 34; i++) {
        my_password[i] = hardcoded_password[i] ^ rand() % 255;
    }
    printf("%s", my_password);
    return 0;
}
```

I could now write a python script that would take the output of that helper program and send it to the service with a 99% chance that the password would match. This worked perfectly locally, but not remotely. The reason for that was the time. The time on my machine was probably different from the time running on the server. This is where option 3 came in. It printed the timezone the server was running, which was IST. Once I changed my machine's timezone to IST, I was able to get it working. Here's the final exploit that gets a successful login and prints out the secret code from option 2:

```
!/usr/bin/env python

from pwn import *
import subprocess

# binary does strncmp(my_password, hardcoded_password, 100). only 33 bytes of my_password are encoded.
# so we need to pad it with the extra junk that strncmp() looks for when comparing against
# the hardcoded_password. This is basically stuff that starts at 0x400e82
junk = (
    "\x57\x65\x6c\x63\x6f\x6d\x65\x20\x74\x6f\x20"
    "\x6d\x79\x2e\x2e\x2e\x00\x00\x00\x00\x00\x00"
    "\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f"
    "\x20\x20\x20\x20\x20\x20\x2e\x5f\x5f\x20\x20"
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x5f\x5f"
    "\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x20\x20\x20\x20"
)

r = remote("13.126.83.119", 10987)

r.recv()          # Welcome...
r.sendline("1")   # Send password option
r.recv()
r.recv()

# run helper program that decodes the hardcoded_password  based on the random value generated from the current time
proc = subprocess.Popen("./helper", stdout=subprocess.PIPE)
my_password = proc.stdout.read()[:34]

buf = "".join([my_password, junk, "\n"])

r.sendline(buf)
d = r.recv()

# send option 2 if login was successful
if "success" in d:
    r.sendline("2")
    r.recv()
    print r.recv()
else:
    print "Didn't work, try again."

```

So right after I solved this and got it working on my machine, I tested it on the target. I was able to match the password, select option 2, but it wouldn't print out the secret. No idea why. I suspected that something was wrong on the server side since no other team had scored the flag either. A few hours later I tried again and it worked. At this point a handful of teams had also successfully solved it. Here's the result:

```
# ./sploit.py SILENT=1
You're logged in! Here's the secret: Flag is the password at epoch 1505768803.


Your options:

            1. Login with the password (*).
            2. View the secret contents (#).
            3. View the usage logs.
            4. Exit.

* => It's theoretically impossible that you can login.
# => Requires login.
```

It was also at this point that I noticed the  challenge description had changed. The flag was the MD5 of 1505768803: flag{c51edda648c6949638488457f32874d6}

300 points in the bag!
