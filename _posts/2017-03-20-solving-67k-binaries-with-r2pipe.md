---
layout: post
title: "Solving 67k binaries with r2pipe"
date: 2017-03-20 11:08:39 -0400
comments: true
categories: ctf
---


This was a 400 point reverse engineering challenge from [EasyCTF 2017](https://www.easyctf.com/). We're given a zip file containing 67,139 small programs starting from 00000.exe to 10642.exe. The idea is to solve each one in order and to join their output. The end result would lead to the flag. Here's the challenge description:

> Here are 67k binaries, well more accurately 67,139 binaries. Solve every single one, append the results together in order (shouldn't be too difficult as the binaries are numbered) and then from there I'm sure you can figure it out.

There are probably a hundred ways to solve this challenge, but I decided to give it a go using radare2's [r2pipe](https://github.com/radare/radare2-r2pipe).

Disclaimer: This was the first time I'd used r2pipe, so I apologize for the noobness. After much Googling and fiddling, I ended up with a hacky script that solved the challenge. The script can definitely be improved upon, and I'd love to hear suggestions from those who are more experienced with r2pipe or radare2 scripting. 

I loaded 00000.exe into radare2 for some static analysis:

![](/images/2017-03-20/01.png)

`entry0` is where the program starts. This function basically breaks down to:

* get a number from the user
* set eax to a value stored at an address (in this case 0x403000). I'll call this value `x`
* set ecx to a constant value (in this case 0xa1a8a7ed). I'll call this value `y`
* call a function, I'll call it `do_op()`, that returns the result of an operation (in this case `eax-ecx`)

Here's what `do_op()` looks like:

![](/images/2017-03-20/02.png)

The return value of this function, I'll call it `z`, is compared against the user's input. If they are identical it follows a branch that does the following:

* set cl to a value stored at an address (in this case 0x403007)
* shift `z` by cl bits and store the result in eax
* do a bitwise `and` on eax and print out the result

Nothing complicated. The goal is to enter the correct input expected by each binary and concatenate its output to get the flag. I examined a handful of binaries and found the following:

* the values for `x` and `y` differ for each binary
* the operation performed by function `do_op()` can be one of `add`, `sub`, or `xor`; however it's always `op eax, ecx`

So in order to solve each binary without having to run it, I needed to calculate `z`, do a shift arithmetic right on it by a certain number of bits, and finally do a bitwise `and` on the result.

Scripting the whole thing with r2pipe was actually pretty easy. For instance, here's how I got the address of `do_op()`

```python
r2p = r2pipe.open(sys.argv[1])  # open the binary
r2p.cmd("aaa")                  # analyze it

t = r2p.cmd("aflj")             # list all functions; should return two results: entry0 and fcn.????????
                                # returns the result in JSON

d = json.loads(t)               # get the results in a dictionary
fc_name = d[0]["name"]          # there are 2 dictionaries returned; check if the first one is fcn.????????
if fc_name == "entry0":         # if not, get it from the second dictionary
    fc_name = d[1]["name"]
print "do_op() is", fc_name
```

If I run this I get

![](/images/2017-03-20/03.png)

Basically it's all about using `r2p.cmd()` to run a radare2 command and parsing its output. In this case I've chosen to return the results of the command in JSON for easier parsing. If there's a better way, I'm all ears!

Here's the full script:

```
#!/usr/bin/env python

import r2pipe
import json
import sys

if __name__ == "__main__":
    r2p = r2pipe.open(sys.argv[1])
    r2p.cmd("aaa")

    # get the address of do_foo()
    t = r2p.cmd("aflj")
    d = json.loads(t)
    fc_name = d[0]["name"]
    if fc_name == "entry0":
        fc_name = d[1]["name"]

    # determine if sub, add, or xor is used; just want the opcode at this point
    t = r2p.cmd("pdj 1@%s" %( fc_name))     # <op> eax, ecx
    d = json.loads(t)
    ins = d[0]["opcode"]

    # get the value of EAX
    t = r2p.cmd("pdj 1@entry0+0x1f")        #  mov eax, dword [0xNNNNNNNN]
    d = json.loads(t)
    pointer = d[0]["esil"].split(",")[0]
    pointer = int(pointer, 16)

    t = r2p.cmd("pxrj 4@%d" % (pointer,))   # get value pointed to by 0xNNNNNNNN
    d = json.loads(t)
    eax = d[0]["value"]

    # get the value of ECX
    t = r2p.cmd("pdj 1@entry0+0x24")        #  mov ecx, 0xMMMMMMMM
    d = json.loads(t)
    ecx = d[0]["opcode"].split()[-1]
    ecx = int(ecx, 16)

    # determine the operation used by do_foo()
    answer = 0
    if "sub" in ins:
        answer = eax - ecx
    elif "xor" in ins:
        answer = eax ^ ecx
    elif "add" in ins:
        answer = eax + ecx

    # get value to use for SAR operation
    t = r2p.cmd("pdj 1@entry0+0x36")        # mov cl, byte [0xNNNNNNNN]
    d = json.loads(t)
    pointer = d[0]["esil"].split(",")[0]
    pointer = int(pointer, 16)

    t = r2p.cmd("pxrj 4@%d" % (pointer,))   # get value pointed to by 0xNNNNNNNN
    t = t.replace("\\x", "")                # get rid of escapes json doesn't like
    d = json.loads(t)
    val = d[0]["value"]
    cl = val & 0xff

    # get the solution to the challenge
    solve = answer >> cl
    solve = solve & 0xff
    sys.stdout.write("%c" % (solve,))
```

The script is commented so hopefully it makes sense, It basically figures out what the expected input is and what the binary's output will be. 

To demonstrate the script, I've copied a handful of the binaries to a sample directory and ran it:

![](/images/2017-03-20/04.png)

So it looks like the binaries will create some obfuscated Javascript code, specifically [hieroglyphy](https://github.com/alcuadrado/hieroglyphy). Running the script against all the binaries took a few hours, but it worked! I executed the Javascript contents in my browser and got the flag:

![](/images/2017-03-20/05.png)

I've attached the completed output and the challenge binaries [here](https://gist.github.com/superkojiman/8e40c4579c36d541f5aa6fe9eaa6b6ba) if you'd like to play with it as well

Overall this was a great learning experiencef or me. I'll be doing some more reading on r2pipe to see what else I can do with it.
