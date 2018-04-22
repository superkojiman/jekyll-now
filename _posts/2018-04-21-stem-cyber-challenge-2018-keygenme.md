---
layout: post
title: "STEM Cyber Challenge 2018: Keygenme"
date: 2018-04-21 17:00:48 -0400
comments: true
categories: ctf
---

I got a chance to play a bit of the STEM Cyber Challenge 2018 CTF over the weekend. This one is called keygenme, a 400 point reverse engineering challenge. Like its name suggests, the binary prompts for input and runs some checks on it to determine if it's a valid key. 

I analyzed the binary using Binary Ninja and found 20 different checks in `main()`. Here's what `check_1()` looks like: 

![](/images/2018-04-21/01.png)

It basically does certain comparisons with different characters in our input along with some math thrown in. A condition is checked at the very and to determine if the check passed or failed. Obviously we want it to pass.

The other check functions are similar, and if we pass them all, then our input is basically the flag. While solving it looked complicated, it was actually a breeze with Angr. 

The only thing I had to tell Angr to look for was the success address, which is 0x400eda

![](/images/2018-04-21/02.png)

Angr uses symbolic execution to determine the input required to get to a target. I used the example from [https://github.com/angr/angr](https://github.com/angr/angr) and updated it to work with the binary: 

```
#!/usr/bin/env python
import angr

project = angr.Project("./keygenme", auto_load_libs=False)
@project.hook(0x400eda)
def print_flag(state):
    print "Flag: {0}\n".format(state.posix.dump_fd(0))
    project.terminate_execution()

project.execute()
```

Running it gives us the flag MCA{A0826B45FE84A765}: 

![](/images/2018-04-21/03.png)
