#Debug

Stop-Service -Name "Informatica10.4.1"
Start-Sleep -s 120
sc.exe delete "Informatica10.4.1"
Remove-Item -Recurse -Force C:/Informatica/ 
Remove-Item -Recurse -Force C:/Infa_Installer/
Remove-Item -Recurse -Force C:/downloads/