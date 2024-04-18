Import-Module -Name ($PSScriptRoot + "\..\Persistence\Persistence.psd1") -Force


Invoke-ScheduledTask -OutFile ".\Output\Persistence\T5103_ScheduledTask.csv" -Show

Invoke-RegistryRunKey -OutFile ".\Output\Persistence\T5147_RegistryRunKey.csv" -Show

Invoke-StartUpFolder -OutFile ".\Output\Persistence\T5147_StartUpFolder.csv" -Show

Invoke-WinLogon -OutFile ".\Output\Persistence\T5147_WinLogon.csv" -Show

Invoke-Service -OutFile ".\Output\Persistence\T5143_Service.csv" -Show

Invoke-AppInitDLL -OutFile ".\Output\Persistence\T5146_AppInitDLL.csv" -Show

Invoke-WMIEventSubscription -OutFile ".\Output\Persistence\T5146-WMIEventSubscription.csv" -Show

Invoke-BitsJobs -OutFile ".\Output\Persistence\T1197-BitsJobs.csv" -Show
