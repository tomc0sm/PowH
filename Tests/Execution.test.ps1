Import-Module -Name ($PSScriptRoot + "\..\Execution\Execution.psd1") -Force


Invoke-ExecEventLog  -OutFile ".\Output\Execution\T1204-Invoke-ExecEventLog.csv" -Show
