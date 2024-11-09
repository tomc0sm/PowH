
#  Usage 


```
git clone https://github.com/tomc0sm/PowerHunt.git

# create output folders 
mkdir .\Output\Persistence
mkdir .\Output\Execution

# run tests 
.\Tests\Persistence.test2.ps1
.\Tests\Execution.test.ps1
```


# Features 

## Persistence

### - T1037\Invoke-LogonScripts

MITRE | ATT&CK : https://attack.mitre.org/techniques/T1037/001/

Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence.This is done via adding a path to a script to the 

- HKCU\Environment\UserInitMprLogonScript Registry key


Output fields

| Path | Name | Value | Type | FileInfo_CompanyName | FileInfo_Copyright | FileInfo_DateCreation | FileInfo_DateModification | FileInfo_FileDescription | FileInfo_FileVersion | FileInfo_OriginalFileName | FileInfo_ProductName | FileInfo_ProductVersion | FileInfo_Sha1 | FileInfo_SignatureCertificateThumbprint | FileInfo_SignatureCertificateTrusted | FileInfo_SignatureStatus | FileInfo_SignatureSubject |
|------|------|-------|------|----------------------|--------------------|-----------------------|---------------------------|--------------------------|----------------------|---------------------------|-----------------------|--------------------------|---------------|------------------------------------------|--------------------------------------|--------------------------|---------------------------|


### - T1197\Invoke-BitsJobs

MITRE | ATT&CK : https://attack.mitre.org/techniques/T1197/

Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Adversaries may abuse BITS to download (e.g. Ingress Tool Transfer), execute, and even clean up after running malicious code (e.g. Indicator Removal). 

Output fields


| CertificateHash | CertificateStoreLocation | CertificateStoreName | CertificateSubjectName | CreationTime       | CustomHeaders | Description    | DisplayName | Dynamic | ErrorCondition    | ErrorContext                                                                                                                                                                                           | ErrorContextDescription                                                                                                                                                                                          | ErrorDescription | FileList | FilesTotal | FilesTransferred | HttpMethod | InternalErrorCode | JobId                                  | JobState       | MaxDownloadTime | ModificationTime   | NotifyCmdLine | NotifyFlags             | OwnerAccount               | Priority  | ProxyBypassList | ProxyList | ProxyUsage    | RetryInterval | RetryTimeout | SecurityFlags              | TransferCompletionTime | TransferPolicy | TransferType | TransientErrorCount |
|-----------------|--------------------------|----------------------|------------------------|--------------------|---------------|----------------|-------------|---------|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------|----------|------------|------------------|------------|-------------------|----------------------------------------|----------------|----------------|--------------------|---------------|-------------------------|---------------------------|-----------|-----------------|-----------|---------------|---------------|--------------|----------------------------|-------------------------|----------------|--------------|---------------------|

 
<br>

### - T5103\Invoke-ScheduledTask

MITRE | ATT&CK&CK : https://attack.mitre.org/techniques/T1053/005/

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence.Adversaries may also create "hidden" scheduled tasks (i.e. Hide Artifacts) that may not be visible to defender tools and manual queries used to enumerate tasks.


This is done by deleting the associated Security Descriptor (SD) registry value 

Example : creating hidden task 

```
$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "HiddenTestTask" -Description "This is a test hidden task"

C:\Tools\SysinternalsSuite\PsExec.exe -i -s powershell.exe

PS C:\Windows\system32>  Remove-ItemProperty  -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\HiddenTestTask" -Name "SD"

```

Output fields : 


| TaskName | TaskPath | RegistrationInfo_Version | RegistrationInfo_Description | RegistrationInfo_URI | Triggers_LogonTrigger_Enabled | Triggers_CalendarTrigger_StartBoundary | Triggers_CalendarTrigger_Enabled | Triggers_CalendarTrigger_ScheduleByDay_DaysInterval | Principals_Principal_UserId | Principals_Principal_RunLevel | Settings_MultipleInstancesPolicy | Settings_DisallowStartIfOnBatteries | Settings_StopIfGoingOnBatteries | Settings_AllowHardTerminate | Settings_StartWhenAvailable | Settings_RunOnlyIfNetworkAvailable | Settings_IdleSettings_Duration | Settings_IdleSettings_WaitTimeout | Settings_IdleSettings_StopOnIdleEnd | Settings_IdleSettings_RestartOnIdle | Settings_AllowStartOnDemand | Settings_Enabled | Settings_Hidden | Settings_RunOnlyIfIdle | Settings_DisallowStartOnRemoteAppSession | Settings_UseUnifiedSchedulingEngine | Settings_WakeToRun | Settings_ExecutionTimeLimit | Settings_Priority | Actions_Exec_Command | Actions_Exec_Arguments | PEFileInfos_CompanyName | PEFileInfos_Copyright | PEFileInfos_DateCreation | PEFileInfos_DateModification | PEFileInfos_FileDescription | PEFileInfos_FileVersion | PEFileInfos_OriginalFileName | PEFileInfos_ProductName | PEFileInfos_ProductVersion | PEFileInfos_Sha1 | PEFileInfos_SignatureCertificateThumbprint | PEFileInfos_SignatureCertificateTrusted | PEFileInfos_SignatureStatus | PEFileInfos_SignatureSubject |
|----------|----------|--------------------------|-------------------------------|----------------------|-------------------------------|----------------------------------------|----------------------------------|-----------------------------------------------|-----------------------------|------------------------------|-------------------------------|-----------------------------------|---------------------------------|-----------------------------|------------------------------|-----------------------------------|-----------------------------|--------------------------------|-----------------------------|----------------------------|-------------------|----------------|---------------------|-------------------------------------|----------------------------------|------------------|--------------------------|-----------------|-------------------|--------------------|---------------------|--------------------|----------------------|------------------------|----------------------|------------------|---------------------|---------------------|-------------------|--------------------------|------------------|--------------------------------------|---------------------------------|----------------------|----------------------|

<br>

### - T5143\Invoke-Service

MITRE | ATT&CK : https://attack.mitre.org/techniques/T1543/003/

Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence.Adversaries may install a new service or modify an existing service to execute at startup in order to persist on a system.Adversaries may also use services to install and execute malicious drivers. Services may be created with administrator privileges but are executed under SYSTEM privileges. Adversaries may also create ‘hidden’ services (i.e., Hide Artifacts), for example by using the sc sdset command to set service permissions via the Service Descriptor Definition Language (SDDL). **This may hide a Windows service from the view of standard service enumeration methods such as Get-Service, sc query, and services.exe**


Output fields : 



| ImagePath        | Type   | Start | ErrorControl | DisplayName | Owners | Group | PSPath         | PSParentPath    | PSChildName | PSProvider | DecodedType | PEFileInfos_Length |
|------------------|--------|-------|--------------|-------------|--------|-------|----------------|-----------------|-------------|------------|-------------|---------------------|


<br>

### - T5146\Invoke-AppInitDLL

MITRE | ATT&CK : https://attack.mitre.org/techniques/T1546/010/

 Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs are loaded by user32.dll into every process that loads user32.dll. 

 This is done by adding the Registry keys : 

 - HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows
 - HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows


Output fields: 

| Path | Name | Value | Type |
|------|------|-------|------|

 <br>

### - T5146\Invoke-WMIEventSubscription


MITRE | ATT&CK :https://attack.mitre.org/techniques/T1546/003/

Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.

OutPut Fields : 

| Name | __RELPATH | PSComputerName | __CLASS | __SUPERCLASS | __NAMESPACE | __PATH | Consumer | Filter | CommandLineTemplate | ExecutablePath | Query |
|------|-----------|----------------|---------|--------------|-------------|--------|----------|--------|---------------------|----------------|-------|


<br> 

### - T5147\Invoke-RegistryRunKey

MITRE | ATT&CK: https://attack.mitre.org/techniques/T1543/003/

Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key

This done by adding the registry keys 

- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx



Output fields 

| Path         | Name         | Value       | Type       | PEFileInfos_CompanyName | PEFileInfos_Copyright | PEFileInfos_DateCreation | PEFileInfos_DateModification | PEFileInfos_FileDescription | PEFileInfos_FileVersion | PEFileInfos_OriginalFileName | PEFileInfos_ProductName | PEFileInfos_ProductVersion | PEFileInfos_Sha1 | PEFileInfos_SignatureCertificateThumbprint | PEFileInfos_SignatureCertificateTrusted | PEFileInfos_SignatureStatus | PEFileInfos_SignatureSubject |
|--------------|--------------|-------------|------------|-------------------------|------------------------|--------------------------|-----------------------------|-----------------------------|--------------------------|-----------------------------|-------------------------|----------------------------|------------------|--------------------------------------------|-----------------------------------------|----------------------------|----------------------------|

<br>

### - T5147\Invoke-StartupFolder

MITRE | ATT&CK: https://attack.mitre.org/techniques/T1543/003/

Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key

The startup folders are : 

- %userdir%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup. 
- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

Output fields: 

| Name         | Path         | TargetPath     | PEFileInfos_CompanyName | PEFileInfos_Copyright | PEFileInfos_DateCreation | PEFileInfos_DateModification | PEFileInfos_FileDescription | PEFileInfos_FileVersion | PEFileInfos_OriginalFileName | PEFileInfos_ProductName | PEFileInfos_ProductVersion | PEFileInfos_Sha1 | PEFileInfos_SignatureCertificateThumbprint | PEFileInfos_SignatureCertificateTrusted | PEFileInfos_SignatureStatus | PEFileInfos_SignatureSubject |
|--------------|--------------|----------------|-------------------------|------------------------|--------------------------|-----------------------------|-----------------------------|--------------------------|-----------------------------|--------------------------|----------------------------|------------------|--------------------------------------------|-----------------------------------------|----------------------------|----------------------------|


<br>

### - T5147\Invoke-Winlogon

MITRE | ATT&CK: https://attack.mitre.org/techniques/T1547/004/

Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in.

This done by adding the Registry keys : 

- HKLM\Software[\Wow6432Node\]\Microsoft\Windows NT\CurrentVersion\Winlogon\ 
- HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Specifically, the following subkeys have been known to be possibly vulnerable to abuse:

- Winlogon\Notify - points to notification package DLLs that handle Winlogon events
- Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on
- Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on
<br>

Output fields :


| Path         | Name         | Value       | Type       | 0_PEFileInfos_CompanyName | 0_PEFileInfos_Copyright | 0_PEFileInfos_DateCreation | 0_PEFileInfos_DateModification | 0_PEFileInfos_FileDescription | 0_PEFileInfos_FileVersion | 0_PEFileInfos_OriginalFileName | 0_PEFileInfos_ProductName | 0_PEFileInfos_ProductVersion | 0_PEFileInfos_Sha1 | 0_PEFileInfos_SignatureCertificateThumbprint | 0_PEFileInfos_SignatureCertificateTrusted | 0_PEFileInfos_SignatureStatus | 0_PEFileInfos_SignatureSubject |
|--------------|--------------|-------------|------------|---------------------------|--------------------------|----------------------------|-------------------------------|-------------------------------|----------------------------|-------------------------------|----------------------------|-----------------------------|------------------|----------------------------------------------|-------------------------------------------|------------------------------|----------------------------|


<br>


## Execution 

### - T1204\Invoke-ExecEventLog

MITRE | ATT&CK: https://attack.mitre.org/techniques/T1547/004/

Event 4688 of Security Log depends on Audit Policy Configuration

- Advanced Audit Policy Configuration ➔ System Audit Policies ➔ Detailed Tracking.
- Computer Configuration ➔ Administrative Templates ➔ System ➔ Audit Process Creation

Output fields: 


| TimeCreated | SubjectUserSid | SubjectUserName | SubjectDomainName | SubjectLogonId | NewProcessId | NewProcessName | TokenElevationType | ProcessId | CommandLine | TargetUserSid | TargetUserName | TargetDomainName | TargetLogonId | ParentProcessName | MandatoryLabel | New_Process_PEFileInfos_CompanyName | New_Process_PEFileInfos_Copyright | New_Process_PEFileInfos_DateCreation | New_Process_PEFileInfos_DateModification | New_Process_PEFileInfos_FileDescription | New_Process_PEFileInfos_FileVersion | New_Process_PEFileInfos_OriginalFileName | New_Process_PEFileInfos_ProductName | New_Process_PEFileInfos_ProductVersion | New_Process_PEFileInfos_Sha1 | New_Process_PEFileInfos_SignatureCertificateThumbprint | New_Process_PEFileInfos_SignatureCertificateTrusted | New_Process_PEFileInfos_SignatureStatus | New_Process_PEFileInfos_SignatureSubject |
|-------------|----------------|-----------------|-------------------|----------------|--------------|----------------|--------------------|-----------|-------------|---------------|----------------|------------------|---------------|-------------------|----------------|-------------------------------------|-----------------------------------|----------------------------------------|----------------------------------------|----------------------------------------|--------------------------------------|----------------------------------------|--------------------------------------|----------------------------------------|------------------------------|-------------------------------------------------------|----------------------------------------------------|----------------------------------------|----------------------------------------|

<br>

## TODO


- Check and document Services & ScheduledTasks => hidden ones ? 
- Task data enrichment => get SD value in Registry HKLM:[...] TaskCache => hidden tasks
- Check and Document BitsJobs, Wmi
- SysInternals result comparison 
- Registry Keys. On Mitre there are many others keys we can parse.
- Errors key not exists on execution
- T1204\Invoke-Prefetch
- T1204\Invoke-RunningProcess
- T1546\Invoke-ComHijacking
- Browser Extensions 


