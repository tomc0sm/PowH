# PowerHunt


##  Usage 


```
git clone https://github.com/tomc0sm/PowerHunt.git

# create output folders 
mkdir .\Output\Persistence
mkdir .\Output\Execution

# run tests 
.\Tests\Persistence.test2.ps1
.\Tests\Execution.test.ps1
```


## Features 

### Persistence

#### T1197-BitsJobs

MITREATT&CK : https://attack.mitre.org/techniques/T1197/

<br>

Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Adversaries may abuse BITS to download (e.g. Ingress Tool Transfer), execute, and even clean up after running malicious code (e.g. Indicator Removal). 

 ```


| CertificateHash | CertificateStoreLocation | CertificateStoreName | CertificateSubjectName | CreationTime       | CustomHeaders | Description    | DisplayName | Dynamic | ErrorCondition    | ErrorContext | ErrorContextDescription | ErrorDescription | FileList | FilesTotal | FilesTransferred | HttpMethod | InternalErrorCode | JobId                                  | JobState       | MaxDownloadTime | ModificationTime   | NotifyCmdLine | NotifyFlags             | OwnerAccount               | Priority  | ProxyBypassList | ProxyList | ProxyUsage    | RetryInterval | RetryTimeout | SecurityFlags              | TransferCompletionTime | TransferPolicy | TransferType | TransientErrorCount |
|-----------------|--------------------------|----------------------|------------------------|--------------------|---------------|----------------|-------------|---------|-------------------|--------------|-------------------------|-------------------|----------|------------|------------------|------------|-------------------|----------------------------------------|----------------|----------------|--------------------|---------------|-------------------------|---------------------------|-----------|-----------------|-----------|---------------|---------------|--------------|----------------------------|-------------------------|----------------|--------------|---------------------|
|                 | CurrentUser              |                      |                        | 11/05/2024 09:13:10 |               | Font Download | False       |         | GeneralQueueManager | L'erreur est survenue dans le Gestionnaire de files d’attente du service de transfert intelligent d’arrière plan (BITS). | Il n’existe actuellement aucune connexion réseau active. Le service de transfert intelligent d’arrière plan (BITS) recommencera plus tard, lorsqu’une carte sera connectée. | Microsoft.BackgroundIntelligentTransfer.Management.BitsFile | 1          | 0                | GET        | -2145386480       | 0f355aa8-2bc1-4244-888f-3a6490e2ea4e | TransientError | 7776000        | 11/05/2024 09:13:10 |               | ,JobTransferred, JobError | AUTORITE NT\SERVICE LOCAL | Foreground |                 |           | SystemDefault | 600           | 1209600      | RedirectPolicyAllowSilent | 01/01/0001 00:00:00    | Standard       | Download     | 0                   |


 


#### T5103-ScheduledTask


#### T5143-Service


#### T5146-AppInitDLL


#### T5146-WMIEventSubscription


#### T5141-RegistryRunKey


#### T5147-StartupFolder


#### T5147-Winlogon


### Execution 

#### T1204-ExecEventLog

This module provides a list of 4688 events from windows Security Log and automaticallyenrich datas using PEFileInfo util.   Details depend on Windows Audit Policy Strategy : 

- To log all events creations :  Advanced Audit Policy Configuration ➔ System Audit Policies ➔ Detailed Tracking ➔ Audit Process Creation. Log both Audit and failure
- To log command lines : Administrative Templates ➔ System ➔  Audit Process Creation. Enable

  




