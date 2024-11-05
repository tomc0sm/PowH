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

- T1197-BitsJobs
- T5103-ScheduledTask
- T5143-Service
- T5146-AppInitDLL
- T5146-WMIEventSubscription
- T5141-RegistryRunKey
- T5147-StartupFolder
- T5147-Winlogon


### Execution 

#### T1204-ExecEventLog

This module provides a list of 4688 events from windows Security Log and automaticallyenrich datas using PEFileInfo util.   Details depend on Windows Audit Policy Strategy : 

- To log all events creations :  Advanced Audit Policy Configuration ➔ System Audit Policies ➔ Detailed Tracking ➔ Audit Process Creation. Log both Audit and failure
- To log command lines : Administrative Templates ➔ System ➔  Audit Process Creation. Enable

  








### Execution 

