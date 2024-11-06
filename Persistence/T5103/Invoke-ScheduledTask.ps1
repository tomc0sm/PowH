function Invoke-ScheduledTask {
    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1053/005/

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1053/005/

    .PARAMETER OutFile

    Export result to csv file. It can be absolute or relative path.

    .PARAMETER Show

    Output result


    .EXAMPLE 

    Invoke-ScheduledTask -Show
    Invoke-ScheduledTask -OutFile .\T5103-ScheduledTask.csv -Show

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Utils\Invoke-Utils.psd1") -Force

    
    # Parse XML Task File 
    function Local:Convert-XMLToProperties {
        param(
            [Parameter(Mandatory = $False )]
            [System.Xml.XmlElement] $XMLElement,
            [Parameter(Mandatory = $False )]
            [string] $Prefix = "",
            [Parameter(Mandatory = $False )]
            [PSCustomObject]$Obj = @{}
        )
       
        foreach ($childNode in $XMLElement.ChildNodes) {
            if($Prefix -ne "" -and $childNode.LocalName -ne "#text"){
                $Prefix = "$($Prefix)_"
            }
            if($childNode.LocalName -ne "#text"){
                $Prefix += $($childNode.LocalName)
            }
            if($childNode.HasChildNodes){
                $Obj = Convert-XMLToProperties -XMLElement $childNode -Prefix $Prefix -Obj $Obj
            }
            else {
                if($childNode.Value -ne "" -and $null -ne $childNode.Value) {
                    $Obj | Add-Member -MemberType NoteProperty -Name $Prefix -Value ($childNode.Value)
                }
            }
    
            if(-not $Prefix.Contains("_")){
                $Prefix = ""
            }
            $Prefix = $Prefix -replace "_[^_]+$"
        }
        return $Obj
    }

    # Main
    $ResultList = New-Object System.Collections.Generic.List[System.Object]
    $ObjFields = @("TaskName","TaskPath","RegistrationInfo_Version","RegistrationInfo_Description","RegistrationInfo_URI","Triggers_LogonTrigger_Enabled","Triggers_CalendarTrigger_StartBoundary","Triggers_CalendarTrigger_Enabled","Triggers_CalendarTrigger_ScheduleByDay_DaysInterval","Principals_Principal_UserId","Principals_Principal_RunLevel","Settings_MultipleInstancesPolicy","Settings_DisallowStartIfOnBatteries","Settings_StopIfGoingOnBatteries","Settings_AllowHardTerminate","Settings_StartWhenAvailable","Settings_RunOnlyIfNetworkAvailable","Settings_IdleSettings_Duration","Settings_IdleSettings_WaitTimeout","Settings_IdleSettings_StopOnIdleEnd","Settings_IdleSettings_RestartOnIdle","Settings_AllowStartOnDemand","Settings_Enabled","Settings_Hidden","Settings_RunOnlyIfIdle","Settings_DisallowStartOnRemoteAppSession","Settings_UseUnifiedSchedulingEngine","Settings_WakeToRun","Settings_ExecutionTimeLimit","Settings_Priority","Actions_Exec_Command","Actions_Exec_Arguments")

    (Get-ScheduledTask -TaskPath "\") | ForEach-Object {
        
        $TaskXml = [XML]((Get-ScheduledTask -TaskName $_.TaskName) |Export-ScheduledTask)
        $ScheduledTask = [PSCustomObject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
        }

        $ScheduledTask = Convert-XMLToProperties -XMLElement $TaskXml.Task -Obj $ScheduledTask
        # Data enrichment
        $ScheduledTask = Add-FileInfo -Obj $ScheduledTask -FilePath $ScheduledTask.Actions_Exec_Command
        $ResultList.Add($ScheduledTask)
    }
    
    # Outputs
    $sortedProperties = Get-SortedProperties($ObjFields)

    if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }

    return $ResultList

}


#Invoke-ScheduledTask -OutFile .\T5103-ScheduledTask.csv -Show

