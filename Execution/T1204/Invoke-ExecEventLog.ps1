function Invoke-ExecEventLog {
    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1204/

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1204/

    .PARAMETER OutFile

    Export result to csv file. It can be absolute or relative path.

    .PARAMETER Show

    Output result


    .EXAMPLE 

    Invoke-ExecEventLog  -Show
    Invoke-ExecEventLog  -OutFile .\T1204-Invoke-ExecEventLog.csv -Show

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Utils\Invoke-Utils.psd1") -Force

    # Main
    $ResultList = New-Object System.Collections.Generic.List[System.Object]

    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688}  | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $ExecEventLog = [PSCustomObject]@{
            TimeCreated = $_.TimeCreated                                       
        }
        #$ExecEventLog
        foreach ($node in $xml.Event.EventData.ChildNodes){
            $ExecEventLog | Add-Member -MemberType NoteProperty -Name "$($node.Name)" -Value  $node.InnerText
        }

        if ($ExecEventLog.NewProcessName -ne ""){
            $PEFileInfo = Get-PeFileInfo $ExecEventLog.NewProcessName
            $PEFileInfo |  Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
                $ExecEventLog | Add-Member -MemberType NoteProperty -Name $("New_Process_PEFileInfos_$_") -Value  $PEFileInfo.$_

            }
        }

        if ($ExecEventLog.ParentProcessName -ne "") {
            $PEFileInfo = Get-PeFileInfo $ExecEventLog.ParentProcessName
            $PEFileInfo |  Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
                $ExecEventLog | Add-Member -MemberType NoteProperty -Name $("Parent_Process_PEFileInfos_$_") -Value  $PEFileInfo.$_

            }
        }

        $ResultList.Add($ExecEventLog)

    }

     # Output 
     if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }
}

Invoke-ExecEventLog
