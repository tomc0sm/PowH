function Invoke-LogonScript {
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

    Invoke-LogonScript -Show
    Invoke-LogonScripts -OutFile .\T1197-BitsJobs.csv -Show

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

    $keyPath ="\Environment"

    $HKU = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $env:COMPUTERNAME)

    $HKU.GetSubKeyNames() | Where-Object {$_ -match '^S-1-5-21' -and $_ -notmatch '_Classes$'} | ForEach-Object {
        $fullPath = $_ + $keyPath
        $HKURegistryKey =  $HKU.OpenSubKey($fullPath, $false)
        $LogonScript = [PSCustomObject]@{
            Path = "HKLM:\$KeyPath\UserInitMprLogonScript"
            Name = $_
            Value = $HKURegistryKey.GetValue('UserInitMprLogonScript')
            Type =  $HKURegistryKey.GetValueKind('UserInitMprLogonScript')
        }

        if($LogonScript.Value -ne "" -and $null -ne $LogonScript.Value){
            $PEFileInfoIndex = 0
            ($LogonScript.Value -split ",") | ForEach-Object { # parse comma separated values
                if($_ -ne ""){
                    $FilePath = Get-WinFilePath ($_ -replace '"','')  
                    $PEFileInfo = Get-PeFileInfo $FilePath
                    $PEFileInfo |  Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
                        $LogonScript | Add-Member -MemberType NoteProperty -Name "$($PEFileInfoIndex)_PEFileInfos_$_" -Value  $PEFileInfo.$_
                        
                    }
                    $PEFileInfoIndex += 1
                }
            }
        }

        $ResultList.Add($LogonScript)
    }

    # Output 
    if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }



   

}

Invoke-LogonScript -Show
