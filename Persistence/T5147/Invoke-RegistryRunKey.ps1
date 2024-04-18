function Invoke-RegistryRunKey{
    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1543/003/

    .DESCRIPTION
    
    MITREATT&CK : https://attack.mitre.org/techniques/T1543/003/


    .EXAMPLE 

    Invoke-RegistryRunKey -Show
    Invoke-RegistryRunKey -OutFile .\T5147-RegistryRunKey.csv -Show

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Utils\Invoke-Utils.psd1") -Force

    $HKU = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $env:COMPUTERNAME)
    $HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)

    $AutoRunRegistryKeys = @(
        "Software\Microsoft\Windows\CurrentVersion\Run", 
        "Software\Microsoft\Windows\CurrentVersion\RunOnce", 
        "Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "Sotware\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $ResultList = New-Object System.Collections.Generic.List[System.Object]
        
    $HKUPaths = New-Object System.Collections.Generic.List[System.Object]
    $HKU.GetSubKeyNames() | Where-Object {$_ -match '^S-1-5-21' -and $_ -notmatch '_Classes$'} | ForEach-Object {
        $HKUPaths.add($_ + "\")
    }

    foreach ($keyPath in $AutoRunRegistryKeys){

        # HKLM locations
        $HKLMKRegistryKey =  $HKLM.OpenSubKey($keyPath, $false)
        if($null -eq $HKLMKRegistryKey){
            continue
        }
        $HKLMKRegistryKey.GetValueNames() | ForEach-Object {
            $RegistryRun = [PSCustomObject]@{
                Path = "HKLM:\$KeyPath"
                Name = $_
                Value = $HKLMKRegistryKey.GetValue($_)
                Type =  $HKLMKRegistryKey.GetValueKind($_)
            }
       
            $FilePath = Get-WinFilePath ($RegistryRun.Value -replace '"','')      
            $PEFileInfo = Get-PeFileInfo $FilePath
            $PEFileInfo |  Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
                $RegistryRun | Add-Member -MemberType NoteProperty -Name "PEFileInfos_$_" -Value  $PEFileInfo.$_
            }
            $ResultList.Add($RegistryRun)
        }

        # HKU Locations
        foreach($userPath in $HKUPaths){
            $fullPath = $userPath + $keyPath
            $HKURegistryKey =  $HKU.OpenSubKey($fullPath, $false)
            if($null -eq $HKURegistryKey){
                continue
            }
            $HKURegistryKey.GetValueNames()| ForEach-Object {
                $RegistryRun = [PSCustomObject]@{
                    Path = "HKU:\$fullPath"
                    Name = $_
                    Value = $HKURegistryKey.GetValue($_)
                    Type =  $HKURegistryKey.GetValueKind($_)
                }
           
                $FilePath = Get-WinFilePath ($RegistryRun.Value -replace '"','')      
                $PEFileInfo = Get-PeFileInfo $FilePath
                $PEFileInfo |  Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
                    $RegistryRun | Add-Member -MemberType NoteProperty -Name "PEFileInfos_$_" -Value  $PEFileInfo.$_
                }
                $ResultList.Add($RegistryRun)
            }
        }
    }

    # Outputs
    if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }

}


