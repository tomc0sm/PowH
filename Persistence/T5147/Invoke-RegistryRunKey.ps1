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

    
    $AutoRunRegistryKeys = @(
        "Software\Microsoft\Windows\CurrentVersion\Run", 
        "Software\Microsoft\Windows\CurrentVersion\RunOnce", 
        "Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "Sotware\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $ResultList = New-Object System.Collections.Generic.List[System.Object]
    $ObjFields = @("Path","Name","Value","Type")

    $HKU = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $env:COMPUTERNAME)
    $HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)
        
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
            $RegistryRun = [PSCustomObject]@{} 
            $RegistryRun | Add-Member -Type NoteProperty -Name "Path" -Value "HKLM:\$KeyPath"
            $RegistryRun | Add-Member -Type NoteProperty -Name "Name" -Value $_
            $RegistryRun | Add-Member -Type NoteProperty -Name "Value" -Value $HKLMKRegistryKey.GetValue($_)
            $RegistryRun | Add-Member -Type NoteProperty -Name "Value" -Value $HKLMKRegistryKey.GetValueKind($_)
            $FilePath = $RegistryRun.Value -replace '"',''
            $RegistryRun = Add-FileInfo -Obj $RegistryRun -FilePath $FilePath
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
                $RegistryRun = [PSCustomObject]@{} 
                $RegistryRun | Add-Member -Type NoteProperty -Name "Path" -Value "HKU:\$fullPath"
                $RegistryRun | Add-Member -Type NoteProperty -Name "Name" -Value $_
                $RegistryRun | Add-Member -Type NoteProperty -Name "Value" -Value $HKLMKRegistryKey.GetValue($_)
                $RegistryRun | Add-Member -Type NoteProperty -Name "Value" -Value $HKLMKRegistryKey.GetValueKind($_)
                $FilePath = $RegistryRun.Value -replace '"',''
                $RegistryRun = Add-FileInfo -Obj $RegistryRun -FilePath $FilePath
                $ResultList.Add($RegistryRun)
            }
        }
    }

    $sortedProperties = Get-SortedProperties($ObjFields)

    # Outputs
    if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }

}


#Invoke-RegistryRunKey -OutFile .\T5147-RegistryRunKey.csv -Show