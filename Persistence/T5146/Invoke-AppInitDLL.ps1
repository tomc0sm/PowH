function Invoke-AppInitDLL {

    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1546/010/

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1546/010/

    .EXAMPLE 

    Invoke-WinLogon  -Show
    Invoke-WinLogon  -OutFile .\T5147-WinLogon.csv -Show

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Utils\Invoke-Utils.psd1") -Force

    $AppInitDLLRegistryKeys = @(
        "Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )
   
    $ResultList = New-Object System.Collections.Generic.List[System.Object]

    $HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)

    foreach($KeyPath in $AppInitDLLRegistryKeys) {

        $HKLMKRegistryKey =  $HKLM.OpenSubKey($KeyPath, $false)
        if( $null -ne $HKLMKRegistryKey) {
            $AppInitDLL = [PSCustomObject]@{
                Path = "HKLM:\$KeyPath\AppInit_DLLs"
                Name = $name
                Value = $HKLMKRegistryKey.GetValue("AppInit_DLLs")
                Type =  $HKLMKRegistryKey.GetValueKind("AppInit_DLLs")
            }
            
            if($AppInitDLL.Value -ne "" -and $null -ne $AppInitDLL.Value){
                $PEFileInfoIndex = 0
                ($AppInitDLL.Value -split ",") | ForEach-Object { # parse comma separated values
                    if($_ -ne ""){
                        $FilePath = Get-WinFilePath ($_ -replace '"','')
                        $PEFileInfo = Get-PeFileInfo $FilePath
                        $PEFileInfo |  Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
                           $AppInitDLL | Add-Member -MemberType NoteProperty -Name "$($PEFileInfoIndex)_PEFileInfos_$_" -Value  $PEFileInfo.$_
                            
                        }
                        $PEFileInfoIndex += 1
                    }
                }
            }
            $ResultList.Add($AppInitDLL)
        }
    }

    # Output 
    if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }
    
}
