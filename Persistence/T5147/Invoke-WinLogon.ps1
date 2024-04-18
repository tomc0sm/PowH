function Invoke-WinLogon {

    <#
    .SYNOPSIS

    MITREATT&CK :https://attack.mitre.org/techniques/T1547/001/


    .DESCRIPTION

    MITREATT&CK :https://attack.mitre.org/techniques/T1547/004/

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

    $WinLogonRegistryKeys = @(
        "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )

    $ResultList = New-Object System.Collections.Generic.List[System.Object]

    $HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)

    foreach($KeyPath in $WinLogonRegistryKeys) {

        $HKLMKRegistryKey =  $HKLM.OpenSubKey($KeyPath, $false)
        if( $null -ne $HKLMKRegistryKey) {

            $WinLogon = [PSCustomObject]@{
                Path = "HKLM:\$KeyPath\Userinit"
                Name = $name
                Value = $HKLMKRegistryKey.GetValue("Userinit")
                Type =  $HKLMKRegistryKey.GetValueKind("Userinit")
            }
            $ResultList.Add($WinLogon)

            $WinLogon = [PSCustomObject]@{
                Path = "HKLM:\$KeyPath\Shell"
                Name = $name
                Value = $HKLMKRegistryKey.GetValue("Shell")
                Type =  $HKLMKRegistryKey.GetValueKind("Shell")
            }      
            $ResultList.Add($WinLogon)
           
            for($i = 0 ; $i -lt $ResultList.Count ; $i++){
                $PEFileInfoIndex = 0
                ($ResultList[$i].Value -split ",") | ForEach-Object { # parse comma separated values
                    if($_ -ne ""){
                        $FilePath = Get-WinFilePath ($_ -replace '"','')
                        $PEFileInfo = Get-PeFileInfo $FilePath
                        $PEFileInfo |  Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
                            $ResultList[$i] | Add-Member -MemberType NoteProperty -Name "$($PEFileInfoIndex)_PEFileInfos_$_" -Value  $PEFileInfo.$_
                            
                        }
                        $PEFileInfoIndex += 1
                    }
                }
            }
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
