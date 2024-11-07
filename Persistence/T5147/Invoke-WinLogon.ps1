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

    Import-Module -Name ($PSScriptRoot + "\..\..\Core\Invoke-Core.psd1") -Force

    $WinLogonRegistryKeyPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
    $WinLogonRegistryKeyValues = @("UserInit","Shell","Notify")
    $ResultList = New-Object System.Collections.Generic.List[System.Object]
    $ObjFields = @("Path","Name","Value","Type")

    $HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)
    $HKU = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $env:COMPUTERNAME)
    $HKUPaths = New-Object System.Collections.Generic.List[System.Object]
    $HKU.GetSubKeyNames() | Where-Object {$_ -match '^S-1-5-21' -and $_ -notmatch '_Classes$'} | ForEach-Object {
        $HKUPaths.add($_ + "\")
    }

    # HKLM
    $HKLMWinLogonKey =  $HKLM.OpenSubKey($WinLogonRegistryKeyPath, $false)
    if( $null -ne $HKLMWinLogonKey) {
        foreach($keyValue in $WinLogonRegistryKeyValues){
            $WinLogon = [PSCustomObject]@{} 
            $WinLogon | Add-Member -Type NoteProperty -Name "Path" -Value "HKLM:\$WinLogonRegistryKeyPath\$keyValue"
            $WinLogon | Add-Member -Type NoteProperty -Name "Name" -Value $Name
            $WinLogon | Add-Member -Type NoteProperty -Name "Value" -Value $HKLMWinLogonKey.GetValue($keyValue)
            $WinLogon | Add-Member -Type NoteProperty -Name "Type" -Value $HKLMWinLogonKey.GetValueKind($keyValue)
            ($WinLogon.value -split ",") | ForEach-Object { # parse comma separated values
                if($_ -ne ""){
                    $WinLogonCpy = $WinLogon.PSObject.Copy()
                    $WinLogonCpy =  Add-FileInfo -Obj $WinLogonCpy -FilePath $_
                    $WinLogonCpy.Value = $_
                    $ResultList.Add($WinLogonCpy)
                }
            }   
        }
    }

    #HKU
    foreach($userPath in $HKUPaths){
        $fullPath = $userPath + "\" + $WinLogonRegistryKeyPath
        $HKUWinLogonKey = $HKU.OpenSubKey($fullPath, $false)
        if( $null -ne $HKUWinLogonKey) {
            foreach($keyValue in $WinLogonRegistryKeyValues){
                $WinLogon = [PSCustomObject]@{} 
                $WinLogon | Add-Member -Type NoteProperty -Name "Path" -Value "$fullPath""$WinLogonRegistryKeyPath\$keyValue"
                $WinLogon | Add-Member -Type NoteProperty -Name "Name" -Value $Name
                $WinLogon | Add-Member -Type NoteProperty -Name "Value" -Value $HKLMWinLogonKey.GetValue($keyValue)
                $WinLogon | Add-Member -Type NoteProperty -Name "Type" -Value $HKLMWinLogonKey.GetValueKind($keyValue)
                ($WinLogon.value -split ",") | ForEach-Object { # parse comma separated values
                    if($_ -ne ""){
                        $WinLogonCpy = $WinLogon.PSObject.Copy()
                        $WinLogonCpy =  Add-FileInfo -Obj $WinLogonCpy -FilePath $_
                        $WinLogonCpy.Value = $_
                        $ResultList.Add($WinLogonCpy)
                    }
                }   
            }
        }
    }

        

    # Output 

    $sortedProperties = Get-SortedProperties($ObjFields)

    if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }

}

#Invoke-WinLogon  -OutFile .\T5147-WinLogon.csv -Show