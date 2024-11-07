function Invoke-LogonScript {
    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1037/001/

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1037/001/

    .PARAMETER OutFile

    Export result to csv file. It can be absolute or relative path.

    .PARAMETER Show

    Output result


    .EXAMPLE 

    Invoke-LogonScript -Show
    Invoke-LogonScript -OutFile .\T1037-LogonScript.csv -Show

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Core\Invoke-Core.psd1") -Force

    $ResultList = New-Object System.Collections.Generic.List[System.Object]
    $ObjFields = @("Path","Name","Value","Type")

    $HKU = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $env:COMPUTERNAME)
    $HKUPaths = New-Object System.Collections.Generic.List[System.Object]
    $HKU.GetSubKeyNames() | Where-Object {$_ -match '^S-1-5-21' -and $_ -notmatch '_Classes$'} | ForEach-Object {
        $HKUPaths.add($_ + "\")
    }

    foreach($userPath in $HKUPaths){
        $fullPath = $userPath + "\Environment"
        $HKUEnvironmentKey = $HKU.OpenSubKey($fullPath, $false)
        $HKUEnvironmentKey.GetValueNames() | ForEach-Object {
            $Environment = [PSCustomObject]@{} 
            $Environment | Add-Member -Type NoteProperty -Name "Path" -Value "HKU:\$fullPath"
            $Environment | Add-Member -Type NoteProperty -Name "Name" -Value $_
            $Environment | Add-Member -Type NoteProperty -Name "Value" -Value $HKUEnvironmentKey.GetValue($_)
            $Environment | Add-Member -Type NoteProperty -Name "Type" -Value $HKUEnvironmentKey.GetValueKind($_)
            ($Environment.Value -split ";") | ForEach-Object { # parse comma separated values
                if($_ -ne ""){
                    Write-Host $_
                    $EnvironmentCpy = $Environment.PSObject.Copy()
                    $EnvironmentCpy =  Add-FileInfo -Obj $EnvironmentCpy -FilePath $_
                    $EnvironmentCpy.Value = $_
                    $ResultList.Add($EnvironmentCpy)
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

#Invoke-LogonScript -OutFile .\T1037-LogonScript.csv -Show
