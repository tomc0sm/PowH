function Invoke-AppInitDLL {

    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1546/010/

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1546/010/

    .EXAMPLE 

    Invoke-AppInitDLL  -Show
    Invoke-AppInitDLL  -OutFile .\T5146-AppInitDLL.csv -Show

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Core\Invoke-Core.psd1") -Force

    $AppInitDLLRegistryKeys = @(
        "Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )
   
    $ResultList = New-Object System.Collections.Generic.List[System.Object]
    $ObjFields = @("Path","Name","Value","Type")

    $HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)

    foreach($KeyPath in $AppInitDLLRegistryKeys) {

        $HKLMKRegistryKey =  $HKLM.OpenSubKey($KeyPath, $false)
        if( $null -ne $HKLMKRegistryKey) {
            $AppInitDLL = [PSCustomObject]@{} 
            $AppInitDLL | Add-Member -Type NoteProperty -Name "Path" -Value "HKLM:\$KeyPath\AppInit_DLLs"
            $AppInitDLL | Add-Member -Type NoteProperty -Name "Name" $name
            $AppInitDLL | Add-Member -Type NoteProperty -Name "Value" $HKLMKRegistryKey.GetValue("AppInit_DLLs")
            $AppInitDLL | Add-Member -Type NoteProperty -Name "Type" $HKLMKRegistryKey.GetValueKind("AppInit_DLLs")
            ($AppInitDLL.value -split ",") | ForEach-Object { # parse comma separated values
                if($_ -ne ""){
                    $AppInitDLLCpy = $AppInitDLL.PSObject.Copy()
                    $AppInitDLLCpy =  Add-FileInfo -Obj $AppInitDLL -FilePath $_
                    $ResultList.Add($AppInitDLLCpy)
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

#Invoke-AppInitDLL  -OutFile .\T5146-AppInitDLL.csv -Show