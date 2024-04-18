function Invoke-Service{

    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1543/003/
    HKLM:\SYSTEM\CurrentControlSet\Services

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1543/003/


    .EXAMPLE 

    Invoke-Service -Show
    Invoke-Service -OutFile .\T5103-ScheduledTask.csv -Show

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Utils\Invoke-Utils.psd1") -Force

    function Get-DecodedServiceType {

        param (
            [int]$Type
        )
    
        $flags = @{
            1 = "Kernel Driver"
            2 = "File System Driver"
            4 = "Adapter"
            8 = "Recognizer Driver"
            16 = "Own Process"
            32 = "Share Process"
            256 = "Win32 Service"
            2048 = "User Service"
        }
    
        $flagList = @()
    
        foreach ($flag in $flags.Keys) {
            if ($Type -band $flag) {
                $flagList += $flags[$flag]
            }
        }
    
        return $flagList -join ", "
    }

    # Main 
    $ResultList = New-Object System.Collections.Generic.List[System.Object]

    $serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services"

    Get-ChildItem -Path $serviceRegistryPath | ForEach-Object {
        $Service = Get-ItemProperty -Path $_.PSPath
        #if($Service.type -ge 16) {  #exclude drivers
            $Service | Add-Member -MemberType NoteProperty -Name "DecodedType" -Value  (Get-DecodedServiceType  $Service.Type)
            if($Service.ImagePath -ne "" -and $null -ne $Service.ImagePath){
                $FilePath = Get-WinFilePath ($Service.ImagePath -replace '"','')
                $PEFileInfo = Get-PeFileInfo $FilePath
                $PEFileInfo |  Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
                    $Service | Add-Member -MemberType NoteProperty -Name "PEFileInfos_$_" -Value  $PEFileInfo.$_
                }
            }
            $ResultList.Add($Service)
        #}
    }

    # Output 
    if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }
   
}

