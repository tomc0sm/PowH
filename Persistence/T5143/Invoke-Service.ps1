function Invoke-Service{

    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1543/003/
    HKLM:\SYSTEM\CurrentControlSet\Services

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1543/003/


    .EXAMPLE 

    Invoke-Service -Show
    Invoke-Service -OutFile .\T5143-Service.csv -Show

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Utils\Invoke-Utils.psd1") -Force

    function Local:Get-DecodedServiceType {

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
    $ObjFields = @("ImagePath","Type","DecodedType","Start","ErrorControl","DisplayName","Owners","Group","PSPath","PSParentPath","PSChildName","PSProvider")

    
    Get-ChildItem -Path $serviceRegistryPath | ForEach-Object {
        $Service = Get-ItemProperty -Path $_.PSPath
        #if($Service.type -ge 16) {  #exclude drivers
            $Service | Add-Member -MemberType NoteProperty -Name "DecodedType" -Value  (Get-DecodedServiceType  $Service.Type)
            $Service = Add-FileInfo -Obj $Service -FilePath $Service.ImagePath
            $ResultList.Add($Service)
        #}
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

#Invoke-Service -OutFile .\T5143-Service.csv -Show