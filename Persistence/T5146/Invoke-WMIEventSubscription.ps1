function Invoke-WMIEventSubscription {
    <#
    .SYNOPSIS

    MITREATT&CK :https://attack.mitre.org/techniques/T1546/003/

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1546/003/

    .PARAMETER OutFile

    Export result to csv file. It can be absolute or relative path.

    .PARAMETER Show

    Output result


    .EXAMPLE 

    Invoke-WMIEventSubscription -Show
    Invoke-WMIEventSubscription -OutFile .\T5146-WMIEventSubscription.csv -Show

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Core\Invoke-Core.psd1") -Force

    # Main
    $ResultList = New-Object System.Collections.Generic.List[System.Object]
    $EventList = New-Object System.Collections.Generic.List[System.Object]
    $ObjFields = @("Name","__RELPATH", "PSComputerName" ,"__CLASS", "__SUPERCLASS" , "__NAMESPACE" , "__PATH", "Consumer", "Filter", "CommandLineTemplate" , "ExecutablePath", "Query")
    
    Get-WMIObject -Namespace root\Subscription -Class __EventFilter | ForEach-Object {
        $EventList.Add($_)
    }
  
    Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | ForEach-Object {
        $EventList.Add($_)
    }

    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding  | ForEach-Object {
        $EventList.Add($_)
    }

    for($i =0; $i -lt $EventList.Count; $i++){
        $WMIEvent = [PSCustomObject]@{}
        foreach ($prop in $ObjFields){
            $WMIEvent | Add-Member -MemberType NoteProperty -Name $prop -Value  ($EventList[$i].$prop -join ",")
        }
        $ResultList.Add($WMIEvent) 
    }
   

    # Outputs

    $sortedProperties = $ObjFields

    if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }

    return $ResultList

}

#Invoke-WMIEventSubscription -OutFile .\T5146-WMIEventSubscription.csv -Show