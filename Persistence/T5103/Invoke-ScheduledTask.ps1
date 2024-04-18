function Invoke-ScheduledTask {
    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1053/005/

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1053/005/

    .PARAMETER OutFile

    Export result to csv file. It can be absolute or relative path.

    .PARAMETER Show

    Output result


    .EXAMPLE 

    Invoke-ScheduledTask -Show
    Invoke-ScheduledTask -OutFile .\T5103-ScheduledTask.csv -Show

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Utils\Invoke-Utils.psd1") -Force

    
    # Parse XML Task File 
    function Local:Convert-XMLToProperties {
        param(
            [Parameter(Mandatory = $False )]
            [System.Xml.XmlElement] $XMLElement,
            [Parameter(Mandatory = $False )]
            [string] $Prefix = "",
            [Parameter(Mandatory = $False )]
            [PSCustomObject]$Obj = @{}
        )
       
        foreach ($childNode in $XMLElement.ChildNodes) {
            if($Prefix -ne "" -and $childNode.LocalName -ne "#text"){
                $Prefix = "$($Prefix)_"
            }
            if($childNode.LocalName -ne "#text"){
                $Prefix += $($childNode.LocalName)
            }
            if($childNode.HasChildNodes){
                $Obj = Convert-XMLToProperties -XMLElement $childNode -Prefix $Prefix -Obj $Obj
            }
            else {
                if($childNode.Value -ne "" -and $null -ne $childNode.Value) {
                    $Obj | Add-Member -MemberType NoteProperty -Name $Prefix -Value ($childNode.Value)
                }
            }
    
            if(-not $Prefix.Contains("_")){
                $Prefix = ""
            }
            $Prefix = $Prefix -replace "_[^_]+$"
        }
        return $Obj
    }

    # Main
    $ResultList = New-Object System.Collections.Generic.List[System.Object]

    (Get-ScheduledTask -TaskPath "\") | ForEach-Object {
        
        $TaskXml = [XML]((Get-ScheduledTask -TaskName $_.TaskName) |Export-ScheduledTask)
        $ScheduledTask = [PSCustomObject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
        }

        $ScheduledTask = Convert-XMLToProperties -XMLElement $TaskXml.Task -Obj $ScheduledTask
       
        # Data enrichment
        $FilePath = Get-WinFilePath $ScheduledTask.Actions_Exec_Command
        $PEFileInfo = Get-PeFileInfo $FilePath
        $PEFileInfo |  Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
            $ScheduledTask | Add-Member -MemberType NoteProperty -Name "PEFileInfos_$_" -Value  $PEFileInfo.$_
        }
        
        $ResultList.Add($ScheduledTask)
    }
    
    # Outputs
    if($PSBoundParameters.ContainsKey('OutFile') -eq $true){
        $ResultList | Select-Object $sortedProperties | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    if($PSBoundParameters.ContainsKey('Show') -eq $true){
        Write-Output  $ResultList | Select-Object $sortedProperties | Format-List
    }

    return $ResultList

}

