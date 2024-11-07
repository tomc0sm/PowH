function Invoke-StartupFolder {
    <#
    .SYNOPSIS
    
    MITREATT&CK : https://attack.mitre.org/techniques/T1547/001/


    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1547/001/

    .EXAMPLE 

    Invoke-StartupFolder  -Show
    Invoke-StartupFolder  -OutFile .\T5147-StartUpFolder.csv -Show


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
    $ObjFields = @("Name","Path","TargetPath")

    $StartUpMenuPaths = New-Object System.Collections.Generic.List[System.Object]
    $StartUpMenuPaths.Add("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")

    Get-LocalUser | ForEach-Object {
        $userpath = "C:\Users\$_\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        if(Test-Path $userpath){
            $StartUpMenuPaths.Add($userpath)
        }
    }

    $sh = New-Object -com wscript.Shell

    foreach($path in $StartUpMenuPaths){
        Get-ChildItem -Path $path -File | Where-Object  { $_.Name -ne 'desktop.ini' } |  Select-Object -Property Name,FullName,Extension | ForEach-Object {
            if($_.Extension -eq ".lnk"){
                $targetFile = $sh.CreateShortcut($_.FullName).TargetPath
            }
            else {
                $targetFile = $_.FullName
            }
            $targetFile
            $StartUpMenu = [PSCustomObject]@{
                Name= $_.Name
                Path = $_.FullName
                TargetPath = $targetFile
            }

            $FilePath = Get-WinFilePath ($StartUpMenu.TargetPath -replace '"','')
            $StartUpMenu = Add-FileInfo -Obj $StartUpMenu -FilePath $FilePath
            $ResultList.Add($StartUpMenu)

           
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

#Invoke-StartupFolder  -OutFile .\T5147-StartUpFolder.csv -Show