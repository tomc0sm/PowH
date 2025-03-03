function Invoke-BrowserExtensions {
    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1176/

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1176/

    .PARAMETER OutFile

    Export result to csv file. It can be absolute or relative path.

    .PARAMETER Show

    Output result


    .EXAMPLE 

    Invoke-BrowserExtensions -Show
    Invoke-BrowserExtensions -OutFile .\T1176-BrowserExtensions.csv -Show
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
    $Browsers = @(
        @{ Name = "Chrome"; Path = "Google\Chrome\User Data\Default\Extensions" },
        @{ Name = "Edge"; Path = "Microsoft\Edge\User Data\Default\Extensions" }
    )
    $Users = Get-WmiObject Win32_UserProfile | Where-Object { $_.Special -eq $false } | Select-Object -ExpandProperty LocalPath

    foreach ($User in $Users) {
        foreach ($Browser in $Browsers) {
            $ExtensionsPath = "$User\AppData\Local\$($Browser.Path)"
            if (Test-Path $ExtensionsPath) {
                Get-ChildItem -Path $ExtensionsPath -Directory | ForEach-Object {
                    $VersionFolder = Get-ChildItem -Path $_.FullName -Directory | Select-Object -First 1
                    #Write-Output $VersionFolder
                    if ($VersionFolder) {
                        $ManifestPath = "$($VersionFolder.FullName)\manifest.json"
                        $ManifestContent = ""
                        if (Test-Path $ManifestPath) {
                            $ManifestJson = Get-Content -Raw -Path $ManifestPath | ConvertFrom-Json
                            $ManifestData = [PSCustomObject]@{
                                Key = $ManifestJson.Key
                                Permissions = $ManifestJson.permissions -join ", "
                                Background  = $ManifestJson.background.scripts -join ", "
                                Content     = $ManifestJson.content_scripts.js -join ", "
                                WebRequest  = $ManifestJson.web_accessible_resources -join ", "
                            }
                            $JsFiles = Get-ChildItem -Path $VersionFolder.FullName -Filter "*.js" -File
                            foreach ($JsFile in $JsFiles) {
                                $Hash = (Get-FileHash -Path $JsFile.FullName -Algorithm SHA1).Hash
                                $ResultList     += [PSCustomObject]@{
                                    User        = $User
                                    Browser     = $Browser.Name
                                    Name        = $_.Name
                                    Version     = $VersionFolder.Name
                                    InstallDate = (Get-Item $_.FullName).CreationTime
                                    ID          = $_.Name
                                    Script      = $JsFile.Name
                                    SHA1        = $Hash
                                    Key         = $ManifestData.Key
                                    Permissions = $ManifestData.Permissions
                                    Background  = $ManifestData.Background
                                    Content     = $ManifestData.Content
                                    WebRequest  = $ManifestData.WebRequest
                                    Path        = $JsFile.FullName
                                }
                            }
                        }
                    }
                }
            }
        }
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

Invoke-BrowserExtensions -OutFile .\T1176-BrowserExtensions.csv -Show