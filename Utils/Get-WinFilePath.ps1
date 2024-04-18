function Get-WinFilePath {

    Param(
        [string] $FilePath
    )


    if($FilePath -match "%localappdata%"){
        $localAppDataPath = (Get-Item -Path $env:LOCALAPPDATA).FullName
        $FilePath = ($FilePath -replace "%localappdata%", $localAppDataPath)
    }

    if($FilePath -match "%windir%"){
        $winDir = "C:\Windows"
        $FilePath = ($FilePath -replace "%windir%", $winDir)
    }

    if ($FilePath.StartsWith("System32") -or $FilePath.StartsWith("system32") -or $FilePath.StartsWith("\SystemRoot\")) {
        $System32Directory = Join-Path -Path $env:SystemRoot -ChildPath 'System32' 
        $FilePath = Join-Path -Path $System32Directory -ChildPath (Split-Path -Path $FilePath -Leaf)
    }

    $CommandPath =  Get-Command  $FilePath -ErrorAction SilentlyContinue
    if($CommandPath.Path -ne "" -and $null -ne $CommandPath.Path){
        $FilePath = $CommandPath.Path
    }

    $pattern = '(?<!\S)(([a-zA-Z]:\\|\\\\)([^<>:"/\\|?*\x00-\x1F]+\\)*([^<>:"/\\|?*\x00-\x1F\s]+)\.([^<>:"/\\|?*\x00-\x1F\s]+)(?<!\s))'
    
    return ($FilePath | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches.Value })

}