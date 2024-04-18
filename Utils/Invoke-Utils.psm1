Get-ChildItem (Join-Path $PSScriptRoot *.ps1) | ForEach-Object { . $_.FullName}
