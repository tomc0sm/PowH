Get-ChildItem -Recurse -File (Join-Path $PSScriptRoot *.ps1) | ForEach-Object { . $_.FullName}
