. "$PSScriptRoot\..\TypeDefinitions\Cryptography.ps1"

$BCRYPT_AES_ALGORITHM = "AES"
$BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"
$BCRYPT_CHAINING_MODE = "ChainingMode"
$BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength"
$STATUS_SUCCESS = 0
$HEADER_SIZE = 3
$IV_SIZE = 12    # 96-bit nonce
$TAG_SIZE = 16   # 128-bit tag


function Invoke-AES-GCM-Encrypt {
    param(
        [string]$PlainText,
        [byte[]]$MasterKey
    )

    # Parameter validation
    if ($PlainText -eq $null -or $MasterKey -eq $null) {
        Write-Error "Missing required parameter"
        return
    }
    if ($MasterKey.Length -ne 32) {
        Write-Error "MasterKey must be 32 bytes"
        return
    }

    #BCrypt handles Initalization
    $hAlgorithm = [IntPtr]::Zero
    $hKey = [IntPtr]::Zero
    $status = 0

    #Open algorithm provider
    $status = [PowH.Core.Cryptography.BCrypt]::BCryptOpenAlgorithmProvider([ref]$hAlgorithm, $BCRYPT_AES_ALGORITHM, $null, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "BCryptOpenAlgorithmProvider failed with status: $status"
        return ""
    }
    #Set GCM mode
    $status = [PowH.Core.Cryptography.BCrypt]::BCryptSetProperty($hAlgorithm, $BCRYPT_CHAINING_MODE,
        [System.Text.Encoding]::Unicode.GetBytes($BCRYPT_CHAIN_MODE_GCM), 16, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "BCryptSetProperty failed with status: $status"
        [PowH.Core.Cryptography.BCrypt]::BCryptCloseAlgorithmProvider($hAlgorithm, 0)
        return ""
    }
    #Generate symmetric key
    $status = [PowH.Core.Cryptography.BCrypt]::BCryptGenerateSymmetricKey($hAlgorithm, [ref]$hKey, $null, 0, $MasterKey, $MasterKey.Length, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "BCryptGenerateSymmetricKey failed with status: $status"
        [PowH.Core.Cryptography.BCrypt]::BCryptCloseAlgorithmProvider($hAlgorithm, 0)
        return ""
    }


    # Prepare Authenticated Cipher Mode Info
    $tagBuffer = [byte[]]::new($TAG_SIZE)
    $tagHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($tagBuffer, [System.Runtime.InteropServices.GCHandleType]::Pinned)
    $IV = [byte[]]::new($IV_SIZE)
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($IV)
    $IVHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($IV, [System.Runtime.InteropServices.GCHandleType]::Pinned)

    $authInfo = New-Object PowH.Core.Cryptography.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    $authInfo.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($authInfo)
    $authInfo.dwInfoVersion = 1
    $authInfo.pbNonce = $IVHandle.AddrOfPinnedObject()
    $authInfo.cbNonce = $IV_SIZE
    $authInfo.pbTag = $tagHandle.AddrOfPinnedObject()
    $authInfo.cbTag = $TAG_SIZE
    $authInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($authInfo))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($authInfo, $authInfoPtr, $false)


    # Get encrypted size
    $PlainBytes = [System.Text.Encoding]::ASCII.GetBytes($PlainText)
    $EncryptedSize = 0
    $status = [PowH.Core.Cryptography.BCrypt]::BCryptEncrypt($hKey, $PlainBytes, $PlainBytes.Length,  $authInfoPtr,
        $null, 0, $null, $null, [ref]$EncryptedSize, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "BCryptEncrypt (1) failed with status: $status"
        return ""
    }

    # Encrypt data
    $CipherText = [byte[]]::new($EncryptedSize)
    $status = [PowH.Core.Cryptography.BCrypt]::BCryptEncrypt($hKey, $PlainBytes, $PlainBytes.Length, $authInfoPtr,
        $null, 0, $CipherText, $EncryptedSize, [ref]$EncryptedSize, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "BCryptEncrypt (2) failed with status: $status"
        return ""
    }

    $header = [byte[]]::new(3)
    $result = [byte[]]::new($HEADER_SIZE + $IV_SIZE + $EncryptedSize + $TAG_SIZE)

   
    $ivBytes = New-Object byte[] $IV_SIZE
    [System.Runtime.InteropServices.Marshal]::Copy($authInfo.pbNonce, $ivBytes, 0, $IV_SIZE)
   
    # CORRECT - show actual tag bytes
    $tagBytes = New-Object byte[] $TAG_SIZE
    [System.Runtime.InteropServices.Marshal]::Copy($authInfo.pbTag, $tagBytes, 0, $TAG_SIZE)
   
    [Array]::Copy($header, 0, $result, 0, 3)
    [Array]::Copy($IV, 0, $result, 3, $IV_SIZE)
    [Array]::Copy($CipherText, 0, $result, 3 + $IV_SIZE, $EncryptedSize)
    [Array]::Copy($tagBuffer, 0, $result, 3 + $IV_SIZE + $EncryptedSize, $TAG_SIZE)

    return $result  
}


function Invoke-AES-GCM-Decrypt {

    param(
        [byte[]]$EncryptedBytes,
        [byte[]]$MasterKey
    )

    # Parameter validation
    if ($EncryptedBytes -eq $null -or $MasterKey -eq $null) {
        Write-Error "Missing required parameter"
        return
    }
    #if ($MasterKey.Length -ne 32 -or $EncryptedBytes.Length -ne 55) {
    #    Write-Error "MasterKey must be 32 bytes"
    #    return
    #}

    #Extract IV, ciphertext and tag from encrypted data
    $IV = [byte[]]::new($IV_SIZE)
    [Array]::Copy($EncryptedBytes, 3, $IV, 0, $IV_SIZE)
    $CipherText = $EncryptedBytes[15..($EncryptedBytes.Length - 17)]
    $Tag = [byte[]]::new($TAG_SIZE)
    [Array]::Copy($EncryptedBytes, ($EncryptedBytes.Length - 16), $Tag, 0, $TAG_SIZE)

    #BCrypt handles Initalization
    $hAlgorithm = [IntPtr]::Zero
    $hKey = [IntPtr]::Zero
    $status = 0

    #Open algorithm provider
    $status = [PowH.Core.Cryptography.BCrypt]::BCryptOpenAlgorithmProvider([ref]$hAlgorithm, $BCRYPT_AES_ALGORITHM, $null, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "BCryptOpenAlgorithmProvider failed with status: $status"
        return ""
    }
    #Set GCM mode
    $status = [PowH.Core.Cryptography.BCrypt]::BCryptSetProperty($hAlgorithm, $BCRYPT_CHAINING_MODE,
        [System.Text.Encoding]::Unicode.GetBytes($BCRYPT_CHAIN_MODE_GCM), 16, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "BCryptSetProperty failed with status: $status"
        [PowH.Core.Cryptography.BCrypt]::BCryptCloseAlgorithmProvider($hAlgorithm, 0)
        return ""
    }

    #Generate symmetric key
    $status = [PowH.Core.Cryptography.BCrypt]::BCryptGenerateSymmetricKey($hAlgorithm, [ref]$hKey, $null, 0, $MasterKey, $MasterKey.Length, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "BCryptGenerateSymmetricKey failed with status: $status"
        [PowH.Core.Cryptography.BCrypt]::BCryptCloseAlgorithmProvider($hAlgorithm, 0)
        return ""
    }

    # Prepare Authenticated Cipher Mode Info
    $tagHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($Tag, [System.Runtime.InteropServices.GCHandleType]::Pinned)
    $IVHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($IV, [System.Runtime.InteropServices.GCHandleType]::Pinned)

    $authInfo = New-Object PowH.Core.Cryptography.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    $authInfo.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($authInfo)
    $authInfo.dwInfoVersion = 1
    $authInfo.pbNonce = $IVHandle.AddrOfPinnedObject()
    $authInfo.cbNonce = $IV_SIZE
    $authInfo.pbTag = $tagHandle.AddrOfPinnedObject()
    $authInfo.cbTag = $TAG_SIZE
    $authInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($authInfo))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($authInfo, $authInfoPtr, $false)

    # Get decrypted size
    $PlainTextSize= 0
    $status = [PowH.Core.Cryptography.BCrypt]::BCryptDecrypt($hKey, $CipherText, $CipherText.Length, $authInfoPtr,
        $IV, $IV.Length, $null, 0, [ref]$PlainTextSize, 0)
    if ($status -ne $STATUS_SUCCESS) {      
        Write-Error "BCryptDecrypt (1) failed with status: $status"
        return ""
    }

    #Decrypt data
    $PlainText = [byte[]]::new($PlainTextSize)
    $status = [PowH.Core.Cryptography.BCrypt]::BCryptDecrypt($hKey, $CipherText, $CipherText.Length, $authInfoPtr,
        $IV, $IV.Length , $PlainText, $PlainText.Length, [ref]$PlainTextSize, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "BCryptDecrypt (2) failed with status: $status"
    }

   
    return $([System.Text.Encoding]::ASCII.GetString($PlainText))

}

