. "$PSScriptRoot\..\TypeDefinitions\Cryptography.ps1"

$BCRYPT_AES_ALGORITHM = "AES"
$BCRYPT_CHAIN_MODE_CBC = "ChainingModeCFB"
$BCRYPT_CHAINING_MODE = "ChainingMode"
$STATUS_SUCCESS = 0
$BCRYPT_BLOCK_PADDING = 0x00000001

function Invoke-AES-CFB-Encrypt {
    param(
        [string]$PlainText,
        [string]$Key, 
        [string]$IV
    )

    # Parameter validation
    if ($PlainText -eq $null -or $Key -eq $null -or $IV -eq $null) {
        Write-Error "Missing required parameter"
        return
    }
    if ($Key.Length -ne 32 -or $IV.Length -ne 16) {
        Write-Error "Key must be 32 bytes and IV must be 16 bytes"
        return
    }

    # Initialize handles
    $hAlgorithm = [System.IntPtr]::Zero
    $hKey = [System.IntPtr]::Zero

    # Open algorithm handle
    $status = [BCrypt]::BCryptOpenAlgorithmProvider([ref]$hAlgorithm, $BCRYPT_AES_ALGORITHM, $null, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "Failed to open algorithm provider $status"
        return
    }

    # Get key object length
    $keyObjLength = [byte[]]::new(4)
    $bytesWritten = 0
    $status = [BCrypt]::BCryptGetProperty($hAlgorithm, "ObjectLength", $keyObjLength, 4, [ref]$bytesWritten, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "Failed to get property ObjectLength $status"
        return
    }

    # Set CBC mode
    $status = [BCrypt]::BCryptSetProperty($hAlgorithm, $BCRYPT_CHAINING_MODE, [System.Text.Encoding]::Unicode.GetBytes($BCRYPT_CHAIN_MODE_CBC), 16, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "Failed to set chaining mode $status"
        return
    }

    # Generate symmetric key
    $cbKeyObject = [BitConverter]::ToInt32($keyObjLength, 0)
    $pbKeyObject = [byte[]]::new($cbKeyObject)
    $status = [BCrypt]::BCryptGenerateSymmetricKey($hAlgorithm, [ref]$hKey, $pbKeyObject, $cbKeyObject, [System.Text.Encoding]::Unicode.GetBytes($Key), 32, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "Failed to generate symmetric key $status"
        return
    }

    # Encrypt data
    $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $blockSize = 16
    $paddedLength = [Math]::Ceiling($plaintextBytes.Length / $blockSize) * $blockSize
    $outputBuffer = [byte[]]::new($paddedLength)
    $bytesWritten = 0
    
    $status = [BCrypt]::BCryptEncrypt($hKey, $plaintextBytes, $plaintextBytes.Length, [IntPtr]::Zero, 
        [System.Text.Encoding]::Unicode.GetBytes($IV), 16, $outputBuffer, $outputBuffer.Length, 
        [ref]$bytesWritten, $BCRYPT_BLOCK_PADDING)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "Failed to encrypt data $status"
        return
    }

    #return $outputBuffer[0..($bytesWritten-1)]
    # Get actual encrypted bytes
    $encryptedBytes = $outputBuffer[0..($bytesWritten-1)]

    #return $encryptedBytes

    # Create array with IV + encrypted data
    $encryptedWithIV = [byte[]]::new(16 + $encryptedBytes.Length)
    [Array]::Copy([System.Text.Encoding]::UTF8.GetBytes($IV), 0, $encryptedWithIV, 0, 16)
    [Array]::Copy($encryptedBytes, 0, $encryptedWithIV, 16, ($encryptedBytes.Length))
    return $encryptedWithIV
}

function Invoke-AES-CFB-Decrypt{

    param(
        [byte[]]$EncryptedData,
        [string]$Key
       
        
    )

     # Extract IV and ciphertext from encrypted data
    $IV =  [System.Text.Encoding]::UTF8.GetString($EncryptedData[0..15])  # First 16 bytes are raw IV bytes
    $ciphertext = $EncryptedData[16..($EncryptedData.Length - 1)]  # Rest is ciphertext

    # checkpoint 
    if ($EncryptedData -eq $null -or $Key -eq $null -or $IV -eq $null) {
        Write-Error "Missing required parameter"
        return
    }
    # check Key and IV length
    if ($Key.Length -ne 32 -or $IV.Length -ne 16) {
        Write-Error "Key must be 32 bytes and IV must be 16 bytes"
        Write-Error "IV length $($IV.Length)"
        Write-Error "Key length $($Key.Length)"
        return
    }

    # Initialize HAlgorithm and HKey handles pointers
    $hAlgorithm = [System.IntPtr]::Zero
    $hKey = [System.IntPtr]::Zero

    ## Open an algorithm handle
    $status = [BCrypt]::BCryptOpenAlgorithmProvider([ref]$hAlgorithm, $BCRYPT_AES_ALGORITHM, $null, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "Failed to open algorithm provider $status"
        return
    }
    # Calculate the size of the buffer to hold the KeyObject for BCryptGetProperty. 
    $keyObjLength = [byte[]]::new(4)
    $bytesWritten = 0
    $status = [BCrypt]::BCryptGetProperty($hAlgorithm, "ObjectLength", $keyObjLength, 4, [ref]$bytesWritten, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "Failed to get property ObjectLength $status"
        return
    }

    # Set chaining mode to CBC
    $status = [BCrypt]::BCryptSetProperty($hAlgorithm, $BCRYPT_CHAINING_MODE, [System.Text.Encoding]::Unicode.GetBytes($BCRYPT_CHAIN_MODE_CBC), 16, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "Failed to set chaining mode $status"
        return
    }



    # Generate the key
    $cbKeyObject = [BitConverter]::ToInt32($keyObjLength, 0)
    $pbKeyObject = [byte[]]::new($cbKeyObject)
    $status = [BCrypt]::BCryptGenerateSymmetricKey($hAlgorithm, [ref]$hKey, $pbKeyObject, $cbKeyObject, [System.Text.Encoding]::Unicode.GetBytes($Key), 32, 0)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "Failed to generate symmetric key $status"
        return
    }

    # Decrypt the data
    $blockSize = 16
    $paddedLength = [Math]::Ceiling($ciphertext.Length / $blockSize) * $blockSize
    $outputBuffer = [byte[]]::new($paddedLength)
    $bytesWritten = 0
    $status = [BCrypt]::BCryptDecrypt($hKey, $ciphertext, $ciphertext.Length, [IntPtr]::Zero, 
    [System.Text.Encoding]::Unicode.GetBytes($IV), 16, $outputBuffer, $outputBuffer.Length, 
    [ref]$bytesWritten, $BCRYPT_BLOCK_PADDING)
    if ($status -ne $STATUS_SUCCESS) {
        Write-Error "Failed to decrypt data $status"
        return
    }
    return $outputBuffer[0..($bytesWritten-1)]

}

