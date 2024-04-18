function Invoke-Prefetch {

    <#

    https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
    https://github.com/Invoke-IR/PowerForensics/blob/master/src/PowerForensicsCore/src/PowerForensics.Windows.Artifacts/Prefetch.cs

    .SYNOPSIS

    MITREATT&CK :https://attack.mitre.org/techniques/T1547/001/


    .DESCRIPTION

    MITREATT&CK :https://attack.mitre.org/techniques/T1547/004/

    .EXAMPLE 

    Invoke-WinLogon  -Show
    Invoke-WinLogon  -OutFile .\T5147-WinLogon.csv -Show

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False )]
        [string]$OutFile,
        [Parameter(Mandatory = $False )]
        [switch]$Show
    )

    $methodsDefinition = @"
[DllImport("ntdll.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)] 
    public static extern uint RtlDecompressBufferEx(
        ushort CompressionFormat,
        IntPtr UncompressedBuffer,
        uint UncompressedBufferSize,
        IntPtr CompressedBuffer,
        uint CompressedBufferSize,
        out uint FinalUncompressedSize,
        IntPtr WorkSpace
    );
[DllImport("ntdll.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)] 
public static extern uint RtlGetCompressionWorkSpaceSize(
    ushort CompressionFormat,
    out uint CompressBufferWorkSpaceSize,
    out uint CompressFragmentWorkSpaceSize
);
"@

    $compression = Add-Type -MemberDefinition $methodsDefinition -Name "Compression" -Namespace "Ntdll" -PassThru 

    Import-Module -Name ($PSScriptRoot + "\..\Utils\Invoke-Utils.psd1") -Force


    function Get-UnCompressPf{

        param (
            [Byte[]]$pfBytes
        )

        $header = $pfBytes[0..7]
        $signature = [BitConverter]::ToUInt32($header, 0)
        $compressedData = $pfBytes[8..$pfBytes.Length]
        $decompressedSize = [BitConverter]::ToUInt32($header, 4)
        $calgo = ($signature -shr 24) -band 0x0F # compression algorithm 
        $crcck = ($signature -shr 28) -band 0x0F # crc checksum 
        $magic = $signature -band 0x00FFFFFF

        # prepare workspace     
        $compressedSize = $compressedData.Length
        $CompressBufferWorkSpaceSize =[uint32]::Zero
        $CompressFragmentWorkSpaceSize = [uint32]::Zero
        $result = $compression::RtlGetCompressionWorkSpaceSize(
            $calgo,
            [ref]$CompressBufferWorkSpaceSize,
            [ref]$CompressFragmentWorkSpaceSize
        )

        if ($result -ne 0) {
            throw "Cannot get workspace size, error: $result"
        }

        # Prepare RtlDecompressBufferEx variables
        $finalUncompressedSize = [uint32]::Zero
        $workspaceBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($compressFragmentWorkSpaceSize)
        $uncompressedBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($decompressedSize)
        $memoryStream = New-Object System.IO.MemoryStream
        $memoryStream.Write($compressedData, 0, $compressedData.Length)
        $handle = [System.Runtime.InteropServices.GCHandle]::Alloc($memoryStream.GetBuffer(), 'Pinned')
        $compressedPtr = $handle.AddrOfPinnedObject()
        $handle.Free()
        $memoryStream.Close()

        # Decompress, chill, relax
        $status = $compression::RtlDecompressBufferEx(
            $calgo,
            $uncompressedBuffer,
            $decompressedSize,
            $compressedPtr,
            $compressedSize,
            [ref] $finalUncompressedSize,
            $workspaceBuffer
        )

        if ($status -ne 0) {
            Write-Host "Decompression failed"
            continue
        }
        if ($finalUncompressedSize -ne $decompressedSize) {
            Write-Host "Decompressed with a different size than original!"
        }

        $decompressedData = New-Object byte[] $decompressedSize
        [System.Runtime.InteropServices.Marshal]::Copy($uncompressedBuffer, $decompressedData, 0, $decompressedSize)

        return $decompressedData
    
    }
   
    $prefetchFolder = "C:\Windows\Prefetch"
    $prefetchFolder = "C:\Users\tom\Desktop\Scripts\HuntingSploit\Tests\Input"


   
    
    Get-ChildItem -Path $prefetchFolder -File -Filter *.pf | ForEach-Object {

        # Get and Parse Prefetch File
        $filePath = $prefetchFolder + "\" + $_
        $pfBytes = [System.IO.File]::ReadAllBytes($filePath)
        
        # Parse header
        $header = $pfBytes[0..7]
        $signature = [BitConverter]::ToUInt32($header, 0)
        $magic = $signature -band 0x00FFFFFF

        # check if PF is compressed
        if ([System.Convert]::ToString($magic,16) -eq "4d414d"){
            $pfBytes = Get-UnCompressPf $pfBytes
            Set-Content -Path "C:\Users\tom\Desktop\Scripts\HuntingSploit\Tests\Output\NOTEPAD.EXE-EB1B961A.pf.txt" -Value $pfBytes -Encoding Byte
        }


        # Parsing Prefetch
        $version = [BitConverter]::ToUInt32($pfBytes, 0)
        $signature = [BitConverter]::ToUInt32($pfBytes, 4)

        $signature

        if($signature -ne 1094927187) { # hexa 41434353  => SCCA 
            continue
        }
       
        $fileSize =  [BitConverter]::ToUInt32($pfBytes, 12)
        $execName = [System.Text.Encoding]::ASCII.GetString($pfBytes[16..75]) 
        $pfHash = ([BitConverter]::ToUInt32($pfBytes, 76))
        


        $fileSize
        $execName
        $pfHash
        $decodedPath

        #$hashValue = "D0D776AC"

        $Filename = "\VOLUME{01da066245b91169-6e45df5c}\WINDOWS\SYSTEM32\NOTEPAD.EXE"
        foreach ($character in $Filename.ToCharArray()) {
            $hashValue = (($hashValue * 37) + [int][char]$character) % 0x100000000
        }

        $hashValue

        $filename = ''
        $modulo = 0x100000000
        $multiplier = 4095  # Multiplicative inverse of 37 modulo $modulo

        while ($hashValue -gt 0) {
            $asciiCode = $HashValue % 37
            $filename = [char]$asciiCode + $filename
            $hashValue = [math]::DivRem($hashValue - $asciiCode, 37, [ref]$null)
        }
       
        $filename
        
       

        
        
        Write-Host "Decompression successful. Prefetch file ready to be parsed!"

    }


}

Invoke-Prefetch
