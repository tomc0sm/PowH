function Get-PeFileHeaders {

    Param(
        [byte[]] $fileContent,
        [String] $filePath
    )

    # file path arg. If defined we try to load binary content
    if (-Not $null -eq $FilePath) {
        if (-Not (Test-Path $FilePath)) {
            Write-Error "Invalid file path."
            return 
        }

        $fileContent = [System.IO.File]::ReadAllBytes($FilePath)
    }

    # check binary content
    if ( $null -eq $fileContent -or $fileContent.Length -eq 0) {
        Write-Error "Invalid or empty file content."
        return
    }

    # easy way
    function Read-Byte($bytes, $offset) {
        return $bytes[$offset]
    }
    function Read-UInt16($bytes, $offset) {
        return [BitConverter]::ToUInt16($bytes[$offset..($offset + 1)], 0)
    }
    function Read-UInt32($bytes, $offset) {
        return [BitConverter]::ToUInt32($bytes[$offset..($offset + 3)], 0)
    }
    function Read-UInt64($bytes, $offset) {
        return [BitConverter]::ToUInt64($bytes[$offset..($offset + 7)], 0)
    }


    # DOS Header 
    $DosHeadersOffsets = @{
        "e_magic_offset" = 0 
        "e_oemid_offset" = 36
        "e_lfanew_offset" = 60 
    }

    $DosHeader = [PSCustomObject]@{}
    $DosHeader | Add-Member -MemberType NoteProperty -Name "e_magic" -Value  (Read-UInt16 $fileContent $DosHeadersOffsets["e_magic_offset"])  # Magic number (MZ)
    $DosHeader | Add-Member -MemberType NoteProperty -Name "e_oemid" -Value  (Read-UInt16 $fileContent $DosHeadersOffsets["e_oemid_offset"])  # OEM identifier
    $DosHeader | Add-Member -MemberType NoteProperty -Name "e_lfanew" -Value  (Read-UInt16 $fileContent $DosHeadersOffsets["e_lfanew_offset"])  # Offset of PE header
   
    # -- NT Headers 
    $fileHeadersOffsets = @{
        "signature_offset" = $DosHeader.e_lfanew + 0 
        "machine_offset" = $DosHeader.e_lfanew + 4
        "numberOfSections_offset" = $DosHeader.e_lfanew + 6
        "timeDateStamp_offset" =  $DosHeader.e_lfanew + 8
        "sizeOfOptionalHeaders_offset" = $DosHeader.e_lfanew + 20
        "characteristics_offset" = $DosHeader.e_lfanew + 22
        "optionalHeader_offset" = $DosHeader.e_lfanew + 24
    }

    $FileHeader = [PSCustomObject]@{}
    $FileHeader | Add-Member -MemberType NoteProperty -Name "signature" -Value  (Read-UInt16 $fileContent $fileHeadersOffsets["signature_offset"]) 
    $FileHeader | Add-Member -MemberType NoteProperty -Name "machineType" -Value  (Read-UInt16 $fileContent $fileHeadersOffsets["machine_offset"])  
    $FileHeader | Add-Member -MemberType NoteProperty -Name "numberOfSections" -Value  (Read-UInt16 $fileContent $fileHeadersOffsets["numberOfSections_offset"])  
    $FileHeader | Add-Member -MemberType NoteProperty -Name "timeDateStamp" -Value  (Read-UInt16 $fileContent $fileHeadersOffsets["timeDateStamp_offset"])
    $FileHeader | Add-Member -MemberType NoteProperty -Name "sizeOfOptionalHeaders" -Value  (Read-UInt16 $fileContent $fileHeadersOffsets["sizeOfOptionalHeaders_offset"]) 
    $FileHeader | Add-Member -MemberType NoteProperty -Name "characteristics" -Value  (Read-UInt16 $fileContent $fileHeadersOffsets["characteristics_offset"])
  
    # ------ Optional Headers 
    $optionalHeadersOffsets = @{
        "magic_offset" = $fileHeadersOffsets["optionalHeader_offset"] + 0 
        "majorLinkerVersion_offset" = $fileHeadersOffsets["optionalHeader_offset"] + 2 
        "minorLinkerVersion_offset" = $fileHeadersOffsets["optionalHeader_offset"] + 3 
        "sizeOfCode_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 4 
        "sizeOfInitializedDatas_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 8 
        "sizeOfUnitializedData_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 12 
        "addressOfEntryPoint_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 16 
        "baseOfCode_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 20 
        "sectionAlignment_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 32 
        "fileAlignement_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 36 
        "majorOperatingSystemVersion_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 40 
        "minorOperatingSystemVersion_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 42
        "majorImageVersion_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 44 
        "minorImageVersion_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 46 
        "majorSubSystemVersion_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 48 
        "minorSubSystemVersion_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 50 
        "win32VersionValue_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 52 
        "imageSize_offset" = $fileHeadersOffsets["optionalHeader_offset"] + 56 
        "sizeOfHeaders_offset" = $fileHeadersOffsets["optionalHeader_offset"] + 60
        "subSystem_offset" = $fileHeadersOffsets["optionalHeader_offset"] + 68
        "dllCharacteristics_offset" = $fileHeadersOffsets["optionalHeader_offset"] + 70
    }

    $PE32PlusOptionalHeadersOffsets = @{
        "imageBase_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 24 # QWORD 
    }

    $PE32OptionalHeadersOffsets =  @{
        "baseOfData_offset" = $fileHeadersOffsets["optionalHeader_offset"] + 24 # DWORD
        "imageBase_offset" =  $fileHeadersOffsets["optionalHeader_offset"] + 28 # DWORD
    }

    $OptionalHeader = [PSCustomObject]@{}
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "magic" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["magic_offset"])

    if ($OptionalHeader.magic -eq 0X10B){
        $optionalHeadersOffsets += $PE32OptionalHeadersOffsets  
        $OptionalHeader | Add-Member -MemberType NoteProperty -Name "imageBase" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["imageBase_offset"])
    }

    elseif ($OptionalHeader.magic -eq 0X20B){
        $optionalHeadersOffsets += $PE32PlusOptionalHeadersOffsets
        $OptionalHeader | Add-Member -MemberType NoteProperty -Name "imageBase" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["imageBase_offset"])
    }

    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "majorLinkerVersion" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["majorLinkerVersion_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "minorLinkerVersion" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["minorLinkerVersion_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "sizeOfCode" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["sizeOfCode_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "sizeOfInitializedDatas" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["sizeOfInitializedDatas_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "sizeOfUnitializedDatas" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["sizeOfUnitializedDatas_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "addressOfEntryPoint" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["addressOfEntryPoint_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "baseOfCode" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["baseOfCode_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "sectionAlignment" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["sectionAlignment_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "fileAlignement" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["fileAlignement_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "imageSize" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["imageSize_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "sizeOfHeaders" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["sizeOfHeaders_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "subSystem" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["subSystem_offset"])
    $OptionalHeader | Add-Member -MemberType NoteProperty -Name "dllCharacteristics" -Value  (Read-UInt16 $fileContent $optionalHeadersOffsets["dllCharacteristicsoffset"])

    # -------- Data Directories #
    $directoryNames = @(
        "EXPORT",
        "IMPORT",
        "RESOURCE",
        "EXCEPTION",
        "SECURITY",
        "BASERELOC",
        "DEBUG",
        "ARCHITECTURE",
        "GLOBAL_PTR",
        "TLS",
        "LOAD_CONFIG",
        "BOUND_IMPORT",
        "IMPORT_ADDRESS_TABLE",
        "DELAY_IMPORT",
        "COM_DESCRIPTOR"
    )

    $optionalHeaderSize = 96
    if ($OptionalHeader.magic -eq 0X20B) {
        $optionalHeaderSize = 112
    }
    $dataDirectory_offset = $fileHeadersOffsets["optionalHeader_offset"] + $optionalHeaderSize
    $numberofDirectories = 15
    $directorySize= 8

    $DataDirectories = New-Object System.Collections.Generic.List[System.Object]
    for ($i = 0; $i -lt $numberofDirectories; $i ++){

            $directory_offset = $dataDirectory_offset + ($i * $directorySize)

            $DirectoryEntry = [PSCustomObject]@{}
            $DirectoryEntry | Add-Member -MemberType NoteProperty -Name "name" -Value ($directoryNames[$i])
            $DirectoryEntry | Add-Member -MemberType NoteProperty -Name "virtualAddress" -Value (Read-UInt32 $fileContent ($directory_offset))
            $DirectoryEntry | Add-Member -MemberType NoteProperty -Name "size" -Value (Read-UInt32 $fileContent ($directory_offset + 4))
          
            $DataDirectories.Add($DirectoryEntry)


    }


    # -- Sections Headers 
    $SectionHeaders = New-Object System.Collections.Generic.List[System.Object]
    $sectionHeaderStart = $fileHeadersOffsets["optionalHeader_offset"] + $FileHeader.sizeOfOptionalHeaders
    $sizeOfSectionHeader = 40
    for ($i = 0; $i -lt $FileHeader.numberOfSections; $i++){
        
        $section_offset = $sectionHeaderStart + ($i * $sizeOfSectionHeader)
        $SectionHeader = [PSCustomObject]@{}
        $SectionHeader | Add-Member -MemberType NoteProperty -Name "name" -Value (([System.Text.Encoding]::ASCII).GetString($fileContent[($section_offset)..($section_offset + 7)]).Trim([char]0))
        $SectionHeader | Add-Member -MemberType NoteProperty -Name "virtualSize" -Value (Read-UInt32 $fileContent ($section_offset + 8))
        $SectionHeader | Add-Member -MemberType NoteProperty -Name "virtualAddress" -Value (Read-UInt32 $fileContent ($section_offset + 12))
        $SectionHeader | Add-Member -MemberType NoteProperty -Name "sizeofRawData" -Value (Read-UInt32 $fileContent ($section_offset + 16))
        $SectionHeader | Add-Member -MemberType NoteProperty -Name "pointerToRawData" -Value (Read-UInt32 $fileContent ($section_offset + 20))
        $SectionHeaders.Add($SectionHeader)
       
    }

    $PeHeader = [PSCustomObject]@{
        "DosHeader" = $DosHeader
        "FileHeader" = $FileHeader
        "OptionalHeader" = $OptionalHeader
        "DataDirectories" = $DataDirectories
        "SectionHeaders" = $SectionHeaders
    }


    return $PeHeader
   

}


