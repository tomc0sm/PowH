
function Get-FileInfo {

    Param(
        [string] $FilePath
    )

    if(-not(Test-Path $FilePath -PathType Leaf)){
        return ""
    }

    $file = Get-Item $FilePath

    $fileVersionInfo = Get-ItemPropertyValue -Path $FilePath -Name VersionInfo
    $signature = (Get-AuthenticodeSignature -FilePath $FilePath)
    
    # Output the extracted information
    return [PSCustomObject]@{
        DateCreation = $file.CreationTime
        DateModification = $file.LastWriteTime
        OriginalFileName = $fileVersionInfo.OriginalFilename
        CompanyName = $fileVersionInfo.CompanyName
        FileDescription = $fileDescription
        FileVersion = $fileVersionInfo.FileVersion
        Copyright = $fileVersionInfo.LegalCopyright
        ProductName = $fileVersionInfo.ProductName
        ProductVersion =  $fileVersionInfo.ProductVersion
        Sha1 = (Get-FileHash $FilePath -Algorithm SHA1).hash
        SignatureSubject =$signature.SignerCertificate.Subject
        SignatureCertificateThumbprint =  $signature.SignerCertificate.Thumbprint
        SignatureStatus = $signature.Status
        SignatureCertificateTrusted = ($trustedRoots | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint })
    }
    
}

function Add-FileInfo {

    param (
        [PSCustomObject]$Obj,
        [string]$FilePath
    )
    
    $FilePath = Get-WinFilePath($FilePath)

    if($null -eq $FilePath -or $FilePath -eq "" ){
        return $Obj
    }   
    $FileInfos_ = Get-FileInfo $FilePath
    if ($FileInfos_.PSObject.Properties['DateCreation']) {
        $FileInfos_ |  Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
            $Obj | Add-Member -MemberType NoteProperty -Name "FileInfo_$_" -Value  $FileInfos_.$_
        }
    }

    return $Obj

}


    