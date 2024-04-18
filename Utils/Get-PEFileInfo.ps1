function Get-PeFileInfo {

    Param(
        [string] $FilePath
    )

    if(-not(Test-Path $FilePath -PathType Leaf)){
        return ""
    }

    $file = Get-Item $FilePath

    $fileVersionInfo = Get-ItemPropertyValue -Path $filePath -Name VersionInfo
    $signature = (Get-AuthenticodeSignature -FilePath $filePath)
    
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