 function Get-SortedProperties {

        param (
            [string[]]$ObjFields
        )

        $PEFields = @("FileInfo_CompanyName","FileInfo_Copyright","FileInfo_DateCreation","FileInfo_DateModification","FileInfo_FileDescription","FileInfo_FileVersion","FileInfo_OriginalFileName","FileInfo_ProductName","FileInfo_ProductVersion","FileInfo_Sha1","FileInfo_SignatureCertificateThumbprint","FileInfo_SignatureCertificateTrusted","FileInfo_SignatureStatus","FileInfo_SignatureSubject")

        $sortedProperties = $ObjFields + $PEFields

        return $sortedProperties
    }