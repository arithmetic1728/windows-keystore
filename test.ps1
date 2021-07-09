$store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
$store.Open("MaxAllowed")
$key = $store.Certificates[1].PrivateKey
$BytesPkcs8 = $key.ExportPkcs8PrivateKey()
[System.Convert]::ToBase64String($BytesPkcs8)


$data = $store.Certificates[0].RawData
$key.ToString()
$pair = $key.ExportCspBlob($true)
#$cert = $store.Certificates | ?{$_.subject -match "^CN=asdasd"}
#$cert.PrivateKey.ToXmlString($false)
$store.Close()