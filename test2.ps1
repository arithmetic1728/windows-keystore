$pw = ConvertTo-SecureString -String "{password}" -Force -AsPlainText
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
$store.Open("MaxAllowed")
$cert = $store.Certificates[0]
$out = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pw)
[System.Convert]::ToBase64String($out)
$store.Close()