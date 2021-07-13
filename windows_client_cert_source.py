import base64
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
import subprocess


def has_cert_and_key(location, serial_number, password):
    proc = subprocess.Popen(
        [
            'powershell',
            '-c',
            f'&{{ $cert = Get-ChildItem {location} | where {{$_.SerialNumber -eq "{serial_number}" -and $_.HasPrivateKey}}; !($cert -eq $null) }}'
        ],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE
    )

    out, err = proc.communicate()
    if err:
        raise ValueError(err)
    return out.rstrip() == b"True"


def get_windows_client_cert_source(location, serial_number, password):
    proc = subprocess.Popen(
        [
            'powershell',
            '-c',
            f'&{{ $cert = Get-ChildItem {location} | where {{$_.SerialNumber -eq "{serial_number}" -and $_.HasPrivateKey}};' +
            f'$out = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, {password});' +
            '[System.Convert]::ToBase64String($out);}'
        ],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE
    )

    out, err = proc.communicate()
    if err:
        raise ValueError(err)

    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(base64.b64decode(out.rstrip().decode()), password.encode())

    def client_cert_source():
        return certificate.public_bytes(Encoding.PEM), private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    return client_cert_source


client_cert_source = get_windows_client_cert_source("Cert:\CurrentUser\my", "670DFEA2714C5712E49B96B390D2D4E81B276AB1", "12345")
print(client_cert_source())