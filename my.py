import base64
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
import subprocess


def get_cert_and_key(password):
    proc = subprocess.Popen(
        [
            'powershell',
            '-c',
            '&{ $store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser); ' +
            '$store.Open("MaxAllowed");' +
            '$cert = $store.Certificates[0];' +
            f'$out = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, {password});' +
            '[System.Convert]::ToBase64String($out);' +
            '$store.Close();}'
        ],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE
    )

    out, err = proc.communicate()
    if err:
        raise ValueError(err)

    #pfx = "MIIFKAIBAzCCBOQGCSqGSIb3DQEHAaCCBNUEggTRMIIEzTCCAjYGCSqGSIb3DQEHAaCCAicEggIjMIICHzCCAhsGCyqGSIb3DQEMCgECoIIBNjCCATIwHAYKKoZIhvcNAQwBAzAOBAgmZ1JfPqf6SwICB9AEggEQZ6GlOr9qCDt+ri1BlS6X1X+WSID92Aep5C9q1ELgT6IIeHgHT/X2y/bBILyIS9kSf8ogIYt2EwDI2c5QNROz/12bhbcziw5JXkV3Je4Rh6n8mojhUT5zIReol9EiII/gU+cCLwX5swIsb0YSD0zdJ0OWbKaWuMQgGK34cq+d42a80TmMQ/4SHpW9b34TzqcKp9fD1SvWTtqEnlgU6HlzJbXCNoJddLYxorhTEMT45FvieDAHqtlzKHs6FZ+VnDzTjqO7zQw5Pt/DRaS9jjAiUgOtp9rMUwwz/G8sU/HET7OJj8m2XGOOmIzSfcLsQfnHb0//F2l6UKNBKMM/o+/LRpvfFaw7T1YmCgT1T4itY7YxgdEwEwYJKoZIhvcNAQkVMQYEBAEAAAAwWwYJKoZIhvcNAQkUMU4eTAB7ADYAMAA1ADQANQBCADEARQAtADUANgA1ADgALQA0ADIANQA3AC0AOQBDADUAQQAtAEQAMAAzAEUAMwA4ADAAOQA5ADEANABFAH0wXQYJKwYBBAGCNxEBMVAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcjCCAo8GCSqGSIb3DQEHBqCCAoAwggJ8AgEAMIICdQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIVXxvIQw3Jk4CAgfQgIICSP5eAb0qOjyLZ7AkDBKSqWp48v3gh0/rdMFj6LpTd3Iz6fW8pRM/p7WVAeDr+B9uqiCIKoZEdAmA4c1wQlj3VWO9wciYRnOre/LjBuzHjNeKRZEgGGlWo7gNLGjyh0xzEHUEEI0qCJYEJniW137sOEoYRkqmnqLi+AXXqwb++qipTHO87xaUwmYeAAdV64E6O6tLQAF6WvQ+tOhq5J0UrWTP+w1sLFiL6cnLK48Dps6mnzKX8ZaeHujmZL+zYn38HavA3rR09P0kW+r/GRIWQdGFXR9ySsm9Siv6dcoHQ0QqGNzKge6ZmuJfvNy44LeLd0/NfggLYxfd1vEmpA3tEY/4KoTKOLQJ55j4gr45aX4GFqYQ0+KjmgXR3TYkh1KeRJET/qHHvcDJPPceGPxB314VffMYeGmdvy+KnCB5XEFgqE2u960bq1ojMYf14VmOGYrpjAiGP/txNlzjsEjBU54iKRAt8GGqBovfcTWzcLBYYYxVe6E1gE02+ckaSfM2RnqwrAAyIF/+c4GPkyKnh3m+R+xnIwS7T//EfRqfLdDbj2XS2Tac/3W4DEIfWbirrXo/vKy39CenBYQfGNGF/hqkrTlaDr6QNDzqX4B3E8jyaUW0Cj0S4hjnHr7Ure8GTYdl4X2bM5re/ed42/Yiuhxg69TakBk+4JObe8bSERWXTk1zuAHOG/2mQFWGo6zRiZP3yuYvj6mnGTWr4lYiJ5Na0BPDlp9GTFnAiqH9zHfGTwM+wBksWii7RDYyPYh3vsS8ufgS2djLMDswHzAHBgUrDgMCGgQU18N5FCLXrdye7266BMGHR36T6BgEFO1PneLwnowD+2wYyN7ru5sd4WyWAgIH0A=="
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(base64.b64decode(out[:-2].decode()), password.encode())

    print(certificate.public_bytes(Encoding.PEM).decode('utf-8'))
    print(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode('utf-8'))

get_cert_and_key("12345")