import wincertstore
import base64 
import ssl
import os 
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

# Certificate Name & Thumbprint to look for
certName = 'localhost'
thumbPrint = '079d41cbcbe3b9806899638dbd97badd1234567890'

def hex_string_readable(bytes):
    return ["{:02X}".format(x) for x in bytes]

with wincertstore.CertSystemStore("PERSONAL") as store:
    #for cert in store.itercerts(usage=wincertstore.SERVER_AUTH):
    for cert in store.itercerts(usage=None):
        if cert.get_name() == certName:
            pem = cert.get_pem()
            encodedDer = ''.join(pem.split("\n")[1:-2])

            cert_bytes = base64.b64decode(encodedDer)
            cert_pem = ssl.DER_cert_to_PEM_cert(cert_bytes)
            cert_details = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())

            fingerprint = hex_string_readable(cert_details.fingerprint(hashes.SHA1()))
            fingerprint_string = ''.join(fingerprint)
                
            if fingerprint_string.lower() == thumbPrint:
                print(cert.get_name())
                print("     Issuer: ", cert_details.issuer.rfc4514_string())
                print("     Thumbprint: ", fingerprint_string.lower())
                print("     Subject: ", cert_details.subject.rfc4514_string())
                print("     Serial Number: ", hex(cert_details.serial_number).replace("0x",""))
                print("     Issued (UTC): ", cert_details.not_valid_before)
                print("     Expiry (UTC): ", cert_details.not_valid_after)

                san = cert_details.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                names = san.get_values_for_type(x509.DNSName)
                print("     SAN(s): ", names)

                cert_usages = cert_details.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value._usages
                print("     Usage(s): ", cert_usages)