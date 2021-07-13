1. First double click the certificate.pfx, and install it to current user's personal store, and use "12345" as the password.

2. Install the python dependency.
```sh
$ python -m pip install -r requirements.txt
```

3. Run the python code to obtain the certificate and private key from the keystore.

```sh
$python windows_client_cert_source.py
```
