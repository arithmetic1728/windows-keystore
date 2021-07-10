import subprocess
import getpass

pw = getpass.getpass()

proc = subprocess.Popen(
    [
        'powershell.exe',
        '-c',
        f'&{{ $pw = ConvertTo-SecureString -String "{pw}" -Force -AsPlainText;',
        'gci Cert:\\*\\My\\* |',
        '?{ $_.HasPrivateKey } |',
        '%{ Export-PfxCertificate -cert $_.PSPath',
        '-FilePath $env:USERPROFILE\\$($_.thumbprint).pfx -Password $pw}',
        '}'
    ],
    stdout = subprocess.PIPE,
    stderr = subprocess.PIPE,
    shell = True
)

out, err = proc.communicate()