# Set up

## Install openssl

Download openssl for windows from web:
https://slproweb.com/download/Win64OpenSSL-1_1_1L.msi
and install to folder `C:\OpenSSL-Win64`.

After installation, in the bottom left search box, type `env` and you should see
`Edit system environment variable`. In `Advanced`->`Environment Variables`, add
the following two environment variables to `System environment variables` section.
```
LIB=C:\OpenSSL-win64\lib;%LIB%
INCLUDE=C:\OpenSSL-win64\include;%INCLUDE%
```

## Install python

If the system already has Python installed, you can ignore this section; otherwise,
please install `pyenv` from https://github.com/pyenv-win/pyenv-win, then install
python 3, for example, 3.8.5.
```
pyenv versions
pyenv install 3.8.5
pyenv local 3.8.5
```

# Create a local build.

## Download google-auth

If you haven't, first download the `google-auth` repo and switch to `offload` branch.

```
git clone https://github.com/googleapis/google-auth-library-python.git
git checkout offload
```

Now go to the repo.
```
cd google-auth-library-python
```

## Create and activate python virtual environment.

```
python -m pip install –user virtualenv
python -m venv env
.\env\Scripts\activate
```

## Install the custom build

If you are using PowerShell, run
```
$env:GOOGLE_AUTH_BUILD_TLS_OFFLOAD=1
python -m pip install -e .
```

If you are using cmd terminal, run
```
set GOOGLE_AUTH_BUILD_TLS_OFFLOAD=1
python -m pip install -e .
```

You should see a `.pyd` file like `tls_offload_ext.cp37-win_amd64.pyd`.

# Run the sample

First navigate to `my` folder.

## generate cert/key

For testing purpose, we generate both RSA and EC keys. We will install RSA key to current
user's cert store, and install EC key to local machine's cert store.

### RSA cert/key
Run 
```
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -out rsa_cert.pem -keyout rsa_key.pem -addext "subjectAltName=DNS:localhost"
```
Then in the questions, remember to type "localhost" for the CN field. The rest doesn't matter, you
can type whatever you want.

```
openssl pkcs12 -inkey rsa_key.pem -in rsa_cert.pem -export -out rsa_mtls.pfx
```
Enter `12345` as the password, then double click the `rsa_mtls.pfx` file to install it
to the current local user.

### EC cert/key
Run
```
openssl ecparam -noout -name prime256v1 -genkey -out ec_key.pem -outform PEM
openssl req -new -x509 -key ec_key.pem -out ec_cert.pem -days 730 -addext "subjectAltName=DNS:localhost"
```
Then in the questions, remember to type "localhost" for the CN field. The rest doesn't matter, you
can type whatever you want.

```
openssl pkcs12 -inkey ec_key.pem -in ec_cert.pem -export -out ec_mtls.pfx
```
Enter `12345` as the password, then double click the `ec_mtls.pfx` file to install it
to the local machine.

## run the server 

Open a new terminal and navigate to the same folder, run

```
go run -v server.go 
```

By default it uses the RSA cert/key. To use the EC cert/key, run
```
go run -v server.go -certType=ec
```

## test the server

Open a new Git Bash terminal and change directory to `my` folder, run 

```
curl -k https://localhost:3000/foo 
```
You should see the server prints out 
```
http: TLS handshake error from 127.0.0.1:55064: tls: client didn't provide a certificate
```

If the server uses RSA, run 
```
curl -k https://localhost:3000/foo --cert rsa_cert.pem --key rsa_key.pem 
```
If the server uses EC cert/key, run
```
curl -k https://localhost:3000/foo --cert rsa_cert.pem --key rsa_key.pem
```
You should see `Called /foo` from server side and `Call succeeded!` from curl.

## run the sample

In the current terminal, run

```
$env:GOOGLE_API_USE_CLIENT_CERTIFICATE='true'
python tls_sample.py
```

You should see `Called /foo` from server side and `Call succeeded!` from curl.

# Windows signer

## Install `pywin32`

```
python -m pip install pywin32
```
