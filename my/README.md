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

Run 
```
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -out cert.pem -keyout key.pem -addext "subjectAltName=DNS:localhost"
```
Then in the questions, remember to type "localhost" for the CN field. The rest doesn't matter, you
can type whatever you want.

## run the server 

Open a new terminal and navigate to the same folder, run

```
go run -v server.go 
```

## test the server

In the current terminal, run 

```
curl -k https://localhost:3000/foo 
```
You should see the server prints out 
```
http: TLS handshake error from 127.0.0.1:55064: tls: client didn't provide a certificate
```

Now run 
```
curl -k https://localhost:3000/foo --cert cert.pem --key key.pem 
```
You should see `Called /foo` from server side and `Call succeeded!` from curl.

## run the sample

In the current terminal, run

```
$env:GOOGLE_API_USE_CLIENT_CERTIFICATE='true'
python tls_sample.py
```

You should see `Called /foo` from server side and `Call succeeded!` from curl.