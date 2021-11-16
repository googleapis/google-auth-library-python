## How to generate cert/key 

Run 
```
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -out cert.pem -keyout key.pem -addext "subjectAltName=DNS:localhost"
```
Then in the questions, remember to type "localhost" for the CN field.

## How to run the server 

```
go run -v server.go 
```

To test the server indeed requires mTLS, run 

```
curl -k https://localhost:3000/foo 
```
You should see the server prints out 
```
http: TLS handshake error from 127.0.0.1:55064: tls: client didn't provide a certificate
```

Then run 
```
curl -k https://localhost:3000/foo --cert cert.pem --key key.pem 
```
You should see `Called /foo` from server side and `Call succeeded!` from curl.

## How to run the client 

```
$env:GOOGLE_API_USE_CLIENT_CERTIFICATE='true'
python tls_sample.py
```