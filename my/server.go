package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

func printMessage(w http.ResponseWriter, r *http.Request) {
	log.Println(("Called /foo\n"))
	io.WriteString(w, "Call succeeded!\n")
}

func main() {
	http.HandleFunc("/foo", printMessage)

	var certType string
	var cert string
	var key string
	flag.StringVar(&certType, "certType", "rsa", "cert/key type to use, rsa or ec, default is rsa")
	flag.Parse()
	if certType == "ec" {
		log.Println(("using EC cert/key\n"))
		cert = "ec_cert.pem"
		key = "ec_key.pem"
	} else {
		log.Println(("using RSA cert/key\n"))
		cert = "rsa_cert.pem"
		key = "rsa_key.pem"
	}

	// CA cert
	caCert, err := ioutil.ReadFile(cert)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config with CA and require client cert verification.
	config := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
	}
	config.BuildNameToCertificate()

	server := &http.Server{
		Addr:      ":3000",
		TLSConfig: config,
	}
	// Use server side cert and key
	log.Fatal(server.ListenAndServeTLS(cert, key))
}
