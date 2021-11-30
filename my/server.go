package main

import (
	"crypto/tls"
	"crypto/x509"
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

	// CA cert
	caCert, err := ioutil.ReadFile("ca_cert.pem")
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
	log.Fatal(server.ListenAndServeTLS("rsa_cert.pem", "rsa_key.pem"))
}
