package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"fmt"

	"github.com/smallstep/certificates/webhook"
	"github.com/smallstep/webhooks/pkg/server"
)

var certFile = "webhook.crt"
var keyFile = "webhook.key"
var clientCAs = []string{"root_ca.crt"}
var address = ":4443"

type data struct {
	Role string `json:"role"`
}

var db = map[string]data{
	"carl@smallstep.com": {Role: "eng"},
}

// For demonstration only. Do not hardcode or commit actual webhook secrets.
var webhookIDsToSecrets = map[string]server.Secret{
	"8509cf3b-c657-4f69-bf78-636be7cd91fc": server.Secret{
		Signing: "G0syl5ee8W1zFTMjhJXpYFuK0QVmZfG++ImzslyVyyciv58ftmX7NMXKJeWCA/A3shjX+xrsoGO0f1+nfu/FSw==",
	},
}

func main() {
	caCertPool := x509.NewCertPool()

	for _, clientCA := range clientCAs {
		caCert, err := os.ReadFile(clientCA)
		if err != nil {
			log.Panic(err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	s := http.Server{
		Addr: address,
		TLSConfig: &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
	}

	h := &server.Handler{
		Secrets: webhookIDsToSecrets,
		LookupX509: func(key string, csr *webhook.X509CertificateRequest) (any, bool, error) {
			item, ok := db[key]
			return item, ok, nil
		},
		LookupSSH: func(key string, cr *webhook.SSHCertificateRequest) (any, bool, error) {
			item, ok := db[key]
			return item, ok, nil
		},
		AllowX509: func(cert *webhook.X509Certificate) (bool, error) {
			cn := cert.Subject.CommonName
			_, ok := db[cn]
			return ok, nil
		},
		AllowSSH: func(cert *webhook.SSHCertificate) (bool, error) {
			return true, nil
		},
	}
	http.HandleFunc("/", h.EnrichX509)
	http.HandleFunc("/ssh/", h.EnrichSSH)
	http.HandleFunc("/auth/", h.Authorize)
	http.HandleFunc("/auth-ssh/", h.AuthorizeSSH)

	fmt.Printf("Listening on %s\n", s.Addr)
	err := s.ListenAndServeTLS(certFile, keyFile)
	log.Fatal(err)
}
