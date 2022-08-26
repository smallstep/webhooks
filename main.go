package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"

	casapi "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/webhooks/pkg/server"
	"go.step.sm/crypto/sshutil"
)

var certFile = "webhook.crt"
var keyFile = "webhook.key"
var clientCAs = []string{
	"/home/areed/.step/authorities/ssh/certs/root_ca.crt",
	"/home/areed/.step/authorities/x509/certs/root_ca.crt",
}
var address = ":9443"

type data struct {
	Role string `json:"role"`
}

var db = map[string]data{
	"andrew@smallstep.com": {Role: "eng"},
}

// For demonstration only. Do not hardcode or commit actual webhook secrets.
var webhookIDsToSecrets = map[string]server.Secret{}

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
		Lookup: func(key string, csr *x509.CertificateRequest) (any, error) {
			return db[key], nil
		},
		LookupSSH: func(key string, cr *sshutil.CertificateRequest) (any, error) {
			return db[key], nil
		},
		Allow: func(cert *casapi.CreateCertificateRequest) (bool, error) {
			cn := cert.Template.Subject.CommonName
			if cn == "" {
				cn = cert.CSR.Subject.CommonName
			}
			_, ok := db[cn]
			return ok, nil
		},
	}
	http.HandleFunc("/", h.Enrich)
	http.HandleFunc("/auth", h.Authorize)

	err := s.ListenAndServeTLS(certFile, keyFile)
	log.Fatal(err)
}
