package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"

	"github.com/smallstep/certificates/webhook"
	"github.com/smallstep/webhooks/pkg/server"
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
var webhookIDsToSecrets = map[string]server.Secret{
	"db963269-ae37-46b8-aa69-7a7a9c346f8a": server.Secret{
		Signing: "qL4wn7umqfecBW52Loo+NJ0V2ViC8TlXxt3LUdoIgsTdTSakCGOjLsZyiHo5io0bkcMNZCIPFXYv3xH2SsAgmg==",
	},
	"ab62d6a3-80fa-480a-b508-5a7f3de11d94": server.Secret{
		Signing: "0qNQMfCY3mWyXAoLE6P8pq+AVGEkDjwKP/sF30LOHHjDs5vfWYk97ulXCgJZcD61piFISd4IJhcxu3ChNw9l6Q==",
	},
	"7d46b110-7645-430e-a32e-12fa611bda7d": server.Secret{
		Signing: "e1b7PFqOXtBHVL+GawfD2H3KpsgRjxeFS6UYqzYiWeZzcHP7lPh4dXAfidNqpguqFA9F5mX2Us7iDuYOAxLUcQ==",
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
		LookupX509: func(key string, csr *webhook.X509CertificateRequest) (any, error) {
			return db[key], nil
		},
		LookupSSH: func(key string, cr *webhook.SSHCertificateRequest) (any, error) {
			return db[key], nil
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

	err := s.ListenAndServeTLS(certFile, keyFile)
	log.Fatal(err)
}
