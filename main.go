package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"

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
var webhookIDsToSecrets = map[string]server.Secret{
	"ce1c8481-89eb-4e22-ba7f-106f8a5ede21": server.Secret{
		Signing: "KYAkS5G1sFUX1NRUdFVFTG5J1ZsJu9iNSbn3tGJWs6Z9nY4ak5Lmui1G25XxJQNdPo0ptPQa03osacV59ApANA==",
		Bearer:  "abc123xyz",
	},
	"b4b3f3fe-66a6-454e-bd6e-b9417c6a136e": server.Secret{
		Signing: "UI/hIskDzPeBQz55rmlBno7LBBU+m+X2J4x/uh8F7ahm1z5m/mkcKWjo23rr/O095RKQKBqisnnvpvPwGq3AvA==",
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

	enricher := &server.Enricher{
		Secrets: webhookIDsToSecrets,
		Lookup: func(key string, csr *x509.CertificateRequest) (any, error) {
			return db[key], nil
		},
		LookupSSH: func(key string, cr *sshutil.CertificateRequest) (any, error) {
			return db[key], nil
		},
	}
	http.HandleFunc("/", enricher.Handle)

	err := s.ListenAndServeTLS(certFile, keyFile)
	log.Fatal(err)
}
