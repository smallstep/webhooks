package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"

	"go.step.sm/crypto/sshutil"
)

type Secret struct {
	Signing  string
	Bearer   string
	Username string
	Password string
}

type Enricher struct {
	Lookup  func(key string, csr *x509.CertificateRequest) (any, error)
	Secrets map[string]Secret
}

type webhookRequestBody struct {
	Timestamp string                     `json:"timestamp"`
	X509_CSR  []byte                     `json:"csr,omitempty"`
	SSH_CR    sshutil.CertificateRequest `json:"ssh_cr,omitempty"`
}

type response struct {
	Data any `json:"data"`
}

func (e *Enricher) Handle(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Smallstep-Webhook-ID")
	if id == "" {
		http.Error(w, "Missing X-Smallstep-Webhook-ID header", http.StatusBadRequest)
		return
	}
	secret, ok := e.Secrets[id]
	if !ok {
		log.Printf("Missing signing secret for webhook %s", id)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if secret.Bearer != "" {
		wantAuth := fmt.Sprintf("Bearer %s", secret.Bearer)
		if r.Header.Get("Authorization") != wantAuth {
			log.Printf("Incorrect bearer authorization header for %s", id)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	} else if secret.Username != "" || secret.Password != "" {
		user, pass, _ := r.BasicAuth()
		if user != secret.Username || pass != secret.Password {
			log.Printf("Incorrect basic authorization header for %s", id)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	sig, err := hex.DecodeString(r.Header.Get("X-Smallstep-Signature"))
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Invalid X-Smallstep-Signature header", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	sigSecret, err := base64.StdEncoding.DecodeString(secret.Signing)
	if err != nil {
		log.Printf("Failed to decode signing secret for %s: %v", id, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	mac := hmac.New(sha256.New, sigSecret).Sum(body)
	if ok := hmac.Equal(sig, mac); !ok {
		log.Printf("Failed to verify request signature for %s", id)
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	wrb := &webhookRequestBody{}
	err = json.Unmarshal(body, wrb)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	csr, err := x509.ParseCertificateRequest(wrb.X509_CSR)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_, key := path.Split(r.URL.Path)
	data, err := e.Lookup(key, csr)
	if err != nil {
		log.Printf("Failed to lookup data for %s: %v", key, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(response{data})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}

	fmt.Printf("Received enriching webhook request for %q. Sent data: %+v\n", key, data)
}
