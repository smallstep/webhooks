package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"

	"github.com/smallstep/certificates/webhook"
	"golang.org/x/crypto/ssh"
)

type Secret struct {
	Signing  string
	Bearer   string
	Username string
	Password string
}

type Handler struct {
	LookupX509 func(key string, cr *webhook.X509CertificateRequest) (any, bool, error)
	LookupSSH  func(key string, cr *webhook.SSHCertificateRequest) (any, bool, error)
	AllowX509  func(certificate *webhook.X509Certificate) (bool, error)
	AllowSSH   func(certificate *webhook.SSHCertificate) (bool, error)
	Secrets    map[string]Secret
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (*webhook.RequestBody, bool) {
	id := r.Header.Get("X-Smallstep-Webhook-ID")
	if id == "" {
		http.Error(w, "Missing X-Smallstep-Webhook-ID header", http.StatusBadRequest)
		return nil, false
	}
	secret, ok := h.Secrets[id]
	if !ok {
		log.Printf("Missing signing secret for webhook %s", id)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}
	if secret.Bearer != "" {
		wantAuth := fmt.Sprintf("Bearer %s", secret.Bearer)
		if r.Header.Get("Authorization") != wantAuth {
			log.Printf("Incorrect bearer authorization header for %s", id)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
	} else if secret.Username != "" || secret.Password != "" {
		user, pass, _ := r.BasicAuth()
		if user != secret.Username || pass != secret.Password {
			log.Printf("Incorrect basic authorization header for %s", id)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
	}

	sig, err := hex.DecodeString(r.Header.Get("X-Smallstep-Signature"))
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Invalid X-Smallstep-Signature header", http.StatusBadRequest)
		return nil, false
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return nil, false
	}

	sigSecret, err := base64.StdEncoding.DecodeString(secret.Signing)
	if err != nil {
		log.Printf("Failed to decode signing secret for %s: %v", id, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}

	hm := hmac.New(sha256.New, sigSecret)
	hm.Write(body)
	mac := hm.Sum(nil)
	if ok := hmac.Equal(sig, mac); !ok {
		log.Printf("Failed to verify request signature for %s", id)
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return nil, false
	}

	wrb := &webhook.RequestBody{}
	err = json.Unmarshal(body, wrb)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}

	return wrb, true
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	wrb, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	allow, err := h.AllowX509(wrb.X509Certificate)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}

	err = json.NewEncoder(w).Encode(webhook.ResponseBody{Allow: allow})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}

	fmt.Printf("Received authorizing webhook request. Sent allow: %t\n", allow)
}

func (h *Handler) AuthorizeSSH(w http.ResponseWriter, r *http.Request) {
	wrb, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if len(wrb.SSHCertificate.PublicKey) > 0 {
		pubKey, err := ssh.ParsePublicKey(wrb.SSHCertificate.PublicKey)
		if err != nil {
			log.Printf("Failed to parse ssh public key: %v", err)
			http.Error(w, "Internal Server Error", 500)
			return
		}
		wrb.SSHCertificate.Certificate.Key = pubKey
	}
	if len(wrb.SSHCertificate.SignatureKey) > 0 {
		sigKey, err := ssh.ParsePublicKey(wrb.SSHCertificate.SignatureKey)
		if err != nil {
			log.Printf("Failed to parse ssh signature key: %v", err)
			http.Error(w, "Internal Server Error", 500)
			return
		}
		wrb.SSHCertificate.Certificate.SignatureKey = sigKey
	}

	allow, err := h.AllowSSH(wrb.SSHCertificate)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}

	err = json.NewEncoder(w).Encode(webhook.ResponseBody{Allow: allow})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}

	fmt.Printf("Received authorizing webhook request. Sent allow: %t\n", allow)
}

func (h *Handler) EnrichX509(w http.ResponseWriter, r *http.Request) {
	wrb, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	_, key := path.Split(r.URL.Path)

	println(r.URL.Path)
	data, ok, err := h.LookupX509(key, wrb.X509CertificateRequest)
	if err != nil {
		log.Printf("Failed to lookup data for %s: %v", key, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(webhook.ResponseBody{Data: data, Allow: ok})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}

	fmt.Printf("Received x509 enriching webhook request for %q. Sent data: %+v\n", key, data)
}

func (h *Handler) EnrichSSH(w http.ResponseWriter, r *http.Request) {
	wrb, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	_, key := path.Split(r.URL.Path)

	cr := wrb.SSHCertificateRequest
	_, err := ssh.ParsePublicKey(cr.PublicKey)
	if err != nil {
		log.Printf("Failed to parse ssh public key: %v", err)
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}

	data, ok, err := h.LookupSSH(key, cr)
	if err != nil {
		log.Printf("Failed to lookup data for %s: %v", key, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(webhook.ResponseBody{Data: data, Allow: ok})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}

	fmt.Printf("Received SSH enriching webhook request for %q. Sent data: %+v\n", key, data)
}
