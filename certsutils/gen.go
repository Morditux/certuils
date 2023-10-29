package certsutils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"
)

type CACerts struct {
	Organization  string `json:"organization"`
	Country       string `json:"country"`
	Province      string `json:"province"`
	Locality      string `json:"locality"`
	StreetAddress string `json:"street_address"`
	PostalCode    string `json:"postal_code"`
	ValidFor      int    `json:"valid_for"`
	cert          []byte
	privateKey    []byte
}

type Certificate struct {
	Organization  string `json:"organization"`
	Country       string `json:"country"`
	Province      string `json:"province"`
	Locality      string `json:"locality"`
	StreetAddress string `json:"street_address"`
	PostalCode    string `json:"postal_code"`
	IPAddress     string `json:"ip_address"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	SubjectKeyID  string `json:"subject_key_id"`
}

func ReadCAConfig(filePath string) (*CACerts, error) {
	file, err := os.Open(filePath)
	if err != nil {
		slog.Error("error opening file", "path", filePath, "error", err)
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	caCerts := &CACerts{}
	err = decoder.Decode(caCerts)
	if err != nil {
		slog.Error("error decoding json", "error", err)
		return nil, err
	}
	return caCerts, nil
}

func ReadCertConfig(filePath string) (*Certificate, error) {
	file, err := os.Open(filePath)
	if err != nil {
		slog.Error("error opening file", "path", filePath, "error", err)
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	cert := &Certificate{}
	err = decoder.Decode(cert)
	if err != nil {
		slog.Error("error decoding json", "error", err)
		return nil, err
	}
	return cert, nil
}

func GenerateCA(caConfig *CACerts) (*x509.Certificate, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{caConfig.Organization},
			Country:       []string{caConfig.Country},
			Province:      []string{caConfig.Province},
			Locality:      []string{caConfig.Locality},
			StreetAddress: []string{caConfig.StreetAddress},
			PostalCode:    []string{caConfig.PostalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caConfig.ValidFor, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	cakey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		slog.Error("error generating key", "error", err)
		return nil, err
	}
	buffer := bytes.Buffer{}
	err = pem.Encode(&buffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cakey)})
	if err != nil {
		slog.Error("error encoding key", "error", err)
		return nil, err
	}
	caConfig.privateKey = buffer.Bytes()

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &cakey.PublicKey, cakey)
	if err != nil {
		slog.Error("error creating certificate", "error", err)
		return nil, err
	}
	buffer.Reset()
	err = pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err != nil {
		slog.Error("error encoding certificate", "error", err)
		return nil, err
	}
	caConfig.cert = buffer.Bytes()
	return ca, nil
}

func GenerateCert(caConfig *CACerts, certConfig *Certificate) (*x509.Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{certConfig.Organization},
			Country:       []string{certConfig.Country},
			Province:      []string{certConfig.Province},
			Locality:      []string{certConfig.Locality},
			StreetAddress: []string{certConfig.StreetAddress},
			PostalCode:    []string{certConfig.PostalCode},
		},
		IPAddresses: []net.IP{net.ParseIP(certConfig.IPAddress)},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		slog.Error("error generating key", "error", err)
		return nil, err
	}
	block, _ := pem.Decode(caConfig.cert)
	ca, err := x509.ParseCertificate(block.Bytes)

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caConfig.privateKey)
	if err != nil {
		slog.Error("error creating certificate", "error", err)
		return nil, err
	}
	certPem := bytes.Buffer{}
	err = pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		slog.Error("error encoding certificate", "error", err)
		return nil, err
	}
	certPrivKeyPem := bytes.Buffer{}
	err = pem.Encode(&certPrivKeyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey)})
	if err != nil {
		slog.Error("error encoding certificate", "error", err)
		return nil, err
	}
	return cert, nil

}
