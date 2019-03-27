package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ribbybibby/tls-tool/tls"
)

type CA struct {
	CommonName            string
	Domain                string
	Constraint            bool
	AdditionalConstraints []string
	Country               string
	PostalCode            string
	Province              string
	Locality              string
	StreetAddress         string
	Organization          string
	Days                  int
	signer                crypto.Signer
	serialNumber          *big.Int
	constraints           []string
	certificate           string
}

// Create creates the certificate
func (ca *CA) Create() (err error) {
	certFileName := "ca.pem"
	pkFileName := "ca-key.pem"

	if !(tls.FileDoesNotExist(certFileName)) {
		return errors.New(certFileName + " already exists!")
	}
	if !(tls.FileDoesNotExist(pkFileName)) {
		return errors.New(pkFileName + " already exists!")
	}

	ca.serialNumber, err = tls.GenerateSerialNumber()
	if err != nil {
		return err
	}

	var pk string
	ca.signer, pk, err = tls.GeneratePrivateKey()
	if err != nil {
		return err
	}

	if ca.Constraint {
		ca.constraints = append(ca.AdditionalConstraints, []string{ca.Domain, "localhost"}...)
	}

	err = ca.generate()
	if err != nil {
		return err
	}

	caFile, err := os.Create(certFileName)
	if err != nil {
		return err
	}
	caFile.WriteString(ca.certificate)
	fmt.Println("==> Saved " + certFileName)
	pkFile, err := os.Create(pkFileName)
	if err != nil {
		return err
	}
	pkFile.WriteString(pk)
	fmt.Println("==> Saved " + pkFileName)

	return
}

// generate the CA
func (ca *CA) generate() error {
	id, err := tls.KeyID(ca.signer.Public())
	if err != nil {
		return err
	}

	// Create the CA cert
	template := x509.Certificate{
		SerialNumber: ca.serialNumber,
		Subject: pkix.Name{
			Country:       []string{ca.Country},
			PostalCode:    []string{ca.PostalCode},
			Province:      []string{ca.Province},
			Locality:      []string{ca.Locality},
			StreetAddress: []string{ca.StreetAddress},
			Organization:  []string{ca.Organization},
			CommonName:    ca.CommonName,
		},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		NotAfter:              time.Now().AddDate(0, 0, ca.Days),
		NotBefore:             time.Now(),
		AuthorityKeyId:        id,
		SubjectKeyId:          id,
	}

	if len(ca.constraints) > 0 {
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = ca.constraints
	}
	bs, err := x509.CreateCertificate(
		rand.Reader, &template, &template, ca.signer.Public(), ca.signer)
	if err != nil {
		return fmt.Errorf("error generating CA certificate: %s", err)
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs})
	if err != nil {
		return fmt.Errorf("error encoding private key: %s", err)
	}

	ca.certificate = buf.String()

	return nil
}
