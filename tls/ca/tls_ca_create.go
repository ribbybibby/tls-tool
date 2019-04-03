package ca

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"

	"github.com/ribbybibby/tls-tool/tls"
)

// CA is a certificate authority
type CA struct {
	Domain                string
	Constraint            bool
	AdditionalConstraints []string
	Subject               pkix.Name
	Days                  int
}

// Create creates the CA
func (ca *CA) Create() (err error) {
	certFileName := "ca.pem"
	pkFileName := "ca-key.pem"

	if !(tls.FileDoesNotExist(certFileName)) {
		return errors.New(certFileName + " already exists!")
	}
	if !(tls.FileDoesNotExist(pkFileName)) {
		return errors.New(pkFileName + " already exists!")
	}

	serialNumber, err := tls.GenerateSerialNumber()
	if err != nil {
		return err
	}

	signer, pk, err := tls.GeneratePrivateKey()
	if err != nil {
		return err
	}

	var constraints []string
	if ca.Constraint {
		constraints = append(ca.AdditionalConstraints, []string{ca.Domain, "localhost"}...)
	}

	if ca.Subject.CommonName == "" {
		ca.Subject.CommonName = ca.Domain + " " + serialNumber.String()
	}

	caCert, err := tls.GenerateCA(signer, serialNumber, ca.Days, constraints, ca.Subject)
	if err != nil {
		return fmt.Errorf("==>" + err.Error())
	}

	caFile, err := os.Create(certFileName)
	if err != nil {
		return err
	}
	caFile.WriteString(caCert)
	fmt.Println("==> Saved " + certFileName)
	pkFile, err := os.Create(pkFileName)
	if err != nil {
		return err
	}
	pkFile.WriteString(pk)
	fmt.Println("==> Saved " + pkFileName)

	return
}
