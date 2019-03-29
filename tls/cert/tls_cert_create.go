package cert

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ribbybibby/tls-tool/tls"
)

type Cert struct {
	CA           string
	Domain       string
	Days         int
	Key          string
	Client       bool
	DNSNames     []string
	signer       crypto.Signer
	serialNumber *big.Int
	public       string
	private      string
	dnsnames     []string
	ipaddresses  []net.IP
	name         string
	cert         []byte
	key          []byte
	extKeyUsage  []x509.ExtKeyUsage
	prefix       string
}

// Create the certificate
func (c *Cert) Create() (err error) {
	if c.CA == "" {
		return fmt.Errorf("Please provide the ca")
	}
	if c.Key == "" {
		return fmt.Errorf("Please provide the key")
	}

	for _, d := range c.DNSNames {
		if len(d) > 0 {
			c.dnsnames = append(c.dnsnames, strings.TrimSpace(d))
		}
	}

	c.dnsnames = append(c.dnsnames, []string{c.name, "localhost"}...)
	c.ipaddresses = []net.IP{net.ParseIP("127.0.0.1")}
	c.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	c.prefix = fmt.Sprintf("cert-%s", c.Domain)

	var pkFileName, certFileName string
	max := 10000
	for i := 0; i <= max; i++ {
		tmpCert := fmt.Sprintf("%s-%d.pem", c.prefix, i)
		tmpPk := fmt.Sprintf("%s-%d-key.pem", c.prefix, i)
		if tls.FileDoesNotExist(tmpCert) && tls.FileDoesNotExist(tmpPk) {
			certFileName = tmpCert
			pkFileName = tmpPk
			break
		}
		if i == max {
			return fmt.Errorf("Could not find a filename that doesn't already exist")
		}
	}

	c.cert, err = ioutil.ReadFile(c.CA)
	if err != nil {
		return fmt.Errorf("Error reading CA: %s", err)
	}
	c.key, err = ioutil.ReadFile(c.Key)
	if err != nil {
		return fmt.Errorf("Error reading CA key: %s", err)
	}

	fmt.Println("==> Using " + c.CA + " and " + c.Key)

	c.signer, err = tls.ParseSigner(string(c.key))
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	c.serialNumber, err = tls.GenerateSerialNumber()
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	c.generate()

	if err = tls.Verify(string(c.cert), c.public, c.name); err != nil {
		return fmt.Errorf("==> " + err.Error())
	}

	certFile, err := os.Create(certFileName)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	certFile.WriteString(c.public)
	fmt.Println("==> Saved " + certFileName)

	pkFile, err := os.Create(pkFileName)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	pkFile.WriteString(c.private)
	fmt.Println("==> Saved " + pkFileName)

	return nil
}

// generate
func (c *Cert) generate() (err error) {
	parent, err := tls.ParseCert(string(c.cert))
	if err != nil {
		return err
	}

	signee, pk, err := tls.GeneratePrivateKey()
	if err != nil {
		return err
	}

	id, err := tls.KeyID(signee.Public())
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber:          c.serialNumber,
		Subject:               pkix.Name{CommonName: c.Domain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           c.extKeyUsage,
		IsCA:                  false,
		NotAfter:              time.Now().AddDate(0, 0, c.Days),
		NotBefore:             time.Now(),
		SubjectKeyId:          id,
		DNSNames:              c.dnsnames,
		IPAddresses:           c.ipaddresses,
	}

	bs, err := x509.CreateCertificate(rand.Reader, &template, parent, signee.Public(), c.signer)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs})
	if err != nil {
		return fmt.Errorf("error encoding private key: %s", err)
	}

	c.public = buf.String()
	c.private = pk

	return nil
}
