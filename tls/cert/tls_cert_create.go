package cert

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"

	"github.com/ribbybibby/tls-tool/tls"
)

// Cert is a certificate
type Cert struct {
	CAFile   string
	Domain   string
	Days     int
	KeyFile  string
	DNSNames []string
	Insecure bool
}

// Create the certificate
func (c *Cert) Create() (err error) {
	var (
		signer       crypto.Signer
		serialNumber *big.Int
		dnsnames     []string
		ipaddresses  []net.IP
		extKeyUsage  []x509.ExtKeyUsage
		prefix       string
	)

	if c.CAFile == "" {
		return fmt.Errorf("Please provide the ca")
	}
	if c.KeyFile == "" {
		return fmt.Errorf("Please provide the key")
	}

	for _, d := range c.DNSNames {
		if len(d) > 0 {
			dnsnames = append(dnsnames, strings.TrimSpace(d))
		}
	}

	dnsnames = append(dnsnames, []string{c.Domain, "localhost"}...)
	ipaddresses = []net.IP{net.ParseIP("127.0.0.1")}
	extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	prefix = fmt.Sprintf("cert-%s", c.Domain)

	var pkFileName, certFileName string
	max := 10000
	for i := 0; i <= max; i++ {
		tmpCert := fmt.Sprintf("%s-%d.pem", prefix, i)
		tmpPk := fmt.Sprintf("%s-%d-key.pem", prefix, i)
		if tls.FileDoesNotExist(tmpCert) && tls.FileDoesNotExist(tmpPk) {
			certFileName = tmpCert
			pkFileName = tmpPk
			break
		}
		if i == max {
			return fmt.Errorf("Could not find a filename that doesn't already exist")
		}
	}

	var caCert, caKey []byte
	caCert, err = ioutil.ReadFile(c.CAFile)
	if err != nil {
		return fmt.Errorf("Error reading CA: %s", err)
	}
	caKey, err = ioutil.ReadFile(c.KeyFile)
	if err != nil {
		return fmt.Errorf("Error reading CA key: %s", err)
	}

	fmt.Println("==> Using " + c.CAFile + " and " + c.KeyFile)

	signer, err = tls.ParseSigner(string(caKey))
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	serialNumber, err = tls.GenerateSerialNumber()
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	public, private, err := tls.GenerateCert(signer, string(caCert), serialNumber, c.Domain, c.Days, dnsnames, ipaddresses, extKeyUsage)
	if err != nil {
		return fmt.Errorf("==>" + err.Error())
	}

	if err = tls.Verify(string(caCert), public, c.Domain); err != nil && !c.Insecure {
		return fmt.Errorf("==> " + err.Error())
	}

	certFile, err := os.Create(certFileName)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	certFile.WriteString(public)
	fmt.Println("==> Saved " + certFileName)

	pkFile, err := os.Create(pkFileName)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	pkFile.WriteString(private)
	fmt.Println("==> Saved " + pkFileName)

	return nil
}
