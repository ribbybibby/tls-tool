package main

import (
	"crypto/x509/pkix"
	"log"
	"os"

	"github.com/ribbybibby/tls-tool/tls/ca"
	"github.com/ribbybibby/tls-tool/tls/cert"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("tls-tool", "A tool for creating TLS certificates quickly")

	caCmd                             = app.Command("ca", "CA")
	caCreate                          = caCmd.Command("create", "Create a new certificate authority")
	caCreateDomain                    = caCreate.Flag("domain", "Domain").Default("ribbybibby.me").String()
	caCreateDays                      = caCreate.Flag("days", "Provide number of days the CA is valid for from now on").Default("1825").Int()
	caCreateNameConstraint            = caCreate.Flag("name-constraint", "Add name constraints for the CA?").Default("false").Bool()
	caCreateAdditionalNameConstraints = caCreate.Flag("additional-name-constraint", "Add additional name constraints for the CA.").Strings()
	caCreateCountry                   = caCreate.Flag("country", "Country").Default("GB").String()
	caCreatePostalCode                = caCreate.Flag("postal-code", "Postal code").Default("SW18XXX").String()
	caCreateProvince                  = caCreate.Flag("province", "Province").Default("England").String()
	caCreateLocality                  = caCreate.Flag("locality", "Locality").Default("London").String()
	caCreateStreetAddress             = caCreate.Flag("street-address", "Street Address").Default("123 Fake St").String()
	caCreateOrganization              = caCreate.Flag("organization", "Organization").Default("ribbybibby").String()

	certCmd                      = app.Command("cert", "Certificates")
	certCreate                   = certCmd.Command("create", "Create a new certificate")
	certCreateCAFile             = certCreate.Flag("ca", "Provide path to the ca").Default("ca.pem").ExistingFile()
	certCreateKeyFile            = certCreate.Flag("key", "Provide path to the key").Default("ca-key.pem").ExistingFile()
	certCreateDays               = certCreate.Flag("days", "Provide number of days the certificate is valid for from now on").Default("365").Int()
	certCreateDomain             = certCreate.Flag("domain", "Domain").Default("ribbybibby.me").String()
	certCreateAdditionalDNSnames = certCreate.Flag("additional-dnsname", "Provide additional dnsnames for Subject Alternative Names.").Strings()
	certCreateInsecure           = certCreate.Flag("insecure", "Optionally allow the creation of purposely expired or otherwise invalid certs").Default("false").Bool()
)

func main() {

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case caCreate.FullCommand():
		c := &ca.CA{
			AdditionalConstraints: *caCreateAdditionalNameConstraints,
			Constraint:            *caCreateNameConstraint,
			Days:                  *caCreateDays,
			Domain:                *caCreateDomain,
			Subject: pkix.Name{
				Country:       []string{*caCreateCountry},
				PostalCode:    []string{*caCreatePostalCode},
				Province:      []string{*caCreateProvince},
				Locality:      []string{*caCreateLocality},
				StreetAddress: []string{*caCreateStreetAddress},
				Organization:  []string{*caCreateOrganization},
			},
		}
		err := c.Create()
		if err != nil {
			log.Fatalf(err.Error())
		}
	case certCreate.FullCommand():

		c := &cert.Cert{
			CAFile:   *certCreateCAFile,
			Days:     *certCreateDays,
			DNSNames: *certCreateAdditionalDNSnames,
			Domain:   *certCreateDomain,
			Insecure: *certCreateInsecure,
			KeyFile:  *certCreateKeyFile,
		}
		err := c.Create()
		if err != nil {
			log.Fatalf(err.Error())
		}
	}
}
