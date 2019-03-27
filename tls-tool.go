package main

import (
	"log"
	"os"

	"github.com/ribbybibby/tls-tool/tls/ca"
	"github.com/ribbybibby/tls-tool/tls/cert"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("tls-tool", "A tool for creating TLS certificates quickly")

	caCmd                             = app.Command("ca", "CA")
	caCreate                          = caCmd.Command("create", "Create a new CA")
	caCreateCommonName                = caCreate.Flag("common-name", "Common name").Default("ribbybibby.me").String()
	caCreateDomain                    = caCreate.Flag("domain", "Domain").Default("ribbybibby.me").String()
	caCreateDays                      = caCreate.Flag("days", "Provide number of days the CA is valid for from now on").Default("1825").Int()
	caCreateNameConstraint            = caCreate.Flag("name-constraint", "Add name constraints for the CA.").Default("false").Bool()
	caCreateAdditionalNameConstraints = caCreate.Flag("additional-name-constraint", "Add name constraints for the CA.").Strings()
	caCreateCountry                   = caCreate.Flag("country", "Country").Default("GB").String()
	caCreatePostalCode                = caCreate.Flag("postal-code", "Postal code").Default("SW18XXX").String()
	caCreateProvince                  = caCreate.Flag("province", "Province").Default("England").String()
	caCreateLocality                  = caCreate.Flag("locality", "Locality").Default("London").String()
	caCreateStreetAddress             = caCreate.Flag("street-address", "Street Address").Default("123 Fake St").String()
	caCreateOrganization              = caCreate.Flag("organization", "Organization").Default("ribbybibby").String()

	certCmd                      = app.Command("cert", "Certificates")
	certCreate                   = certCmd.Command("create", "Create a new certificate")
	certCreateType               = certCreate.Arg("type", "Server or client certificate").Required().Enum([]string{"server", "client"}...)
	certCreateCAFile             = certCreate.Flag("ca", "Provide path to the ca").Default("ca.pem").ExistingFile()
	certCreateKeyFile            = certCreate.Flag("key", "Provide path to the key").Default("ca-key.pem").ExistingFile()
	certCreateDays               = certCreate.Flag("days", "Provide number of days the certificate is valid for from now on").Default("365").Int()
	certCreateDomain             = certCreate.Flag("domain", "Domain").Default("ribbybibby.me").String()
	certCreateAdditionalDNSnames = certCreate.Flag("additional-dnsname", "Provide an additional dnsname for Subject Alternative Names.").Strings()
)

func main() {

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case caCreate.FullCommand():
		c := &ca.CA{
			Domain:                *caCreateDomain,
			Days:                  *caCreateDays,
			CommonName:            *caCreateCommonName,
			Constraint:            *caCreateNameConstraint,
			AdditionalConstraints: *caCreateAdditionalNameConstraints,
			Country:               *caCreateCountry,
			PostalCode:            *caCreatePostalCode,
			Province:              *caCreateProvince,
			Locality:              *caCreateLocality,
			StreetAddress:         *caCreateStreetAddress,
			Organization:          *caCreateOrganization,
		}
		err := c.Create()
		if err != nil {
			log.Fatalf(err.Error())
		}
	case certCreate.FullCommand():
		var server bool
		var client bool

		switch *certCreateType {
		case "server":
			server = true
			client = false
		case "client":
			server = false
			client = true
		default:
			server = false
			client = true
		}

		c := &cert.Cert{
			CA:       *certCreateCAFile,
			Domain:   *certCreateDomain,
			Days:     *certCreateDays,
			Key:      *certCreateKeyFile,
			Server:   server,
			Client:   client,
			DNSNames: *certCreateAdditionalDNSnames,
		}
		err := c.Create()
		if err != nil {
			log.Fatalf(err.Error())
		}
	}
}
