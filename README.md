# tls-tool
I needed to create a CA and a few server and client certificates for my [ssl_exporter](https://github.com/ribbybibby/ssl_exporter) tests but I found doing it repeatedly with `openssl` was tiresome. I'm a big fan of the [consul tls client](https://learn.hashicorp.com/consul/advanced/day-1-operations/certificates) but I wanted more control over the content of the certificates. So, I've copied the code from [consul](https://github.com/hashicorp/consul/tree/master/command/tls) and tweaked it a bit for my purposes.

## Usage
```
$ tls-tool --help
usage: tls-tool [<flags>] <command> [<args> ...]

A tool for creating TLS certificates quickly

Flags:
  --help  Show context-sensitive help (also try --help-long and --help-man).

Commands:
  help [<command>...]
    Show help.

  ca create [<flags>]
    Create a new certificate authority

  cert create [<flags>]
    Create a new certificate
```
```
$ tls-tool ca create --help
usage: tls-tool ca create [<flags>]

Create a new certificate authority

Flags:
  --help                       Show context-sensitive help (also try --help-long and --help-man).
  --domain="ribbybibby.me"     Domain
  --days=1825                  Provide number of days the CA is valid for from now on
  --name-constraint            Add name constraints for the CA?
  --additional-name-constraint=ADDITIONAL-NAME-CONSTRAINT ...  
                               Add additional name constraints for the CA.
  --country="GB"               Country
  --postal-code="SW18XXX"      Postal code
  --province="England"         Province
  --locality="London"          Locality
  --street-address="123 Fake St"  
                               Street Address
  --organization="ribbybibby"  Organization
```
```
$ tls-tool cert create --help
usage: tls-tool cert create [<flags>]

Create a new certificate

Flags:
  --help                    Show context-sensitive help (also try --help-long and --help-man).
  --ca=ca.pem               Provide path to the ca
  --key=ca-key.pem          Provide path to the key
  --days=365                Provide number of days the certificate is valid for from now on
  --domain="ribbybibby.me"  Domain
  --additional-dnsname=ADDITIONAL-DNSNAME ...  
                            Provide additional dnsnames for Subject Alternative Names.
  --insecure                Optionally allow the creation of purposely expired or otherwise invalid certs
```

## Example
Create a CA:
```
$ tls-tool ca create
==> Saved ca.pem
==> Saved ca-key.pem
```

Create a certificate:
```
$ tls-tool cert create
==> Using ca.pem and ca-key.pem
==> Saved cert-ribbybibby.me-0.pem
==> Saved cert-ribbybibby.me-0-key.pem
```
