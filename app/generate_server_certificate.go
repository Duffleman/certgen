package app

import (
	"strings"

	"certgen"
)

// GenerateServerCertificate generates a new server certificate
func (a *App) GenerateServerCertificate(name string) error {
	err := a.checkForInit()
	if err != nil {
		return err
	}

	nextSerial, err := a.getNextSerial(certgen.ServerCertificate, name)
	if err != nil {
		return err
	}

	rootCA, err := a.loadCertificate(certgen.RootCA, "root")
	if err != nil {
		return err
	}

	rootPrivate, err := a.loadPrivate(certgen.RootCA, "root")
	if err != nil {
		return err
	}

	private, err := a.getOrSetPrivate(certgen.ServerCertificate, name)
	if err != nil {
		return err
	}

	certTemplate, err := a.createTemplate(certgen.ServerCertificate, nextSerial)
	if err != nil {
		return err
	}

	dnsNames := []string{name}

	domainParts := strings.Split(name, ".")

	if domainParts[0] == "www" {
		dnsNames = append(dnsNames, strings.Join(domainParts[1:], "."))
	}

	certTemplate.Subject.CommonName = name
	certTemplate.DNSNames = dnsNames

	if _, err := a.createCertificate(&certSignReq{
		certType:          certgen.ServerCertificate,
		template:          certTemplate,
		parent:            rootCA,
		certificatePublic: private.Public(),
		parentPrivate:     rootPrivate,
	}); err != nil {
		return err
	}

	return nil
}
