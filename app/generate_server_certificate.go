package app

import (
	"fmt"
	"path"
	"strings"

	"certgen"
)

// GenerateServerCertificate generates a new server certificate
func (a *App) GenerateServerCertificate(name string) error {
	err := a.checkForInit()
	if err != nil {
		return err
	}

	nextSerial, err := a.getNextSerial(ClientCertificiate, name)
	if err != nil {
		return err
	}

	rootCA, err := a.loadCertificate(path.Join(a.RootDirectory, certgen.RootCAFolder, "root.public.pem"))
	if err != nil {
		return err
	}

	rootPrivate, err := a.loadPrivate(path.Join(a.RootDirectory, certgen.RootCAFolder, "root.private.pem"))
	if err != nil {
		return err
	}

	private, err := a.getOrSetPrivate(fmt.Sprintf("%s.private", name))
	if err != nil {
		return err
	}

	certTemplate, err := a.createTemplate(ServerCertificate, nextSerial)
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

	if _, err := a.createCertificate(fmt.Sprintf("%s.public", name), &CertSignReq{
		certType:          ServerCertificate,
		template:          certTemplate,
		parent:            rootCA,
		certificatePublic: private.Public(),
		parentPrivate:     rootPrivate,
	}); err != nil {
		return err
	}

	return nil
}
