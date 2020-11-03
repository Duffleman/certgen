package app

import (
	"fmt"
	"path"

	"certgen"
)

// GenerateClientCertificate generates a new client certificate
func (a *App) GenerateClientCertificate(name, password string) error {
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

	certTemplate, err := a.createTemplate(ClientCertificiate, nextSerial)
	if err != nil {
		return err
	}

	certTemplate.Subject.CommonName = name

	certificate, err := a.createCertificate(fmt.Sprintf("%s.public", name), &CertSignReq{
		certType:          ClientCertificiate,
		template:          certTemplate,
		parent:            rootCA,
		certificatePublic: private.Public(),
		parentPrivate:     rootPrivate,
	})
	if err != nil {
		return err
	}

	return a.saveP12(fmt.Sprintf("%s.public", name), private, certificate, rootCA, password)
}
