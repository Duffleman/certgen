package app

import "certgen"

// GenerateRootCA generates a new root CA
func (a *App) GenerateRootCA() error {
	err := a.checkForInit()
	if err != nil {
		return err
	}

	nextSerial, err := a.getNextSerial(certgen.RootCA, a.CertificateInformation.RootCA.CommonName)
	if err != nil {
		return err
	}

	private, err := a.getOrSetPrivate(certgen.RootCA, "root")
	if err != nil {
		return err
	}

	certTemplate, err := a.createTemplate(certgen.RootCA, nextSerial)
	if err != nil {
		return err
	}

	certTemplate.Subject.CommonName = a.CertificateInformation.RootCA.CommonName

	if len(a.CertificateInformation.CRLURLs) > 0 {
		certTemplate.CRLDistributionPoints = a.CertificateInformation.CRLURLs
	}

	_, err = a.createCertificate(&certSignReq{
		certType:          certgen.RootCA,
		template:          certTemplate,
		parent:            certTemplate,
		certificatePublic: private.Public(),
		parentPrivate:     private,
	})
	if err != nil {
		return err
	}

	return nil
}
