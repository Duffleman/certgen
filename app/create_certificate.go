package app

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"

	"certgen"
)

type certSignReq struct {
	certType          certgen.CertificateType
	template          *x509.Certificate
	parent            *x509.Certificate
	certificatePublic crypto.PublicKey
	parentPrivate     *ecdsa.PrivateKey
}

// createCertificate will create the x509 certificate, save it as a PEM file,
// and ensure that the serial file has been written to
func (a *App) createCertificate(req *certSignReq) (*x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, req.template, req.parent, req.certificatePublic, req.parentPrivate)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	err = a.savePEM(req.certType, req.template.Subject.CommonName, pemPublic, certBytes)
	if err != nil {
		return cert, err
	}

	serialKey := a.getSerialKey(req.certType, req.template.Subject.CommonName)

	return cert, a.writeSerialFile(req.template.SerialNumber, serialKey)
}
