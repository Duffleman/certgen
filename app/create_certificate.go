package app

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"path"
)

type CertSignReq struct {
	certType          CertificateType
	template          *x509.Certificate
	parent            *x509.Certificate
	certificatePublic crypto.PublicKey
	parentPrivate     *ecdsa.PrivateKey
}

func (a *App) createCertificate(filePath string, req *CertSignReq) (*x509.Certificate, error) {
	certPath := path.Join(a.WorkingDirectory, filePath)

	certBytes, err := x509.CreateCertificate(rand.Reader, req.template, req.parent, req.certificatePublic, req.parentPrivate)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	err = a.savePEM("CERTIFICATE", certPath, certBytes)
	if err != nil {
		return cert, err
	}

	serialKey := a.GetSerialKey(req.certType, req.template.Subject.CommonName)

	return cert, a.writeSerialFile(req.template.SerialNumber, serialKey)
}
