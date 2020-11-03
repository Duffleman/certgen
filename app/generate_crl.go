package app

import (
	"crypto/rand"
	"crypto/x509"
	"path"
	"time"

	"certgen"
)

// GenerateCRL creates a new certificate revocation list (saved as a PEM file)
func (a *App) GenerateCRL() error {
	err := a.checkForInit()
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

	nextSerial, err := a.getNextSerial(certgen.CRL, "crl")
	if err != nil {
		return err
	}

	revoked, err := a.getOrSetRevoked()
	if err != nil {
		return err
	}

	now := time.Now()

	crlTemplate := &x509.RevocationList{
		Number:              nextSerial,
		SignatureAlgorithm:  x509.ECDSAWithSHA384,
		ThisUpdate:          now,
		NextUpdate:          now.Add(2 * time.Hour),
		RevokedCertificates: revoked,
	}

	crl, err := x509.CreateRevocationList(rand.Reader, crlTemplate, rootCA, rootPrivate)
	if err != nil {
		return err
	}

	err = a.savePEM("X509 CRL", path.Join(a.RootDirectory, "crl"), crl)
	if err != nil {
		return err
	}

	return a.writeSerialFile(nextSerial, "crl")
}
