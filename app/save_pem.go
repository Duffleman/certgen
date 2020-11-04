package app

import (
	"encoding/pem"
	"fmt"
	"os"
	"path"

	"certgen"
	"certgen/lib/cher"
)

type pemType string

const (
	pemPublic  pemType = "CERTIFICATE"
	pemPrivate pemType = "EC PRIVATE KEY"
	pemCRL     pemType = "X509 CRL"
)

// savePEM saves a PEM file of anything you throw at it
func (a *App) savePEM(certType certgen.CertificateType, name string, pemType pemType, bytes []byte) error {
	var pubPriv string

	switch pemType {
	case pemPublic, pemCRL:
		pubPriv = "public"
	default:
		pubPriv = "private"
	}

	filePath := path.Join(
		a.RootDirectory,
		certgen.CertFolderMap[certType],
		fmt.Sprintf("%s.%s.pem", name, pubPriv),
	)

	if _, err := os.Stat(filePath); err == nil || os.IsExist(err) {
		return cher.New("certificate_already_exists", cher.M{"path": filePath})
	} else if !os.IsNotExist(err) {
		return err
	}

	certOut, err := os.Create(filePath)
	if err != nil {
		return err
	}

	if err = pem.Encode(certOut, &pem.Block{Type: string(pemType), Bytes: bytes}); err != nil {
		return err
	}

	return certOut.Close()
}
