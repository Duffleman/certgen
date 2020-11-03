package app

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"certgen"
	"certgen/lib/cher"
)

// getCertificate will load a certificate from the file system
func (a *App) getCertificate(certType certgen.CertificateType, name string) (*x509.Certificate, error) {
	publicPath := path.Join(
		a.RootDirectory,
		certgen.CertFolderMap[certType],
		fmt.Sprintf("%s.public.pem", name),
	)

	_, err := os.Stat(publicPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		return nil, cher.New("no_certificate_found", cher.M{"path": publicPath})
	}

	return a.loadCertificate(certType, name)
}

// loadCertificate will load a certificate from the filesystem without any checks
// such as checking if it exists
func (a *App) loadCertificate(certType certgen.CertificateType, name string) (*x509.Certificate, error) {
	filePath := path.Join(
		a.RootDirectory,
		certgen.CertFolderMap[certType],
		fmt.Sprintf("%s.public.pem", name),
	)

	certBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return nil, cher.New("empty_pem_file", cher.M{
			"path": filePath,
		})
	}

	return x509.ParseCertificate(certBlock.Bytes)
}
