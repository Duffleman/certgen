package app

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"certgen/lib/cher"
)

func (a *App) getCertificate(filePath string) (*x509.Certificate, error) {
	publicPath := path.Join(a.WorkingDirectory, fmt.Sprintf("%s.pem", filePath))

	_, err := os.Stat(publicPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		return nil, cher.New("no_certificate_found", cher.M{"path": filePath})
	}

	return a.loadCertificate(publicPath)
}

func (a *App) loadCertificate(filePath string) (*x509.Certificate, error) {
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
