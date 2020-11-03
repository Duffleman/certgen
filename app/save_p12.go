package app

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// saveP12 saves a certificate into the P12 format for browsers and computers to
// import
func (a *App) saveP12(filePath string, private *ecdsa.PrivateKey, certificate, rootCA *x509.Certificate, password string) error {
	filePath = path.Join(a.WorkingDirectory, filePath)

	if !strings.HasSuffix(filePath, ".p12") {
		filePath = fmt.Sprintf("%s.p12", filePath)
	}

	if _, err := os.Stat(filePath); err == nil || os.IsExist(err) {
		return errors.New("p12_already_exists")
	} else if !os.IsNotExist(err) {
		return err
	}

	pfxData, err := pkcs12.Encode(rand.Reader, private, certificate, []*x509.Certificate{rootCA}, password)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, pfxData, 0644)
}
