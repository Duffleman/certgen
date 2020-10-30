package filesys

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

func SaveP12(path string, privateKey *ecdsa.PrivateKey, certificate, rootCA *x509.Certificate, password string) error {
	if !strings.HasSuffix(path, ".p12") {
		path = fmt.Sprintf("%s.p12", path)
	}

	if _, err := os.Stat(path); err == nil || os.IsExist(err) {
		return errors.New("certificate_already_exists")
	} else if !os.IsNotExist(err) {
		return err
	}

	pfxData, err := pkcs12.Encode(rand.Reader, privateKey, certificate, []*x509.Certificate{rootCA}, password)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, pfxData, 0777)
}
