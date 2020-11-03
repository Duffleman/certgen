package app

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"certgen"
	"certgen/lib/cher"

	"software.sslmate.com/src/go-pkcs12"
)

type saveP12Req struct {
	name        string
	private     *ecdsa.PrivateKey
	certificate *x509.Certificate
	rootCA      *x509.Certificate
	password    string
}

// saveP12 saves a certificate into the P12 format for browsers and computers to
// import, a password is always required
func (a *App) saveP12(certType certgen.CertificateType, req *saveP12Req) error {
	filePath := path.Join(
		a.RootDirectory,
		certgen.CertFolderMap[certType],
		fmt.Sprintf("%s.public.p12", req.name),
	)

	if req.password == "" {
		return cher.New("missing_password", cher.M{
			"type":   certType,
			"name":   req.name,
			"format": "p12",
		})
	}

	if _, err := os.Stat(filePath); err == nil || os.IsExist(err) {
		return cher.New("p12_already_exists", nil)
	} else if !os.IsNotExist(err) {
		return err
	}

	pfxData, err := pkcs12.Encode(rand.Reader, req.private, req.certificate, []*x509.Certificate{req.rootCA}, req.password)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, pfxData, 0644)
}
