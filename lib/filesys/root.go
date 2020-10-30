package filesys

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path"

	"certgen/lib/cher"
)

func LoadRootCA(rootDirectory string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPath := path.Join(rootDirectory, "root_public.pem")
	keyPath := path.Join(rootDirectory, "root_private.pem")

	if _, err := os.Stat(certPath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil, cher.New("missing_root_certificate", cher.M{
				"path": certPath,
			})
		}

		return nil, nil, err
	}

	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil, cher.New("missing_root_key", cher.M{
				"path": keyPath,
			})
		}

		return nil, nil, err
	}

	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return nil, nil, cher.New("empty_pem_file", cher.M{
			"path": certPath,
		})
	}

	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, nil, cher.New("empty_pem_file", cher.M{
			"path": keyPath,
		})
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	private, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, cher.New("unexpected_private_key_type", cher.M{
			"path": keyPath,
			"file": privateKey,
		})
	}

	return certificate, private, nil
}
