package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"certgen"
	"certgen/lib/cher"
)

// getOrSetPrivate loads a certificate, or creates one if it cannot find one
func (a *App) getOrSetPrivate(certType certgen.CertificateType, name string) (*ecdsa.PrivateKey, error) {
	privatePath := path.Join(
		a.RootDirectory,
		certgen.CertFolderMap[certType],
		fmt.Sprintf("%s.private.pem", name),
	)

	_, err := os.Stat(privatePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		return a.createPrivate(certType, name)
	}

	return a.loadPrivate(certType, name)
}

// createPrivate creates a private key, but will override one if it exists
func (a *App) createPrivate(certType certgen.CertificateType, name string) (*ecdsa.PrivateKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}

	return private, a.savePEM(certType, name, pemPrivate, privBytes)
}

// loadPrivate loads private key from the file system
func (a *App) loadPrivate(certType certgen.CertificateType, name string) (*ecdsa.PrivateKey, error) {
	filePath := path.Join(
		a.RootDirectory,
		certgen.CertFolderMap[certType],
		fmt.Sprintf("%s.private.pem", name),
	)

	keyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, cher.New("empty_pem_file", cher.M{
			"path": filePath,
		})
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	private, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, cher.New("unexpected_private_key_type", cher.M{
			"path": filePath,
		})
	}

	return private, nil
}
