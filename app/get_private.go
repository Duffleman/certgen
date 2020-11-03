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

	"certgen/lib/cher"
)

func (a *App) getOrSetPrivate(filePath string) (*ecdsa.PrivateKey, error) {
	privatePath := path.Join(a.WorkingDirectory, fmt.Sprintf("%s.pem", filePath))

	_, err := os.Stat(privatePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		return a.createPrivate(privatePath)
	}

	return a.loadPrivate(privatePath)
}

func (a *App) createPrivate(filePath string) (*ecdsa.PrivateKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}

	return private, a.savePEM("EC PRIVATE KEY", filePath, privBytes)
}

func (a *App) loadPrivate(filePath string) (*ecdsa.PrivateKey, error) {
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
