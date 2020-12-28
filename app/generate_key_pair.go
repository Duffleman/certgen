package app

import (
	"certgen"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
)

// GenerateKeyPair generates a random public and private key pair
func (a *App) GenerateKeyPair(name string) error {
	err := a.checkForInit()
	if err != nil {
		return err
	}

	private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}

	public := private.PublicKey

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(&public)
	if err != nil {
		return err
	}

	privFilePath := path.Join(
		a.RootDirectory,
		certgen.CertFolderMap[certgen.KeyPair],
		fmt.Sprintf("%s.private.pem", name),
	)

	pubFilePath := path.Join(
		a.RootDirectory,
		certgen.CertFolderMap[certgen.KeyPair],
		fmt.Sprintf("%s.public.pem", name),
	)

	privOut, err := os.Create(privFilePath)
	if err != nil {
		return err
	}
	defer privOut.Close()

	pubOut, err := os.Create(pubFilePath)
	if err != nil {
		return err
	}
	defer pubOut.Close()

	if err = pem.Encode(privOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded}); err != nil {
		return err
	}

	if err = pem.Encode(pubOut, &pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub}); err != nil {
		return err
	}

	return nil
}
