package app

import (
	"crypto/x509/pkix"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"time"
)

type RevokedCertificate struct {
	SerialNumber string    `json:"serial_numer"`
	RevokedAt    time.Time `json:"revoked_at"`
}

func (a *App) getOrSetRevoked() ([]pkix.RevokedCertificate, error) {
	revokedPath := path.Join(a.RootDirectory, "crl.json")

	_, err := os.Stat(revokedPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		return a.createRevoked(revokedPath)
	}

	return a.loadRevoked(revokedPath)
}

func (a *App) createRevoked(filePath string) ([]pkix.RevokedCertificate, error) {
	err := ioutil.WriteFile(filePath, []byte("[]"), 0644)

	return []pkix.RevokedCertificate{}, err
}

func (a *App) loadRevoked(filePath string) ([]pkix.RevokedCertificate, error) {
	fileBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	set := []RevokedCertificate{}

	err = json.Unmarshal(fileBytes, &set)
	if err != nil {
		return nil, err
	}

	out := []pkix.RevokedCertificate{}

	for _, s := range set {
		sn := &big.Int{}
		sn.SetString(s.SerialNumber, 10)

		out = append(out, pkix.RevokedCertificate{
			SerialNumber:   sn,
			RevocationTime: s.RevokedAt,
		})
	}

	return out, nil
}
