package app

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"certgen/lib/cher"
)

func (a *App) savePEM(pemType, path string, bytes []byte) error {
	if !strings.HasSuffix(path, ".pem") {
		path = fmt.Sprintf("%s.pem", path)
	}

	if _, err := os.Stat(path); err == nil || os.IsExist(err) {
		return cher.New("certificate_already_exists", cher.M{"path": path})
	} else if !os.IsNotExist(err) {
		return err
	}

	certOut, err := os.Create(path)
	if err != nil {
		return err
	}
	if err = pem.Encode(certOut, &pem.Block{Type: pemType, Bytes: bytes}); err != nil {
		return err
	}
	return certOut.Close()
}
