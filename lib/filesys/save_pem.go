package filesys

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

func SavePEM(certType, path string, bytes []byte) error {
	if !strings.HasSuffix(path, ".pem") {
		path = fmt.Sprintf("%s.pem", path)
	}

	if _, err := os.Stat(path); err == nil || os.IsExist(err) {
		return errors.New("certificate_already_exists")
	} else if !os.IsNotExist(err) {
		return err
	}

	certOut, err := os.Create(path)
	if err != nil {
		return err
	}
	if err = pem.Encode(certOut, &pem.Block{Type: certType, Bytes: bytes}); err != nil {
		return err
	}
	return certOut.Close()
}
