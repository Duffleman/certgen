package app

import (
	"fmt"

	"certgen"
)

// getSerialKey will get the key to save into the serial history file
func (a *App) getSerialKey(certType certgen.CertificateType, name string) string {
	return fmt.Sprintf("%s:%s", certType, name)
}
