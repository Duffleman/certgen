package app

import (
	"fmt"
)

func (a *App) GetSerialKey(certType CertificateType, name string) string {
	return fmt.Sprintf("%s:%s", certType, name)
}
