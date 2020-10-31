package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path"
	"time"

	"certgen/lib/certserial"
	"certgen/lib/filesys"
	"certgen/lib/template"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var certificateTemplate = &x509.Certificate{
	Subject:   pkix.Name{},
	NotBefore: time.Now(),
	KeyUsage:  x509.KeyUsageDigitalSignature,
	ExtKeyUsage: []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageServerAuth,
	},
	BasicConstraintsValid: true,
	IsCA:                  false,
}

var GenerateServerCertificateCmd = &cobra.Command{
	Use:     "generate_server_certificate [domain]",
	Aliases: []string{"gsc"},
	Short:   "Generate a server certificate",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]

		rootDirectory := viper.GetString("SECERTS_ROOT_DIR")
		directory := path.Join(rootDirectory, "server_certs")
		rootCADir := path.Join(rootDirectory, "root_ca")

		rootCA, rootPrivate, err := filesys.LoadRootCA(rootCADir)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(directory, 0777); err != nil {
			return err
		}

		certInfo, err := template.LoadInfoFromTemplate()
		if err != nil {
			return err
		}

		nextSerial, err := certserial.GetNextSerial(fmt.Sprintf("server:%s", domain))
		if err != nil {
			return err
		}

		logrus.Infof("Using serial %s", nextSerial)

		certificateTemplate.SerialNumber = nextSerial
		certificateTemplate.Subject.CommonName = domain
		certificateTemplate.Subject.Country = certInfo.RootCA.Country
		certificateTemplate.Subject.Organization = certInfo.RootCA.Organisation
		certificateTemplate.DNSNames = []string{domain}

		certificateTemplate.NotAfter = time.Now().AddDate(certInfo.CertificateExpiryYears, 0, 0)

		// private key stuff
		keyPath := path.Join(directory, fmt.Sprintf("%s.private", domain))

		private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}

		privBytes, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return err
		}

		err = filesys.SavePEM("EC PRIVATE KEY", keyPath, privBytes)
		if err != nil {
			return err
		}

		// public key stuff
		certPath := path.Join(directory, fmt.Sprintf("%s.public", domain))

		certBytes, err := x509.CreateCertificate(rand.Reader, certificateTemplate, rootCA, &private.PublicKey, rootPrivate)
		if err != nil {
			return err
		}

		return filesys.SavePEM("CERTIFICATE", certPath, certBytes)
	},
}
