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

const DefaultLengthYears = 10

var rootTemplate = &x509.Certificate{
	Subject:               pkix.Name{},
	NotBefore:             time.Now().Add(-1 * time.Second),
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	BasicConstraintsValid: true,
	IsCA:                  true,
}

var GenerateRootCACmd = &cobra.Command{
	Use:     "generate_root_ca",
	Aliases: []string{"gca"},
	Short:   "Generate a new root CA",

	RunE: func(cmd *cobra.Command, args []string) error {
		rootDirectory := viper.GetString("SECERTS_ROOT_DIR")
		directory := path.Join(rootDirectory, "root_ca")

		if err := os.MkdirAll(directory, 0777); err != nil {
			return err
		}

		certInfo, err := template.LoadInfoFromTemplate()
		if err != nil {
			return err
		}

		nextSerial, err := certserial.GetNextSerial(fmt.Sprintf("root:%s", "DFL Root CA"))
		if err != nil {
			return err
		}

		logrus.Infof("Using serial %s", nextSerial)

		rootTemplate.SerialNumber = nextSerial
		rootTemplate.Subject.CommonName = certInfo.RootCA.CommonName
		rootTemplate.Subject.Country = certInfo.RootCA.Country
		rootTemplate.Subject.Organization = certInfo.RootCA.Organisation
		if len(certInfo.CRLURLs) > 0 {
			rootTemplate.CRLDistributionPoints = certInfo.CRLURLs
		}

		rootTemplate.NotAfter = time.Now().AddDate(certInfo.CertificateExpiryYears, 0, 0)

		// private key stuff
		keyPath := path.Join(directory, "root.private")

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
		certPath := path.Join(directory, "root.public")

		certBytes, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, private.Public(), private)
		if err != nil {
			return err
		}

		return filesys.SavePEM("CERTIFICATE", certPath, certBytes)
	},
}
