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

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var clientTemplate = &x509.Certificate{
	SerialNumber: nil,
	Subject: pkix.Name{
		Organization: []string{"Duffleman"},
		Country:      []string{"GB"},
	},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(DefaultLengthYears, 0, 0),
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	KeyUsage:              x509.KeyUsageDigitalSignature,
	IsCA:                  false,
	BasicConstraintsValid: true,
}

var passwordForP12 string

func init() {
	GenerateClientCertificateCmd.Flags().StringP("password", "p", "", "What should the password be?")
	GenerateClientCertificateCmd.MarkFlagRequired("password")
}

var GenerateClientCertificateCmd = &cobra.Command{
	Use:     "generate_client_ceritificate [hostname]",
	Aliases: []string{"gcc"},
	Short:   "Generate a client certificate",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hostname := args[0]

		rootDirectory := viper.GetString("SECERTS_ROOT_DIR")
		directory := path.Join(rootDirectory, "client_certs")
		rootCADir := path.Join(rootDirectory, "root_ca")

		rootCA, rootPrivate, err := filesys.LoadRootCA(rootCADir)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(directory, 0777); err != nil {
			return err
		}

		nextSerial, err := certserial.GetNextSerial()
		if err != nil {
			return err
		}

		logrus.Infof("Using serial %s", nextSerial)

		clientTemplate.SerialNumber = nextSerial
		clientTemplate.Subject.CommonName = hostname

		// private key
		keyPath := path.Join(directory, fmt.Sprintf("%s.private", hostname))

		private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}

		privBytes, err := x509.MarshalECPrivateKey(private)
		if err != nil {
			return err
		}

		err = filesys.SavePEM("EC PRIVATE KEY", keyPath, privBytes)
		if err != nil {
			return err
		}

		// public key
		certPath := path.Join(directory, fmt.Sprintf("%s.public", hostname))

		certBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, rootCA, &private.PublicKey, rootPrivate)
		if err != nil {
			return err
		}

		x509Cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return err
		}

		err = filesys.SavePEM("CERTIFICATE", certPath, certBytes)
		if err != nil {
			return err
		}

		password, err := cmd.Flags().GetString("password")
		if err != nil {
			return err
		}

		return filesys.SaveP12(keyPath, private, x509Cert, rootCA, password)
	},
}
