package commands

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"path"
	"time"

	"certgen/lib/certserial"
	"certgen/lib/cher"
	"certgen/lib/filesys"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var filename = "crl.txt"

var crlTemplate = &x509.RevocationList{
	SignatureAlgorithm: x509.ECDSAWithSHA384,
}

var CreateCRLFileCmd = &cobra.Command{
	Use:     "create_crl_file",
	Aliases: []string{"crl"},
	Short:   "Create a CRL file",
	Long:    "Create a certificate revociation list file to upload to your given URL",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rootDirectory := viper.GetString("SECERTS_ROOT_DIR")
		crlFilename := path.Join(rootDirectory, filename)
		rootCADir := path.Join(rootDirectory, "root_ca")

		now := time.Now()
		later := time.Now().Add(24 * time.Hour)

		rootCA, rootPrivate, err := filesys.LoadRootCA(rootCADir)
		if err != nil {
			return err
		}

		revoked, err := loadRevoked(crlFilename)
		if err != nil {
			return err
		}

		nextSerial, err := certserial.GetNextSerial("crl")
		if err != nil {
			return err
		}

		logrus.Infof("Using serial %s", nextSerial)

		crlTemplate.Number = nextSerial
		crlTemplate.RevokedCertificates = revoked
		crlTemplate.ThisUpdate = now
		crlTemplate.NextUpdate = later

		crl, err := x509.CreateRevocationList(rand.Reader, crlTemplate, rootCA, rootPrivate)
		if err != nil {
			return err
		}

		return filesys.SavePEM("X509 CRL", path.Join(rootDirectory, "crl"), crl)
	},
}

func loadRevoked(crlPath string) ([]pkix.RevokedCertificate, error) {
	if _, err := os.Stat(crlPath); err != nil {
		if os.IsNotExist(err) {
			return nil, cher.New("no_revocation_list", cher.M{
				"path": crlPath,
			})
		}

		return nil, err
	}

	file, err := os.Open(crlPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	revocationSet := []pkix.RevokedCertificate{}

	for {
		line, prefix, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, err
		}

		if prefix {
			return nil, cher.New("line_too_long", cher.M{
				"path": crlPath,
			})
		}

		parts := bytes.Split(line, []byte(":"))

		serialNumber := &big.Int{}
		serialNumber.SetBytes(parts[0])

		rest := bytes.Join(parts[1:], []byte(":"))

		t, err := time.Parse(time.RFC3339, string(rest))
		if err != nil {
			return nil, err
		}

		r := pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: t,
		}

		revocationSet = append(revocationSet, r)
	}

	return revocationSet, nil
}
