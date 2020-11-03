package commands

import (
	"crypto/x509"

	"certgen/app"

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

		app := &app.App{
			RootDirectory:    rootDirectory,
			WorkingDirectory: rootDirectory,
		}

		return app.GenerateCRL()
	},
}
