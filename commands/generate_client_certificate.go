package commands

import (
	"certgen/app"
	"certgen/lib/cher"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
		name := args[0]

		password, err := cmd.Flags().GetString("password")
		if err != nil || password == "" {
			return cher.New("no_password_given", nil)
		}

		rootDirectory := viper.GetString("SECERTS_ROOT_DIR")

		app := &app.App{
			RootDirectory: rootDirectory,
		}

		return app.GenerateClientCertificate(name, password)
	},
}
