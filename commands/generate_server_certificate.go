package commands

import (
	"certgen/app"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var GenerateServerCertificateCmd = &cobra.Command{
	Use:     "generate_server_ceritificate [domain]",
	Aliases: []string{"gsc"},
	Short:   "Generate a server certificate",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		rootDirectory := viper.GetString("SECERTS_ROOT_DIR")

		app := &app.App{
			RootDirectory: rootDirectory,
		}

		return app.GenerateServerCertificate(name)
	},
}
