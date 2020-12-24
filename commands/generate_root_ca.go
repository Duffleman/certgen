package commands

import (
	"certgen/app"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var GenerateRootCACmd = &cobra.Command{
	Use:     "generate_root_ca",
	Aliases: []string{"gca"},
	Short:   "Generate a new root CA",
	Args:    cobra.NoArgs,

	RunE: func(cmd *cobra.Command, args []string) error {
		rootDirectory := viper.GetString("SECERTS_ROOT_DIR")

		app := &app.App{
			RootDirectory: rootDirectory,
		}

		return app.GenerateRootCA()
	},
}
