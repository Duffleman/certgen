package commands

import (
	"certgen"
	"path"

	"certgen/app"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var GenerateRootCACmd = &cobra.Command{
	Use:     "generate_root_ca",
	Aliases: []string{"gca"},
	Short:   "Generate a new root CA",

	RunE: func(cmd *cobra.Command, args []string) error {
		rootDirectory := viper.GetString("SECERTS_ROOT_DIR")
		directory := path.Join(rootDirectory, certgen.RootCAFolder)

		app := &app.App{
			RootDirectory:    rootDirectory,
			WorkingDirectory: directory,
		}

		return app.GenerateRootCA()
	},
}
