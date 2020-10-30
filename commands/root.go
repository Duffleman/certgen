package commands

import (
	"fmt"

	"certgen"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:  "certgen [command]",
	Long: "certgen manages and generates certificates for you.",
}

var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of certgen",
	Long:  `I don't always drink beer. But when I do, I drink certgen...`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("certgen v%s\n", certgen.Version)
	},
}
