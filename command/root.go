package command

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "sx",
	Short:   "Fast, modern, easy-to-use network scanner",
	Version: "0.1.0",
}

var jsonFlag bool

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "enable JSON output")
}

func Main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
