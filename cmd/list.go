package cmd

import "github.com/spf13/cobra"

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Muestra información almacenada localmente",
}

func init() {
	rootCmd.AddCommand(listCmd)
}
