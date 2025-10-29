package cmd

import "github.com/spf13/cobra"

var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Gestiona operaciones de carga hacia los targets",
}

func init() {
	rootCmd.AddCommand(uploadCmd)
}
