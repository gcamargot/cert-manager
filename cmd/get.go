/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import "github.com/spf13/cobra"

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Obtiene información de los targets configurados",
	Long: `
Ejemplos:

  cert-updater get certificate expiration -t target1,target2
  cert-updater get certificate expiration -A --output json
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
