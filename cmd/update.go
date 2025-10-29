/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import "github.com/spf13/cobra"

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Actualiza recursos locales o remotos",
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
