/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands

type Target struct {
	name       string
	key        string
	secret     string
	url        string
	targetType string
}

var TargetList []Target

var (
	rootCmd = &cobra.Command{
		Use:   "cert-updater",
		Short: "Cert-updater is a CLI tool to automate SSL certs update",
		Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		// Uncomment the following line if your bare application
		// has an action associated with it:
		// Run: func(cmd *cobra.Command, args []string) { },
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	cobra.OnInitialize(loadAllTargets)
	// rootCmd.PersistentFlags().StringVar(&cert, "cert", "", "")
	// rootCmd.PersistentFlags().StringVar(&pkey, "pkey", "", "")
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func loadAllTargets() {
	TargetList = TargetList[:0]

	if err := godotenv.Load(); err != nil {
		fmt.Println("Ocurrio un error al cargar el .env")
		return
	}

	file, err := os.Open("targetlist")
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		fmt.Println("No se puedo leer la lista de targets:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		current := strings.TrimSpace(scanner.Text())
		if current == "" {
			continue
		}
		t := Target{
			name:       current,
			key:        os.Getenv(current + "_key"),
			secret:     os.Getenv(current + "_secret"),
			url:        os.Getenv(current + "_url"),
			targetType: os.Getenv(current + "_type"),
		}
		TargetList = append(TargetList, t)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error al leer la lista de targets:", err)
	}
}
