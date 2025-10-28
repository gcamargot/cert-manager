/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	// "net/http"
	"os"
)

type target struct {
	name   string
	key    string
	secret string
	url    string
}

var targetlist []target

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			cobra.CheckErr(fmt.Errorf("update requires a target"))
		} else {
			update(args)
		}
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// updateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// updateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func update(args []string) {
	if args[0] == "all" {
		loadAllTargets()
	} else {
		fmt.Println("Target not found: " + args[0])
	}
}

func loadAllTargets() {
	file, err := os.Open("targetlist")
	err2 := godotenv.Load()
	if err2 != nil {
		fmt.Println("Ocurrio un error al cargar el .env")
	} else {
		if err != nil {
			fmt.Println("No se puedo leer la lista de targets")
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			current := scanner.Text()
			t := target {
				name: current,
				key:	os.Getenv(current + "_key"),
				secret: os.Getenv(current + "_secret"),
				url: os.Getenv(current + "_url"),
				}
			targetlist = append (targetlist, t)
		}
		for _, t := range targetlist {
			fmt.Println(t)
		}
	}
}
