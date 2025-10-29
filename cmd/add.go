package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Gestiona la creación de recursos",
}

var addTargetCmd = &cobra.Command{
	Use:   "target",
	Short: "Agrega un nuevo target al archivo .env",
	RunE:  runAddTarget,
}

func init() {
	rootCmd.AddCommand(addCmd)
	addCmd.AddCommand(addTargetCmd)

	addTargetCmd.Flags().StringP("name", "n", "", "Nombre del target")
	addTargetCmd.Flags().StringP("key", "k", "", "API key del target")
	addTargetCmd.Flags().StringP("secret", "s", "", "API secret del target")
	addTargetCmd.Flags().StringP("url", "u", "", "URL base del target")
	addTargetCmd.Flags().StringP("type", "t", "", "Tipo de sistema del target")

	cobra.CheckErr(addTargetCmd.MarkFlagRequired("name"))
	cobra.CheckErr(addTargetCmd.MarkFlagRequired("key"))
	cobra.CheckErr(addTargetCmd.MarkFlagRequired("secret"))
	cobra.CheckErr(addTargetCmd.MarkFlagRequired("url"))
	cobra.CheckErr(addTargetCmd.MarkFlagRequired("type"))
}

func runAddTarget(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(cmd.Flag("name").Value.String())
	apiKey := strings.TrimSpace(cmd.Flag("key").Value.String())
	apiSecret := strings.TrimSpace(cmd.Flag("secret").Value.String())
	baseURL := strings.TrimSpace(cmd.Flag("url").Value.String())
	targetType := strings.TrimSpace(cmd.Flag("type").Value.String())

	if name == "" || apiKey == "" || apiSecret == "" || baseURL == "" || targetType == "" {
		return fmt.Errorf("todos los parámetros son obligatorios")
	}

	if err := ensureTargetDoesNotExist(name); err != nil {
		return err
	}

	if err := persistTarget(name, apiKey, apiSecret, baseURL, targetType); err != nil {
		return err
	}

	// Actualiza el entorno actual para mantener la información sincronizada.
	_ = os.Setenv(name+"_key", apiKey)
	_ = os.Setenv(name+"_secret", apiSecret)
	_ = os.Setenv(name+"_url", baseURL)
	_ = os.Setenv(name+"_type", targetType)

	TargetList = append(TargetList, Target{
		name:       name,
		key:        apiKey,
		secret:     apiSecret,
		url:        baseURL,
		targetType: targetType,
	})

	fmt.Printf("Target %s agregado correctamente\n", name)
	return nil
}

func ensureTargetDoesNotExist(name string) error {
	for _, t := range TargetList {
		if strings.EqualFold(t.name, name) {
			return fmt.Errorf("el target %s ya existe", name)
		}
	}

	envBytes, err := os.ReadFile(".env")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("no se pudo leer el archivo .env: %w", err)
	}

	envMap, err := godotenv.Unmarshal(string(envBytes))
	if err != nil {
		return fmt.Errorf("no se pudo interpretar el archivo .env: %w", err)
	}

	if _, ok := envMap[name+"_key"]; ok {
		return fmt.Errorf("el archivo .env ya tiene credenciales para %s", name)
	}

	return nil
}

func persistTarget(name, apiKey, apiSecret, baseURL, targetType string) error {
	const (
		envPath        = ".env"
		targetListPath = "targetlist"
	)

	envOriginal, envExists, err := readFileIfExists(envPath)
	if err != nil {
		return err
	}

	targetOriginal, _, err := readFileIfExists(targetListPath)
	if err != nil {
		return err
	}

	envContent := appendLines(string(envOriginal), []string{
		fmt.Sprintf("%s_key=%s", name, apiKey),
		fmt.Sprintf("%s_secret=%s", name, apiSecret),
		fmt.Sprintf("%s_url=%s", name, baseURL),
		fmt.Sprintf("%s_type=%s", name, targetType),
	})

	targetContent := appendLines(string(targetOriginal), []string{name})

	envMode := fileModeOrDefault(envPath, 0o600)
	targetMode := fileModeOrDefault(targetListPath, 0o644)

	if err := os.WriteFile(envPath, []byte(envContent), envMode); err != nil {
		return fmt.Errorf("no se pudo actualizar el archivo .env: %w", err)
	}

	if err := os.WriteFile(targetListPath, []byte(targetContent), targetMode); err != nil {
		if envExists {
			_ = os.WriteFile(envPath, envOriginal, envMode)
		} else {
			_ = os.Remove(envPath)
		}
		return fmt.Errorf("no se pudo actualizar la lista de targets: %w", err)
	}

	return nil
}

func appendLines(existing string, newLines []string) string {
	existing = strings.TrimRight(existing, "\n")
	var builder strings.Builder

	if existing != "" {
		builder.WriteString(existing)
		builder.WriteString("\n")
	}

	for i, line := range newLines {
		builder.WriteString(line)
		if i < len(newLines)-1 {
			builder.WriteString("\n")
		}
	}
	builder.WriteString("\n")

	return builder.String()
}

func readFileIfExists(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

func fileModeOrDefault(path string, defaultMode os.FileMode) os.FileMode {
	info, err := os.Stat(path)
	if err != nil {
		return defaultMode
	}
	return info.Mode()
}
