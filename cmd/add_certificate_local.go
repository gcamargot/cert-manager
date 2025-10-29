package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type storedCertificate struct {
	Name       string `json:"name"`
	CertPath   string `json:"certPath"`
	KeyPath    string `json:"keyPath,omitempty"`
	CommonName string `json:"commonName,omitempty"`
	ExpiresAt  string `json:"expiresAt,omitempty"`
	AddedAt    string `json:"addedAt"`
	Country    string `json:"country,omitempty"`
}

var addCertificateMetadataCmd = &cobra.Command{
	Use:   "certificate",
	Short: "Registra un certificado localmente para una futura carga",
	RunE:  runAddCertificateMetadata,
}

var (
	addMetadataCertFile string
	addMetadataKeyFile  string
	addMetadataName     string
	addMetadataCountry  string
)

func init() {
	addCmd.AddCommand(addCertificateMetadataCmd)

	addCertificateMetadataCmd.Flags().StringVarP(&addMetadataCertFile, "cert", "c", "", "Ruta al certificado (PEM)")
	addCertificateMetadataCmd.Flags().StringVarP(&addMetadataKeyFile, "key", "k", "", "Ruta a la clave privada (opcional)")
	addCertificateMetadataCmd.Flags().StringVarP(&addMetadataName, "name", "n", "", "Nombre único para identificar el certificado")
	addCertificateMetadataCmd.Flags().StringVar(&addMetadataCountry, "country", "", "Código de país asociado al certificado (ej: ES)")

	cobra.CheckErr(addCertificateMetadataCmd.MarkFlagRequired("cert"))
	cobra.CheckErr(addCertificateMetadataCmd.MarkFlagRequired("name"))
}

func runAddCertificateMetadata(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(addMetadataName)
	if name == "" {
		return fmt.Errorf("el nombre del certificado es obligatorio")
	}

	certPath, err := resolveFilePath(addMetadataCertFile)
	if err != nil {
		return err
	}
	absCertPath, err := filepath.Abs(certPath)
	if err != nil {
		absCertPath = certPath
	}

	var absKeyPath string
	if strings.TrimSpace(addMetadataKeyFile) != "" {
		keyPath, err := resolveFilePath(addMetadataKeyFile)
		if err != nil {
			return err
		}
		if absKeyPath, err = filepath.Abs(keyPath); err != nil {
			absKeyPath = keyPath
		}
	}

	info, err := extractCertificateInfo(absCertPath)
	if err != nil {
		return err
	}

	destCertPath, err := certificatePemPath(name)
	if err != nil {
		return err
	}

	if err := copyFileSecure(absCertPath, destCertPath); err != nil {
		return fmt.Errorf("no se pudo copiar el certificado a %s: %w", destCertPath, err)
	}
	absCertPath = destCertPath

	store, err := loadStoredCertificates()
	if err != nil {
		return err
	}

	lowerName := strings.ToLower(name)
	for existing := range store {
		if strings.ToLower(existing) == lowerName {
			return fmt.Errorf("ya existe un certificado registrado con el nombre %s", name)
		}
	}

	record := storedCertificate{
		Name:       name,
		CertPath:   absCertPath,
		KeyPath:    absKeyPath,
		CommonName: info.CommonName,
		ExpiresAt:  formatExpiration(info.NotAfter),
		AddedAt:    time.Now().UTC().Format(time.RFC3339),
		Country:    deriveCertificateCountry(addMetadataCountry, info),
	}

	if strings.TrimSpace(record.Country) == "" {
		return fmt.Errorf("debe especificar el país (--country) cuando el certificado no lo provee")
	}

	store[name] = record

	if err := saveStoredCertificates(store); err != nil {
		return err
	}

	fmt.Printf("Certificado %s registrado correctamente\n", name)
	return nil
}

func extractCertificateInfo(certPath string) (certificateInfo, error) {
	content, err := os.ReadFile(certPath)
	if err != nil {
		return certificateInfo{}, fmt.Errorf("no se pudo leer el certificado %s: %w", certPath, err)
	}

	_, _, info, _, err := parseCertificatePEM(content)
	if err != nil {
		return certificateInfo{}, err
	}
	return info, nil
}

func deriveCertificateCountry(flagValue string, info certificateInfo) string {
	flagValue = strings.TrimSpace(flagValue)
	if flagValue != "" {
		return strings.ToUpper(flagValue)
	}
	return strings.ToUpper(strings.TrimSpace(info.Country))
}

func loadStoredCertificates() (map[string]storedCertificate, error) {
	path, err := certificateStorePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]storedCertificate), nil
		}
		return nil, fmt.Errorf("no se pudo leer el almacén de certificados: %w", err)
	}

	var store map[string]storedCertificate
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("no se pudo interpretar el almacén de certificados: %w", err)
	}
	return store, nil
}

func saveStoredCertificates(store map[string]storedCertificate) error {
	path, err := certificateStorePath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("no se pudo crear el directorio %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("no se pudo serializar el almacén de certificados: %w", err)
	}

	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return fmt.Errorf("no se pudo escribir el archivo temporal: %w", err)
	}

	if err := os.Rename(temp, path); err != nil {
		return fmt.Errorf("no se pudo actualizar el almacén de certificados: %w", err)
	}
	return nil
}

func certificateStorePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no se pudo obtener el home del usuario: %w", err)
	}
	return filepath.Join(home, ".cert-manager", "certificates.json"), nil
}

func formatExpiration(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

func sortedStoredCertificates(store map[string]storedCertificate) []storedCertificate {
	names := make([]string, 0, len(store))
	for name := range store {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]storedCertificate, 0, len(names))
	for _, name := range names {
		result = append(result, store[name])
	}
	return result
}

func findStoredCertificate(name string) (storedCertificate, bool, error) {
	store, err := loadStoredCertificates()
	if err != nil {
		return storedCertificate{}, false, err
	}

	for key, record := range store {
		if strings.EqualFold(key, name) {
			return record, true, nil
		}
	}
	return storedCertificate{}, false, nil
}
