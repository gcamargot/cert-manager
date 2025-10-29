package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	updateCertificateCmd = &cobra.Command{
		Use:   "certificate",
		Short: "Actualiza un certificado registrado localmente",
		RunE:  runUpdateCertificate,
	}

	updateCertificateName    string
	updateCertificateFile    string
	updateCertificateKeyFile string
	updateCertificateCountry string
)

func init() {
	updateCmd.AddCommand(updateCertificateCmd)

	updateCertificateCmd.Flags().StringVarP(&updateCertificateName, "name", "n", "", "Alias del certificado registrado")
	updateCertificateCmd.Flags().StringVarP(&updateCertificateFile, "cert", "c", "", "Nuevo certificado en formato PEM")
	updateCertificateCmd.Flags().StringVarP(&updateCertificateKeyFile, "key", "k", "", "Nueva clave privada (opcional)")
	updateCertificateCmd.Flags().StringVar(&updateCertificateCountry, "country", "", "Código de país si el certificado no lo provee")

	cobra.CheckErr(updateCertificateCmd.MarkFlagRequired("name"))
	cobra.CheckErr(updateCertificateCmd.MarkFlagRequired("cert"))
}

func runUpdateCertificate(cmd *cobra.Command, args []string) error {
	alias := strings.TrimSpace(updateCertificateName)
	if alias == "" {
		return fmt.Errorf("el nombre del certificado es obligatorio")
	}

	store, err := loadStoredCertificates()
	if err != nil {
		return err
	}

	var (
		record   storedCertificate
		foundKey string
	)

	for key, value := range store {
		if strings.EqualFold(key, alias) {
			record = value
			foundKey = key
			break
		}
	}

	if foundKey == "" {
		return fmt.Errorf("no se encontró un certificado registrado con el nombre %s", alias)
	}

	certPath, err := resolveFilePath(updateCertificateFile)
	if err != nil {
		return err
	}
	absCertPath, err := filepath.Abs(certPath)
	if err != nil {
		absCertPath = certPath
	}

	certData, err := os.ReadFile(absCertPath)
	if err != nil {
		return fmt.Errorf("no se pudo leer el certificado nuevo %s: %w", absCertPath, err)
	}

	_, _, info, _, err := parseCertificatePEM(certData)
	if err != nil {
		return fmt.Errorf("no se pudo interpretar el certificado nuevo: %w", err)
	}

	var absKeyPath string
	if strings.TrimSpace(updateCertificateKeyFile) != "" {
		keyPath, err := resolveFilePath(updateCertificateKeyFile)
		if err != nil {
			return err
		}
		if absKeyPath, err = filepath.Abs(keyPath); err != nil {
			absKeyPath = keyPath
		}
	}

	if err := backupStoredCertificate(record); err != nil {
		return err
	}

	country := deriveCertificateCountry(updateCertificateCountry, info)
	if strings.TrimSpace(country) == "" {
		return fmt.Errorf("el certificado no especifica el país; utilice --country")
	}

	destCertPath, err := certificatePemPath(record.Name)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(destCertPath), 0o700); err != nil {
		return fmt.Errorf("no se pudo crear el directorio destino: %w", err)
	}

	if err := os.WriteFile(destCertPath, certData, 0o600); err != nil {
		return fmt.Errorf("no se pudo escribir el nuevo certificado: %w", err)
	}

	record.CertPath = destCertPath
	if absKeyPath != "" {
		record.KeyPath = absKeyPath
	}
	record.CommonName = info.CommonName
	record.ExpiresAt = formatExpiration(info.NotAfter)
	record.Country = strings.ToUpper(strings.TrimSpace(country))
	record.AddedAt = time.Now().UTC().Format(time.RFC3339)

	store[foundKey] = record
	return saveStoredCertificates(store)
}

func backupStoredCertificate(record storedCertificate) error {
	src := strings.TrimSpace(record.CertPath)
	if src == "" {
		return nil
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("no se pudo respaldar el certificado original: %w", err)
	}

	dir, err := certificateBackupDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("no se pudo crear el directorio de backups: %w", err)
	}

	expires := strings.TrimSpace(record.ExpiresAt)
	if expires == "" {
		expires = "UNKNOWN"
	}
	parsed, err := time.Parse("2006-01-02 15:04:05", expires)
	if err == nil {
		expires = parsed.Format("2006-01-02")
	}

	sanitized := strings.NewReplacer(" ", "_", ":", "-", "/", "-").Replace(expires)
	filename := fmt.Sprintf("%s_EXPIRED(%s).pem", safeFileName(record.Name), sanitized)
	dest := filepath.Join(dir, filename)

	if info, err := os.Stat(dest); err == nil && !info.IsDir() {
		existing, readErr := os.ReadFile(dest)
		if readErr == nil && bytes.Equal(existing, data) {
			return nil
		}
		dest = uniqueBackupPath(dest)
	}

	if err := os.Rename(src, dest); err != nil {
		if writeErr := os.WriteFile(dest, data, 0o600); writeErr != nil {
			return fmt.Errorf("no se pudo crear el backup: %w", writeErr)
		}
		if removeErr := os.Remove(src); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("no se pudo limpiar el certificado original: %w", removeErr)
		}
		return nil
	}

	return nil
}

func certificateBackupDir() (string, error) {
	path, err := certificateStorePath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "backups"), nil
}

func uniqueBackupPath(base string) string {
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return base
	}
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	for i := 1; i < 1000; i++ {
		candidate := fmt.Sprintf("%s_%d%s", name, i, ext)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	return fmt.Sprintf("%s_%d%s", name, time.Now().Unix(), ext)
}
