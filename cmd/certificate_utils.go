package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func safeFileName(name string) string {
	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		" ", "_",
		":", "-",
		"\t", "-",
		"*", "-",
		"?", "-",
		"\"", "",
		"<", "-",
		">", "-",
		"|", "-",
	)
	return replacer.Replace(strings.TrimSpace(name))
}

func certificateDataDir() (string, error) {
	storePath, err := certificateStorePath()
	if err != nil {
		return "", err
	}
	return filepath.Dir(storePath), nil
}

func certificatePemPath(alias string) (string, error) {
	baseDir, err := certificateDataDir()
	if err != nil {
		return "", err
	}
	if alias == "" {
		return "", fmt.Errorf("alias vacío para calcular la ruta del certificado")
	}
	return filepath.Join(baseDir, safeFileName(alias)+".pem"), nil
}

func copyFileSecure(src, dest string) error {
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return fmt.Errorf("no se pudo resolver la ruta %s: %w", src, err)
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("no se pudo resolver la ruta %s: %w", dest, err)
	}

	if absSrc == absDest {
		return nil
	}

	data, err := os.ReadFile(absSrc)
	if err != nil {
		return fmt.Errorf("no se pudo leer %s: %w", src, err)
	}

	if err := os.MkdirAll(filepath.Dir(absDest), 0o700); err != nil {
		return fmt.Errorf("no se pudo crear el directorio destino: %w", err)
	}

	return os.WriteFile(absDest, data, 0o600)
}
