package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var listCertificatesCmd = &cobra.Command{
	Use:   "certificates",
	Short: "Lista los certificados registrados localmente",
	RunE:  runListCertificates,
}

func init() {
	listCmd.AddCommand(listCertificatesCmd)
}

func runListCertificates(cmd *cobra.Command, args []string) error {
	store, err := loadStoredCertificates()
	if err != nil {
		return err
	}

	if len(store) == 0 {
		fmt.Println("No hay certificados registrados.")
		return nil
	}

	records := sortedStoredCertificates(store)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Nombre\tCommonName\tPaís\tExpiración\tRuta del certificado\tEstado")

	for _, record := range records {
		info, err := extractCertificateInfo(record.CertPath)
		commonName := record.CommonName
		expiration := record.ExpiresAt
		status := "OK"
		country := strings.TrimSpace(record.Country)

		if err == nil {
			if info.CommonName != "" {
				commonName = info.CommonName
			}
			if !info.NotAfter.IsZero() {
				expiration = formatExpiration(info.NotAfter)
			}

			infoCountry := strings.ToUpper(strings.TrimSpace(info.Country))
			if infoCountry != "" {
				country = infoCountry
			}

			if record.CommonName != commonName || record.ExpiresAt != expiration || !strings.EqualFold(strings.TrimSpace(record.Country), country) {
				record.CommonName = commonName
				record.ExpiresAt = expiration
				record.Country = strings.ToUpper(strings.TrimSpace(country))
				store[record.Name] = record
			}
		} else {
			status = fmt.Sprintf("ERROR: %s", err)
		}

		if strings.TrimSpace(expiration) == "" {
			expiration = "-"
		}
		if strings.TrimSpace(commonName) == "" {
			commonName = "-"
		}
		country = strings.TrimSpace(record.Country)
		if country == "" {
			country = "-"
		}

		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			record.Name,
			commonName,
			country,
			expiration,
			record.CertPath,
			status,
		)
	}

	_ = w.Flush()

	return saveStoredCertificates(store)
}
