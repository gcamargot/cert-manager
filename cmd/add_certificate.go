package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type certificateInfo struct {
	CommonName         string
	Country            string
	State              string
	City               string
	Organization       string
	OrganizationalUnit string
	NotAfter           time.Time
}

var (
	uploadCertificateCmd = &cobra.Command{
		Use:   "certificate",
		Short: "Importa un certificado en uno o más targets",
		RunE:  runUploadCertificate,
	}

	uploadCertificateTargets    string
	uploadCertificateAlias      string
	uploadCertificateFile       string
	uploadCertificateKeyFile    string
	uploadCertificateName       string
	uploadCertificateType       string
	uploadCertificateCommonName string
	uploadCertificateCountry    string
	uploadCertificateOrg        string
	uploadCertificateOrgUnit    string
	uploadCertificateCity       string
	uploadCertificateState      string
)

func init() {
	uploadCmd.AddCommand(uploadCertificateCmd)

	uploadCertificateCmd.Flags().StringVarP(&uploadCertificateTargets, "target", "t", "", "Targets separados por coma")
	uploadCertificateCmd.Flags().StringVarP(&uploadCertificateAlias, "alias", "a", "", "Nombre del certificado registrado a reutilizar")
	uploadCertificateCmd.Flags().StringVarP(&uploadCertificateFile, "cert", "c", "", "Archivo principal del certificado (PEM)")
	uploadCertificateCmd.Flags().StringVarP(&uploadCertificateKeyFile, "key", "k", "", "Archivo de clave privada en caso de no estar embebida en el certificado")
	uploadCertificateCmd.Flags().StringVar(&uploadCertificateName, "name", "", "Descripción con la que se almacenará el certificado")
	uploadCertificateCmd.Flags().StringVar(&uploadCertificateType, "type", "server_cert", "Tipo de certificado en el target")
	uploadCertificateCmd.Flags().StringVar(&uploadCertificateCommonName, "common-name", "", "Common Name a registrar (si se omite se detectará del certificado)")

	// Datos opcionales para documentar el certificado (se envían si se completan)
	uploadCertificateCmd.Flags().StringVar(&uploadCertificateCountry, "country", "", "Código de país (opcional)")
	uploadCertificateCmd.Flags().StringVar(&uploadCertificateState, "state", "", "Provincia/Estado (opcional)")
	uploadCertificateCmd.Flags().StringVar(&uploadCertificateCity, "city", "", "Ciudad (opcional)")
	uploadCertificateCmd.Flags().StringVar(&uploadCertificateOrg, "organization", "", "Organización (opcional)")
	uploadCertificateCmd.Flags().StringVar(&uploadCertificateOrgUnit, "organizational-unit", "", "Unidad organizacional (opcional)")

	cobra.CheckErr(uploadCertificateCmd.MarkFlagRequired("target"))
}

func runUploadCertificate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	targets, err := resolveTargets(uploadCertificateTargets, false)
	if err != nil {
		return err
	}

	alias := strings.TrimSpace(uploadCertificateAlias)
	var certInput string
	var keyPath string
	switch {
	case alias != "":
		if strings.TrimSpace(uploadCertificateFile) != "" || strings.TrimSpace(uploadCertificateKeyFile) != "" {
			return fmt.Errorf("no se puede combinar --alias con rutas directas de certificado/clave")
		}

		record, ok, err := findStoredCertificate(alias)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no se encontró un certificado registrado con el nombre %s", alias)
		}

		certInput = record.CertPath
		if strings.TrimSpace(record.KeyPath) != "" {
			keyPath = record.KeyPath
		}
		if strings.TrimSpace(uploadCertificateName) == "" {
			uploadCertificateName = record.Name
		}
		if strings.TrimSpace(uploadCertificateCommonName) == "" && record.CommonName != "" {
			uploadCertificateCommonName = record.CommonName
		}
		if strings.TrimSpace(uploadCertificateCountry) == "" && record.Country != "" {
			uploadCertificateCountry = record.Country
		}
	default:
		certInput = uploadCertificateFile
		keyPath = uploadCertificateKeyFile
	}

	if strings.TrimSpace(certInput) == "" {
		return fmt.Errorf("debe especificar --cert o --alias")
	}

	certPath, err := resolveFilePath(certInput)
	if err != nil {
		return err
	}

	if strings.TrimSpace(keyPath) != "" {
		keyPath, err = resolveFilePath(keyPath)
		if err != nil {
			return err
		}
	}

	certPayload, keyPayload, metadata, keyType, err := loadCertificateMaterial(certPath, keyPath)
	if err != nil {
		return err
	}

	description := strings.TrimSpace(uploadCertificateName)
	if description == "" {
		description = fallbackCertificateDescription(certPath, metadata.CommonName)
	}

	commonName := strings.TrimSpace(uploadCertificateCommonName)
	if commonName == "" {
		commonName = metadata.CommonName
	}

	if commonName == "" {
		commonName = description
	}

	if keyType == "" {
		keyType = "2048"
	}

	request := buildOPNSenseCertPayload(certPayload, keyPayload, commonName, description, keyType)

	if uploadCertificateCountry != "" {
		request.Cert.Country = strings.ToUpper(strings.TrimSpace(uploadCertificateCountry))
	} else if metadata.Country != "" {
		request.Cert.Country = strings.ToUpper(strings.TrimSpace(metadata.Country))
	}
	if uploadCertificateState != "" {
		request.Cert.State = uploadCertificateState
	} else if metadata.State != "" {
		request.Cert.State = metadata.State
	}
	if uploadCertificateCity != "" {
		request.Cert.City = uploadCertificateCity
	} else if metadata.City != "" {
		request.Cert.City = metadata.City
	}
	if uploadCertificateOrg != "" {
		request.Cert.Organization = uploadCertificateOrg
	} else if metadata.Organization != "" {
		request.Cert.Organization = metadata.Organization
	}
	if uploadCertificateOrgUnit != "" {
		request.Cert.OrganizationalUnit = uploadCertificateOrgUnit
	} else if metadata.OrganizationalUnit != "" {
		request.Cert.OrganizationalUnit = metadata.OrganizationalUnit
	}

	request.Cert.CertType = strings.TrimSpace(uploadCertificateType)
	if request.Cert.CertType == "" {
		request.Cert.CertType = "server_cert"
	}

	if request.Cert.Country == "" {
		return fmt.Errorf("el certificado no especifica el país y OPNsense lo requiere; utilice --country para definirlo manualmente")
	}

	results := make([]string, 0, len(targets))
	var failures []string

	for _, target := range targets {
		if strings.ToLower(strings.TrimSpace(target.targetType)) != "opnsense" {
			failures = append(failures, fmt.Sprintf("%s: tipo %s no soportado", target.name, target.targetType))
			continue
		}

		if err := uploadCertificateToOPNSense(ctx, target, request); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", target.name, err))
		} else {
			results = append(results, target.name)
		}
	}

	if len(results) > 0 {
		fmt.Printf("Certificado importado correctamente en: %s\n", strings.Join(results, ", "))
	}

	if len(failures) > 0 {
		return fmt.Errorf("no se pudo importar el certificado en: %s", strings.Join(failures, "; "))
	}

	return nil
}

type opnsenseCertRequest struct {
	Cert opnsenseCertBody `json:"cert"`
}

type opnsenseCertBody struct {
	Action                string `json:"action"`
	Descr                 string `json:"descr"`
	CertType              string `json:"cert_type"`
	PrivateKeyLocation    string `json:"private_key_location"`
	KeyType               string `json:"key_type"`
	Digest                string `json:"digest"`
	Caref                 string `json:"caref"`
	Lifetime              string `json:"lifetime"`
	Country               string `json:"country"`
	State                 string `json:"state"`
	City                  string `json:"city"`
	Organization          string `json:"organization"`
	OrganizationalUnit    string `json:"organizationalunit"`
	Email                 string `json:"email"`
	CommonName            string `json:"commonname"`
	OCSPURI               string `json:"ocsp_uri"`
	AltNamesDNS           string `json:"altnames_dns"`
	AltNamesIP            string `json:"altnames_ip"`
	AltNamesURI           string `json:"altnames_uri"`
	AltNamesEmail         string `json:"altnames_email"`
	CertificatePayload    string `json:"crt_payload"`
	PrivateKeyPayload     string `json:"prv_payload"`
	CertificateReqPayload string `json:"csr_payload"`
}

func buildOPNSenseCertPayload(certPEM, keyPEM, commonName, description, keyType string) opnsenseCertRequest {
	request := opnsenseCertRequest{
		Cert: opnsenseCertBody{
			Action:                "import",
			Descr:                 description,
			CertType:              "server_cert",
			PrivateKeyLocation:    "firewall",
			KeyType:               keyType,
			Digest:                "sha256",
			Caref:                 "",
			Lifetime:              "397",
			Country:               "",
			State:                 "",
			City:                  "",
			Organization:          "",
			OrganizationalUnit:    "",
			Email:                 "",
			CommonName:            commonName,
			OCSPURI:               "",
			AltNamesDNS:           "",
			AltNamesIP:            "",
			AltNamesURI:           "",
			AltNamesEmail:         "",
			CertificatePayload:    certPEM,
			PrivateKeyPayload:     keyPEM,
			CertificateReqPayload: "",
		},
	}

	return request
}

func uploadCertificateToOPNSense(ctx context.Context, target Target, request opnsenseCertRequest) error {
	baseURL, err := normalizeBaseURL(target.url)
	if err != nil {
		return fmt.Errorf("URL inválida: %w", err)
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/api/trust/cert/add/"

	payload := new(bytes.Buffer)
	if err := json.NewEncoder(payload).Encode(request); err != nil {
		return fmt.Errorf("no se pudo serializar la petición: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, payload)
	if err != nil {
		return fmt.Errorf("no se pudo crear la petición: %w", err)
	}

	req.SetBasicAuth(target.key, target.secret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	if strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		client.Transport = insecureTLSTransport()
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("no se pudo enviar el certificado: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("respuesta %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var apiResp opnsenseCertResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &apiResp); err != nil {
			// Si la respuesta no es JSON válido, consideramos la operación como correcta.
			return nil
		}
	}

	if apiResp.Result != "" && strings.ToLower(apiResp.Result) != "saved" {
		msg := apiResp.Message
		if msg == "" {
			msg = "operación rechazada"
		}

		if len(apiResp.Validations) > 0 {
			msg = msg + " (" + apiResp.Validations.String() + ")"
		}
		return errors.New(msg)
	}

	return nil
}

type opnsenseCertResponse struct {
	Result      string        `json:"result"`
	Message     string        `json:"message"`
	UUID        string        `json:"uuid"`
	Validations validationBag `json:"validations"`
}

type validationBag map[string]interface{}

func (v validationBag) String() string {
	if len(v) == 0 {
		return ""
	}
	var parts []string
	for key, value := range v {
		switch typed := value.(type) {
		case string:
			parts = append(parts, fmt.Sprintf("%s: %s", key, typed))
		case []interface{}:
			values := make([]string, 0, len(typed))
			for _, item := range typed {
				values = append(values, fmt.Sprint(item))
			}
			parts = append(parts, fmt.Sprintf("%s: %s", key, strings.Join(values, ", ")))
		default:
			parts = append(parts, fmt.Sprintf("%s: %v", key, typed))
		}
	}
	return strings.Join(parts, "; ")
}

func insecureTLSTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: legacyInsecureTLSConfig(),
	}
}

func legacyInsecureTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // necesario para targets con certificados autofirmados
	}
}

func resolveFilePath(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("ruta vacía de certificado/clave")
	}

	expanded, err := expandUserPath(input)
	if err != nil {
		return "", err
	}

	candidates := []string{expanded}

	if !fileExists(expanded) {
		if home, err := os.UserHomeDir(); err == nil {
			defaultDir := filepath.Join(home, ".cert-manager")
			alt := filepath.Join(defaultDir, input)
			if alt != expanded {
				candidates = append(candidates, alt)
			}
		}
	}

	for _, candidate := range candidates {
		if fileExists(candidate) {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("no se encontró el archivo %s (buscado en %s)", input, strings.Join(candidates, ", "))
}

func expandUserPath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("no se pudo resolver el home del usuario: %w", err)
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~"))
	}
	return path, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func loadCertificateMaterial(certPath, keyPath string) (string, string, certificateInfo, string, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return "", "", certificateInfo{}, "", fmt.Errorf("no se pudo leer el certificado %s: %w", certPath, err)
	}

	certPEM, embeddedKey, info, keyType, err := parseCertificatePEM(certBytes)
	if err != nil {
		return "", "", certificateInfo{}, "", err
	}

	var keyPEM string
	if embeddedKey != "" {
		keyPEM = embeddedKey
	}

	if keyPEM == "" && keyPath != "" {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return "", "", certificateInfo{}, "", fmt.Errorf("no se pudo leer la clave privada %s: %w", keyPath, err)
		}
		keyPEM, keyType = extractPrivateKeyPEM(keyBytes)
		if keyPEM == "" {
			return "", "", certificateInfo{}, "", fmt.Errorf("el archivo %s no contiene una clave privada válida", keyPath)
		}
	}

	return certPEM, keyPEM, info, keyType, nil
}

func parseCertificatePEM(data []byte) (string, string, certificateInfo, string, error) {
	var certificates []*pem.Block
	var keyBlock *pem.Block
	var info certificateInfo
	var keyType string

	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			certificates = append(certificates, block)
			if info.CommonName == "" {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					info.CommonName = cert.Subject.CommonName
					info.Country = firstOrEmpty(cert.Subject.Country)
					info.State = firstOrEmpty(cert.Subject.Province)
					info.City = firstOrEmpty(cert.Subject.Locality)
					info.Organization = firstOrEmpty(cert.Subject.Organization)
					info.OrganizationalUnit = firstOrEmpty(cert.Subject.OrganizationalUnit)
					info.NotAfter = cert.NotAfter
					info.Country = strings.ToUpper(strings.TrimSpace(info.Country))
				}
			}
		default:
			if keyBlock == nil && isPrivateKeyBlock(block.Type) {
				keyBlock = block
				keyType = detectKeyType(block)
			}
		}
	}

	if len(certificates) == 0 {
		return "", "", certificateInfo{}, "", errors.New("el archivo de certificado no contiene bloques PEM de tipo CERTIFICATE")
	}

	var builder strings.Builder
	for _, block := range certificates {
		builder.Write(pem.EncodeToMemory(block))
	}

	keyPEM := ""
	if keyBlock != nil {
		keyPEM = string(pem.EncodeToMemory(keyBlock))
	}

	return builder.String(), keyPEM, info, keyType, nil
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func extractPrivateKeyPEM(data []byte) (string, string) {
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if isPrivateKeyBlock(block.Type) {
			return string(pem.EncodeToMemory(block)), detectKeyType(block)
		}
	}
	return "", ""
}

func isPrivateKeyBlock(blockType string) bool {
	switch strings.ToUpper(blockType) {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		return true
	default:
		return false
	}
}

func detectKeyType(block *pem.Block) string {
	if block == nil {
		return ""
	}

	parse := func() (interface{}, error) {
		switch strings.ToUpper(block.Type) {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		case "PRIVATE KEY":
			return x509.ParsePKCS8PrivateKey(block.Bytes)
		default:
			return x509.ParsePKCS8PrivateKey(block.Bytes)
		}
	}

	key, err := parse()
	if err != nil {
		return ""
	}

	switch typed := key.(type) {
	case *rsa.PrivateKey:
		return strconv.Itoa(typed.N.BitLen())
	case *ecdsa.PrivateKey:
		return strings.ToUpper(typed.Curve.Params().Name)
	default:
		return ""
	}
}

func fallbackCertificateDescription(certPath, commonName string) string {
	if commonName != "" {
		return commonName
	}
	base := filepath.Base(certPath)
	return strings.TrimSuffix(base, filepath.Ext(base))
}
