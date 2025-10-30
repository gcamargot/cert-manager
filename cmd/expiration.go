package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	certificateCmd = &cobra.Command{
		Use:   "certificate",
		Short: "Operaciones relacionadas con certificados",
	}

	expirationCmd = &cobra.Command{
		Use:   "expiration",
		Short: "Obtiene la fecha de expiración de los certificados por target",
		RunE:  runGetCertificateExpiration,
	}

	expirationTargetsRaw string
	expirationAllTargets bool
	expirationOutput     string
)

func init() {
	getCmd.AddCommand(certificateCmd)
	certificateCmd.AddCommand(expirationCmd)

	expirationCmd.Flags().StringVarP(&expirationTargetsRaw, "target", "t", "", "Lista de targets (separados por coma)")
	expirationCmd.Flags().BoolVarP(&expirationAllTargets, "all", "A", false, "Consultar todos los targets configurados")
	expirationCmd.Flags().StringVar(&expirationOutput, "output", "table", "Formato de salida (table|json)")
}

type certificateSummary struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Expiration string `json:"expiration,omitempty"`
	CommonName string `json:"commonName,omitempty"`
}

type targetCertificateResult struct {
	Target       string               `json:"target"`
	Certificates []certificateSummary `json:"certificates,omitempty"`
	Error        string               `json:"error,omitempty"`
}

func runGetCertificateExpiration(cmd *cobra.Command, args []string) error {
	if expirationAllTargets && expirationTargetsRaw != "" {
		return fmt.Errorf("no se puede combinar --all con --target")
	}

	selectedTargets, err := resolveTargets(expirationTargetsRaw, expirationAllTargets)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	results := make([]targetCertificateResult, 0, len(selectedTargets))

	for _, target := range selectedTargets {
		res := targetCertificateResult{Target: target.name}

		if strings.TrimSpace(target.targetType) == "" {
			res.Error = "el target no tiene tipo configurado"
			results = append(results, res)
			continue
		}

		certs, fetchErr := fetchCertificatesForTarget(ctx, target)
		if fetchErr != nil {
			res.Error = fetchErr.Error()
		} else {
			res.Certificates = certs
		}

		results = append(results, res)
	}

	switch strings.ToLower(expirationOutput) {
	case "", "table":
		renderCertificatesTable(results)
	case "json":
		if err := renderCertificatesJSON(results); err != nil {
			return err
		}
	default:
		return fmt.Errorf("formato de salida no soportado: %s", expirationOutput)
	}

	return nil
}

func resolveTargets(raw string, all bool) ([]Target, error) {
	if all {
		if len(TargetList) == 0 {
			return nil, errors.New("no hay targets configurados")
		}
		return append([]Target(nil), TargetList...), nil
	}

	names := splitAndClean(raw)
	if len(names) == 0 {
		return nil, fmt.Errorf("debe especificar al menos un target con --target o usar --all")
	}

	resolved := make([]Target, 0, len(names))
	seen := make(map[string]struct{})

	for _, name := range names {
		if _, duplicated := seen[strings.ToLower(name)]; duplicated {
			continue
		}

		target, ok := findTargetByName(name)
		if !ok {
			return nil, fmt.Errorf("el target %s no existe en la configuración", name)
		}

		resolved = append(resolved, target)
		seen[strings.ToLower(name)] = struct{}{}
	}

	return resolved, nil
}

func splitAndClean(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' '
	})

	cleaned := make([]string, 0, len(fields))
	for _, field := range fields {
		if value := strings.TrimSpace(field); value != "" {
			cleaned = append(cleaned, value)
		}
	}
	return cleaned
}

func findTargetByName(name string) (Target, bool) {
	for _, target := range TargetList {
		if strings.EqualFold(target.name, name) {
			return target, true
		}
	}
	return Target{}, false
}

func renderCertificatesTable(results []targetCertificateResult) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "Target\tCertificate\tExpiration\tCommonName")

	for _, result := range results {
		if result.Error != "" {
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", result.Target, "ERROR", "-", result.Error)
			continue
		}

		if len(result.Certificates) == 0 {
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", result.Target, "(sin certificados)", "-", "-")
			continue
		}

		for _, cert := range result.Certificates {
			fmt.Fprintf(
				writer,
				"%s\t%s\t%s\t%s\n",
				result.Target,
				nonEmpty(cert.Name),
				nonEmpty(cert.Expiration),
				nonEmpty(cert.CommonName),
			)
		}
	}

	_ = writer.Flush()
}

func renderCertificatesJSON(results []targetCertificateResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func nonEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func fetchCertificatesForTarget(ctx context.Context, target Target) ([]certificateSummary, error) {
	switch strings.ToLower(strings.TrimSpace(target.targetType)) {
	case "opnsense":
		return fetchOPNSenseCertificates(ctx, target)
	default:
		return nil, fmt.Errorf("tipo de target no soportado: %s", target.targetType)
	}
}

func fetchOPNSenseCertificates(ctx context.Context, target Target) ([]certificateSummary, error) {
	if strings.TrimSpace(target.url) == "" {
		return nil, fmt.Errorf("el target %s no tiene URL configurada", target.name)
	}
	if target.key == "" || target.secret == "" {
		return nil, fmt.Errorf("el target %s no tiene credenciales configuradas", target.name)
	}

	baseURL, err := normalizeBaseURL(target.url)
	if err != nil {
		return nil, fmt.Errorf("URL inválida para el target %s: %w", target.name, err)
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/api/trust/cert/search"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("no se pudo crear la petición: %w", err)
	}
	req.SetBasicAuth(target.key, target.secret)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	if strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // OPNsense típicamente usa certificados autofirmados
			},
		}
		client.Transport = transport
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("no se pudieron obtener los certificados: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("respuesta inesperada (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()

	var payload interface{}
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("no se pudo interpretar la respuesta: %w", err)
	}

	certificates := extractCertificatesFromPayload(payload)
	sortCertificates(certificates)

	return certificates, nil
}

func normalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("URL vacía")
	}

	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}

	if parsed.Host == "" {
		if parsed.Path != "" && !strings.Contains(parsed.Path, "/") {
			parsed.Host = parsed.Path
			parsed.Path = ""
		} else {
			return "", fmt.Errorf("no se pudo determinar el host en la URL %s", raw)
		}
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String(), nil
}

func extractCertificatesFromPayload(payload interface{}) []certificateSummary {
	switch data := payload.(type) {
	case map[string]interface{}:
		for _, key := range []string{"rows", "data", "certificates", "items"} {
			if value, ok := data[key]; ok {
				return extractCertificatesFromPayload(value)
			}
		}
		// Si no hay listas conocidas, intentamos tratar el mapa como un único certificado.
		if cert := buildCertificateFromMap(data); cert != nil {
			return []certificateSummary{*cert}
		}
	case []interface{}:
		results := make([]certificateSummary, 0, len(data))
		for _, item := range data {
			if cert := buildCertificateFromInterface(item); cert != nil {
				results = append(results, *cert)
			}
		}
		return results
	}
	return nil
}

func buildCertificateFromInterface(value interface{}) *certificateSummary {
	if value == nil {
		return nil
	}
	if m, ok := value.(map[string]interface{}); ok {
		return buildCertificateFromMap(m)
	}
	return nil
}

func buildCertificateFromMap(m map[string]interface{}) *certificateSummary {
	if len(m) == 0 {
		return nil
	}

	id := firstNonEmptyString(m, "refid", "uuid", "id")
	name := firstNonEmptyString(m, "descr", "description", "name", "certificate", "uuid", "id")
	commonName := firstNonEmptyString(m, "common_name", "commonName", "subject_cn", "subjectCN", "cn")
	if commonName == "" {
		if subject, ok := m["subject"].(map[string]interface{}); ok {
			commonName = firstNonEmptyString(subject, "CN", "commonName", "name")
		}
	}

	expiration := firstValidDate(m,
		"validTo", "valid_to", "validNotAfter", "valid_not_after", "validNotafter",
		"validUntil", "expiry", "expiration", "expires", "valid_to_ut", "validUntill",
	)

	if expiration == "" {
		if validity, ok := m["validity"].(map[string]interface{}); ok {
			expiration = firstValidDate(validity, "to", "validTo", "valid_to", "validNotAfter")
		}
	}

	if name == "" && commonName == "" && expiration == "" {
		return nil
	}

	return &certificateSummary{
		ID:         id,
		Name:       name,
		CommonName: commonName,
		Expiration: expiration,
	}
}

func firstNonEmptyString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := m[key]; ok {
			if str := normalizeToString(value); str != "" {
				return str
			}
			continue
		}
		if value, ok := lookupInsensitive(m, key); ok {
			if str := normalizeToString(value); str != "" {
				return str
			}
		}
	}
	return ""
}

func firstValidDate(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := m[key]; ok {
			if formatted := normalizeToDate(value); formatted != "" {
				return formatted
			}
			continue
		}
		if value, ok := lookupInsensitive(m, key); ok {
			if formatted := normalizeToDate(value); formatted != "" {
				return formatted
			}
		}
	}
	return ""
}

func lookupInsensitive(m map[string]interface{}, target string) (interface{}, bool) {
	target = strings.ToLower(target)
	for key, value := range m {
		if strings.ToLower(key) == target {
			return value, true
		}
	}
	return nil, false
}

func normalizeToString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func normalizeToDate(value interface{}) string {
	if value == nil {
		return ""
	}

	if timestamp, ok := numericAsTimestamp(value); ok {
		return timestamp.UTC().Format("2006-01-02 15:04:05")
	}

	str := normalizeToString(value)
	if str == "" {
		return ""
	}

	if ts, err := parseNumericTimestamp(str); err == nil {
		return ts.UTC().Format("2006-01-02 15:04:05")
	}

	if t, err := parseDateString(str); err == nil {
		return t.UTC().Format("2006-01-02 15:04:05")
	}

	return str
}

func numericAsTimestamp(value interface{}) (time.Time, bool) {
	switch typed := value.(type) {
	case json.Number:
		if i, err := typed.Int64(); err == nil {
			return unixTimestampFromInt(i)
		}
		if f, err := strconv.ParseFloat(typed.String(), 64); err == nil {
			return unixTimestampFromFloat(f)
		}
	case float64:
		return unixTimestampFromFloat(typed)
	case int64:
		return unixTimestampFromInt(typed)
	case int:
		return unixTimestampFromInt(int64(typed))
	}
	return time.Time{}, false
}

func unixTimestampFromInt(value int64) (time.Time, bool) {
	switch {
	case value > 1_000_000_000_000:
		return time.UnixMilli(value), true
	case value > 1_000_000_000:
		return time.Unix(value, 0), true
	default:
		return time.Time{}, false
	}
}

func unixTimestampFromFloat(value float64) (time.Time, bool) {
	if value > 1_000_000_000_000 {
		return time.UnixMilli(int64(value)), true
	}
	if value > 1_000_000_000 {
		return time.Unix(int64(value), 0), true
	}
	return time.Time{}, false
}

func parseDateString(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty date")
	}

	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z0700",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02",
		"Mon, 02 Jan 2006 15:04:05 MST",
		"02-01-2006",
		"01/02/2006",
		"2006/01/02",
	}

	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed, nil
		}
	}

	return time.Time{}, fmt.Errorf("unknown date format: %s", raw)
}

func parseNumericTimestamp(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty")
	}

	if strings.ContainsAny(raw, " ,.:/") {
		return time.Time{}, fmt.Errorf("not numeric")
	}

	if strings.Contains(raw, "e") || strings.Contains(raw, "E") {
		if f, err := strconv.ParseFloat(raw, 64); err == nil {
			if t, ok := unixTimestampFromFloat(f); ok {
				return t, nil
			}
		}
		return time.Time{}, fmt.Errorf("invalid float timestamp")
	}

	if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if t, ok := unixTimestampFromInt(i); ok {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid numeric timestamp")
}

func sortCertificates(certs []certificateSummary) {
	sort.SliceStable(certs, func(i, j int) bool {
		ti, errI := parseDateString(certs[i].Expiration)
		tj, errJ := parseDateString(certs[j].Expiration)

		if errI != nil && errJ != nil {
			return strings.Compare(certs[i].Name, certs[j].Name) < 0
		}
		if errI != nil {
			return false
		}
		if errJ != nil {
			return true
		}

		if ti.Equal(tj) {
			return strings.Compare(certs[i].Name, certs[j].Name) < 0
		}
		return ti.Before(tj)
	})
}
