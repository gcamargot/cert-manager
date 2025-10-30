package cmd

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type csrfToken struct {
	Key   string
	Value string
}

func (t csrfToken) valid() bool {
	return strings.TrimSpace(t.Key) != "" && strings.TrimSpace(t.Value) != ""
}

var (
	setSSLCmd = &cobra.Command{
		Use:   "set-ssl",
		Short: "Configura el certificado que utiliza el WebGUI de un target",
		RunE:  runSetSSL,
	}

	setSSLTarget   string
	setSSLCertName string
	setSSLUser     string
	setSSLPassword string
	setSSLUseGUI   bool
)

func init() {
	rootCmd.AddCommand(setSSLCmd)

	setSSLCmd.Flags().StringVarP(&setSSLTarget, "target", "t", "", "Nombre del target configurado (OPNsense)")
	setSSLCmd.Flags().StringVarP(&setSSLCertName, "cert", "c", "", "Nombre del certificado (columna Certificate) o UUID")
	setSSLCmd.Flags().StringVarP(&setSSLUser, "username", "u", "", "Usuario del WebGUI")
	setSSLCmd.Flags().StringVarP(&setSSLPassword, "password", "p", "", "Contraseña del WebGUI (no recomendado en plano)")
	setSSLCmd.Flags().BoolVar(&setSSLUseGUI, "gui", false, "Usar simulación de GUI en lugar de modificación directa de XML")

	setSSLCmd.MarkFlagRequired("target")
}

func runSetSSL(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	target, ok := findTargetByName(strings.TrimSpace(setSSLTarget))
	if !ok {
		return fmt.Errorf("el target %s no existe", setSSLTarget)
	}

	if strings.ToLower(strings.TrimSpace(target.targetType)) != "opnsense" {
		return fmt.Errorf("el comando set-ssl solo está disponible para targets de tipo OPNsense")
	}

	username := strings.TrimSpace(setSSLUser)
	if username == "" {
		var err error
		username, err = promptLine("Usuario WebGUI: ")
		if err != nil {
			return err
		}
		username = strings.TrimSpace(username)
		if username == "" {
			return fmt.Errorf("el usuario no puede ser vacío")
		}
	}

	password := setSSLPassword
	if password == "" {
		var err error
		password, err = promptPassword("Contraseña WebGUI: ")
		if err != nil {
			return err
		}
		if password == "" {
			return fmt.Errorf("la contraseña no puede ser vacía")
		}
	}

	certs, err := fetchCertificatesForTarget(ctx, target)
	if err != nil {
		return fmt.Errorf("no se pudieron obtener los certificados: %w", err)
	}
	if len(certs) == 0 {
		return fmt.Errorf("el target %s no tiene certificados disponibles", target.name)
	}

	selected, err := selectCertificate(certs, setSSLCertName)
	if err != nil {
		return err
	}

	if strings.TrimSpace(selected.ID) == "" {
		return fmt.Errorf("el certificado seleccionado no expone un UUID o refid válido")
	}

	if verbose {
		fmt.Printf("[set-ssl] Certificado seleccionado: %s (ID: %s)\n", selected.Name, selected.ID)
	}

	baseURL, err := normalizeBaseURL(target.url)
	if err != nil {
		return err
	}

	session, csrfToken, err := loginOPNsenseGUI(baseURL, username, password)
	if err != nil {
		return err
	}

	if setSSLUseGUI {
		if verbose {
			fmt.Println("[set-ssl] Usando simulación de GUI para configurar certificado")
		}
		return setSSLCertificateViaGUI(session, baseURL, csrfToken, selected.ID, selected.Name)
	}

	// Método original: modificación directa de XML
	// Intentar descargar con POST primero
	if verbose {
		fmt.Println("[set-ssl] Intentando descarga con POST: https://" + strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://") + "/diag_backup.php")
	}
	configXML, err := downloadOPNsenseConfigPOST(session, baseURL, csrfToken)
	if err != nil {
		if verbose {
			fmt.Printf("[set-ssl] POST falló: %v, intentando GET...\n", err)
		}
		// Fallback a GET
		configXML, err = downloadOPNsenseConfig(session, baseURL)
		if err != nil {
			return fmt.Errorf("no se pudo descargar la configuración: %w", err)
		}
	}

	if verbose {
		currentCertID := extractCurrentCertID(configXML)
		if currentCertID != "" {
			fmt.Printf("[set-ssl] Certificado actual en XML: %s\n", currentCertID)
		} else {
			fmt.Println("[set-ssl] No se encontró certificado actual en XML")
		}
	}

	modifiedXML, err := setWebGUICertificate(configXML, selected.ID)
	if err != nil {
		return err
	}

	if verbose {
		fmt.Printf("[set-ssl] XML modificado (%d bytes -> %d bytes)\n", len(configXML), len(modifiedXML))
		// Buscar el ssl-certref en el XML modificado
		certIDInXML := extractCurrentCertID(modifiedXML)
		if certIDInXML != "" {
			fmt.Printf("[set-ssl] Certificado en XML modificado: %s\n", certIDInXML)
		}
	}

	if bytes.Equal(configXML, modifiedXML) {
		fmt.Println("El WebGUI ya utiliza el certificado seleccionado. No se realizaron cambios.")
		return nil
	}

	// Validar que el XML modificado es válido (básico)
	// El XML puede comenzar con <?xml o directamente con <opnsense
	xmlStr := string(modifiedXML)
	if !strings.HasPrefix(xmlStr, "<?xml") && !strings.Contains(xmlStr, "<opnsense") {
		if verbose {
			fmt.Printf("[set-ssl] XML modificado (primeros 200 bytes): %s\n", string(modifiedXML[:min(200, len(modifiedXML))]))
		}
		return fmt.Errorf("el XML modificado no parece ser válido")
	}

	if verbose {
		fmt.Printf("[set-ssl] XML validado, tamaño: %d bytes\n", len(modifiedXML))
	}

	if err := uploadConfigViaDiagBackup(session, baseURL, modifiedXML, csrfToken); err != nil {
		return fmt.Errorf("no se pudo restaurar la configuración: %w", err)
	}

	if verbose {
		fmt.Println("[set-ssl] Esperando unos segundos para que OPNsense procese la configuración...")
	}
	time.Sleep(5 * time.Second)

	// Verificar que el cambio se aplicó correctamente
	verifyConfigXML, err := downloadOPNsenseConfig(session, baseURL)
	if err != nil {
		if verbose {
			fmt.Printf("[set-ssl] No se pudo verificar la configuración: %v\n", err)
		}
		fmt.Printf("Certificado \"%s\" (%s) aplicado. El WebGUI se reiniciará automáticamente.\n", selected.Name, selected.ID)
		fmt.Println("ADVERTENCIA: No se pudo verificar que el cambio se aplicó correctamente.")
		return nil
	}

	currentCertID := extractCurrentCertID(verifyConfigXML)
	if strings.EqualFold(currentCertID, selected.ID) {
		if verbose {
			fmt.Printf("[set-ssl] Verificación exitosa: certificado actual es %s\n", currentCertID)
		}
		fmt.Printf("Certificado \"%s\" (%s) aplicado correctamente. El WebGUI se reiniciará automáticamente.\n", selected.Name, selected.ID)
	} else {
		fmt.Printf("Certificado \"%s\" (%s) aplicado. El WebGUI se reiniciará automáticamente.\n", selected.Name, selected.ID)
		fmt.Printf("ADVERTENCIA: Verificación falló. Certificado esperado: %s, encontrado: %s\n", selected.ID, currentCertID)
	}
	return nil
}

func selectCertificate(list []certificateSummary, wanted string) (certificateSummary, error) {
	wanted = strings.TrimSpace(wanted)
	if wanted != "" {
		for _, cert := range list {
			if strings.EqualFold(cert.Name, wanted) || strings.EqualFold(cert.ID, wanted) {
				return cert, nil
			}
		}
		return certificateSummary{}, fmt.Errorf("no se encontró el certificado %s en el target", wanted)
	}

	if verbose {
		fmt.Printf("[set-ssl] %d certificados disponibles\n", len(list))
	}

	fmt.Println("Seleccione el certificado a utilizar:")
	for i, cert := range list {
		fmt.Printf("[%d] %s\tCN=%s\tExpira=%s\n", i+1, nonEmpty(cert.Name), nonEmpty(cert.CommonName), nonEmpty(cert.Expiration))
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Ingrese el número del certificado: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return certificateSummary{}, err
		}
		line = strings.TrimSpace(line)
		index, err := strconv.Atoi(line)
		if err != nil || index < 1 || index > len(list) {
			fmt.Println("Selección inválida, intente nuevamente.")
			continue
		}
		return list[index-1], nil
	}
}

func loginOPNsenseGUI(baseURL, username, password string) (*http.Client, csrfToken, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, csrfToken{}, fmt.Errorf("no se pudo crear cookiejar: %w", err)
	}

	client := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: legacyInsecureTLSConfig(),
		},
		Timeout: 30 * time.Second,
	}

	if verbose {
		fmt.Println("[set-ssl] Intentando login vía API de sesión")
	}
	if token, err := loginViaSessionAPI(client, baseURL, username, password); err == nil && token.valid() {
		if verbose {
			fmt.Println("[set-ssl] Login vía API exitoso")
		}
		return client, token, nil
	} else if err != nil && verbose {
		fmt.Printf("[set-ssl] Login vía API falló: %v\n", err)
	}

	loginURL := strings.TrimRight(baseURL, "/") + "/index.php"

	if verbose {
		fmt.Println("[set-ssl] Intentando login legacy con formulario")
	}
	loginResp, err := client.Get(loginURL)
	if err != nil {
		return nil, csrfToken{}, fmt.Errorf("no se pudo acceder a la página de login: %w", err)
	}
	body, err := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	if err != nil {
		return nil, csrfToken{}, fmt.Errorf("no se pudo leer la página de login: %w", err)
	}

	loginToken, err := extractCSRFToken(body)
	if err != nil {
		if fallback, fallbackErr := fetchCSRFTokenFromPath(client, baseURL, "/diag_backup.php"); fallbackErr == nil && fallback.valid() {
			loginToken = fallback
			if verbose {
				fmt.Println("[set-ssl] CSRF recuperado desde diag_backup")
			}
		} else {
			return nil, csrfToken{}, fmt.Errorf("no se pudo obtener el token CSRF para login: %w", err)
		}
	}

	form := url.Values{
		"login":       {"Login"},
		"usernamefld": {username},
		"passwordfld": {password},
	}
	if loginToken.valid() {
		form.Set(loginToken.Key, loginToken.Value)
	}

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, csrfToken{}, fmt.Errorf("no se pudo crear la petición de login: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", loginURL)

	postResp, err := client.Do(req)
	if err != nil {
		return nil, csrfToken{}, fmt.Errorf("no se pudo iniciar sesión: %w", err)
	}

	if verbose {
		fmt.Printf("[set-ssl] Login legacy respuesta %d\n", postResp.StatusCode)
	}

	var resp *http.Response = postResp

	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if verbose {
			fmt.Printf("[set-ssl] Redirección a %s\n", location)
		}
		if location != "" {
			redirectedURL := location
			if !strings.HasPrefix(redirectedURL, "http") {
				redirectedURL = strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(location, "/")
			}
			resp.Body.Close()
			redirectedResp, err := client.Get(redirectedURL)
			if err != nil {
				return nil, csrfToken{}, fmt.Errorf("no se pudo seguir redirección tras login: %w", err)
			}
			defer redirectedResp.Body.Close()
			resp = redirectedResp
		}
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		return nil, csrfToken{}, fmt.Errorf("login respondió con estado %d", resp.StatusCode)
	}

	token, err := fetchCSRFTokenFromPath(client, baseURL, "/diag_backup.php")
	if err != nil {
		return nil, csrfToken{}, fmt.Errorf("no se pudo obtener token CSRF: %w", err)
	}
	if !token.valid() {
		return nil, csrfToken{}, fmt.Errorf("no se pudo validar la sesión, token CSRF vacío")
	}

	if verbose {
		fmt.Println("[set-ssl] Login legacy exitoso")
	}
	return client, token, nil
}

func loginViaSessionAPI(client *http.Client, baseURL, username, password string) (csrfToken, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/api/core/session/login"
	payload := map[string]string{
		"username": username,
		"password": password,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return csrfToken{}, err
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return csrfToken{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return csrfToken{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if verbose && resp.StatusCode == http.StatusNotFound {
			fmt.Println("[set-ssl] API de sesión no disponible (404)")
		}
		return csrfToken{}, fmt.Errorf("estado %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return csrfToken{}, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return csrfToken{}, err
	}

	if status, ok := result["status"].(string); ok && strings.ToLower(status) != "ok" {
		if verbose {
			fmt.Printf("[set-ssl] API login rechazó la sesión: %s\n", status)
		}
		return csrfToken{}, fmt.Errorf("login API rechazado: %s", status)
	}

	if csrf, ok := result["csrf"].(string); ok && strings.TrimSpace(csrf) != "" {
		return csrfToken{Key: "__csrf_magic", Value: csrf}, nil
	}
	token, err := fetchCSRFTokenFromPath(client, baseURL, "/diag_backup.php")
	if err != nil {
		return csrfToken{}, err
	}
	return token, nil
}

func downloadOPNsenseConfig(client *http.Client, baseURL string) ([]byte, error) {
	downloadURL := strings.TrimRight(baseURL, "/") + "/diag_backup.php?download=1"
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/xml, text/xml, */*")
	req.Header.Set("Referer", strings.TrimRight(baseURL, "/")+"/diag_backup.php")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("descarga devuelta con estado %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if verbose {
		fmt.Printf("[set-ssl] Config descargada (%d bytes)\n", len(data))
		if len(data) > 0 {
			contentType := resp.Header.Get("Content-Type")
			fmt.Printf("[set-ssl] Content-Type: %s\n", contentType)
			// Verificar si es HTML o XML
			if strings.Contains(strings.ToLower(contentType), "html") || bytes.HasPrefix(data, []byte("<!doctype")) || bytes.HasPrefix(data, []byte("<html")) {
				fmt.Printf("[set-ssl] ADVERTENCIA: La descarga devolvió HTML en lugar de XML (primeros 200 bytes): %s\n", string(data[:min(200, len(data))]))
				return nil, fmt.Errorf("la descarga devolvió HTML en lugar de XML. La sesión puede haber expirado o la autenticación falló")
			}
		}
	}

	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("no se pudo descomprimir el backup: %w", err)
		}
		defer gr.Close()
		return io.ReadAll(gr)
	}

	return data, nil
}

func downloadOPNsenseConfigPOST(client *http.Client, baseURL string, token csrfToken) ([]byte, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Agregar campos del formulario como lo hace el navegador
	if token.valid() {
		if err := writer.WriteField(token.Key, token.Value); err != nil {
			return nil, err
		}
	}
	if err := writer.WriteField("download", "1"); err != nil {
		return nil, err
	}
	if err := writer.WriteField("backupcount", "1"); err != nil {
		return nil, err
	}
	if err := writer.WriteField("donotbackuprrd", "1"); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", strings.TrimRight(baseURL, "/")+"/diag_backup.php", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Accept", "application/xml, text/xml, */*")
	req.Header.Set("Referer", strings.TrimRight(baseURL, "/")+"/diag_backup.php")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("descarga POST devuelta con estado %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if verbose {
		fmt.Printf("[set-ssl] Config descargada vía POST (%d bytes)\n", len(data))
		contentType := resp.Header.Get("Content-Type")
		fmt.Printf("[set-ssl] Content-Type: %s\n", contentType)
		// Verificar si es HTML o XML
		if strings.Contains(strings.ToLower(contentType), "html") || bytes.HasPrefix(data, []byte("<!doctype")) || bytes.HasPrefix(data, []byte("<html")) {
			return nil, fmt.Errorf("la descarga POST devolvió HTML en lugar de XML")
		}
	}

	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("no se pudo descomprimir el backup: %w", err)
		}
		defer gr.Close()
		return io.ReadAll(gr)
	}

	return data, nil
}

func setWebGUICertificate(configXML []byte, certID string) ([]byte, error) {
	if verbose {
		fmt.Println("[set-ssl] Actualizando nodo ssl-certref")
	}
	re := regexp.MustCompile(`(?i)(?s)<\s*ssl-certref\s*>\s*[^<]*?\s*</\s*ssl-certref\s*>`)
	replacement := []byte(fmt.Sprintf("<ssl-certref>%s</ssl-certref>", certID))

	if re.Match(configXML) {
		if verbose {
			fmt.Printf("[set-ssl] Reemplazando certificado existente con %s\n", certID)
		}
		return re.ReplaceAll(configXML, replacement), nil
	}

	if verbose {
		fmt.Println("[set-ssl] No se encontró ssl-certref existente, insertando nuevo")
	}

	// Buscar <webgui> de manera case-insensitive
	webguiRe := regexp.MustCompile(`(?i)(?s)<\s*webgui\s*>`)
	matches := webguiRe.FindIndex(configXML)
	if matches != nil {
		start := matches[0]
		closeWebguiRe := regexp.MustCompile(`(?i)(?s)</\s*webgui\s*>`)
		closeMatches := closeWebguiRe.FindIndex(configXML[start:])
		if closeMatches != nil {
			end := start + closeMatches[0]
			insertPos := start + bytes.Index(configXML[start:], []byte(">"))
			if insertPos > start {
				insertPos++
				// Detectar indentación
				lineStart := bytes.LastIndex(configXML[:insertPos], []byte("\n"))
				if lineStart == -1 {
					lineStart = 0
				} else {
					lineStart++
				}
				indent := configXML[lineStart:insertPos]
				indentStr := string(indent)
				
				var buffer bytes.Buffer
				buffer.Write(configXML[:end])
				buffer.WriteString("\n")
				buffer.WriteString(indentStr)
				buffer.Write(replacement)
				buffer.Write(configXML[end:])
				return buffer.Bytes(), nil
			}
		}
	}

	// Buscar <system> si no encontramos <webgui>
	systemRe := regexp.MustCompile(`(?i)(?s)<\s*system\s*>`)
	systemMatches := systemRe.FindIndex(configXML)
	if systemMatches != nil {
		start := systemMatches[0]
		closeSystemRe := regexp.MustCompile(`(?i)(?s)</\s*system\s*>`)
		closeMatches := closeSystemRe.FindIndex(configXML[start:])
		if closeMatches != nil {
			end := start + closeMatches[0]
			insertPos := start + bytes.Index(configXML[start:], []byte(">"))
			if insertPos > start {
				insertPos++
				lineStart := bytes.LastIndex(configXML[:insertPos], []byte("\n"))
				if lineStart == -1 {
					lineStart = 0
				} else {
					lineStart++
				}
				indent := configXML[lineStart:insertPos]
				indentStr := string(indent)
				
				var buffer bytes.Buffer
				buffer.Write(configXML[:end])
				buffer.WriteString("\n")
				buffer.WriteString(indentStr)
				buffer.WriteString("  <webgui>\n")
				buffer.WriteString(indentStr)
				buffer.WriteString("    ")
				buffer.Write(replacement)
				buffer.WriteString("\n")
				buffer.WriteString(indentStr)
				buffer.WriteString("  </webgui>\n")
				buffer.Write(configXML[end:])
				return buffer.Bytes(), nil
			}
		}
	}

	// Buscar </opnsense> como último recurso
	opnsenseRe := regexp.MustCompile(`(?i)(?s)</\s*opnsense\s*>`)
	opnsenseMatches := opnsenseRe.FindIndex(configXML)
	if opnsenseMatches != nil {
		insertPos := opnsenseMatches[0]
		lineStart := bytes.LastIndex(configXML[:insertPos], []byte("\n"))
		if lineStart == -1 {
			lineStart = 0
		} else {
			lineStart++
		}
		indent := configXML[lineStart:insertPos]
		indentStr := string(indent)
		
		var buffer bytes.Buffer
		buffer.Write(configXML[:insertPos])
		buffer.WriteString("\n")
		buffer.WriteString(indentStr)
		buffer.WriteString("  <system>\n")
		buffer.WriteString(indentStr)
		buffer.WriteString("    <webgui>\n")
		buffer.WriteString(indentStr)
		buffer.WriteString("      ")
		buffer.Write(replacement)
		buffer.WriteString("\n")
		buffer.WriteString(indentStr)
		buffer.WriteString("    </webgui>\n")
		buffer.WriteString(indentStr)
		buffer.WriteString("  </system>\n")
		buffer.Write(configXML[insertPos:])
		return buffer.Bytes(), nil
	}

	// Si no encontramos nada, agregar al final
	var buffer bytes.Buffer
	buffer.Write(configXML)
	if !bytes.HasSuffix(configXML, []byte("\n")) {
		buffer.WriteByte('\n')
	}
	buffer.WriteString("  <system>\n")
	buffer.WriteString("    <webgui>\n")
	buffer.WriteString("      ")
	buffer.Write(replacement)
	buffer.WriteString("\n")
	buffer.WriteString("    </webgui>\n")
	buffer.WriteString("  </system>\n")
	return buffer.Bytes(), nil
}

func uploadConfigViaDiagBackup(client *http.Client, baseURL string, xml []byte, token csrfToken) error {
	csrf := token
	if !csrf.valid() {
		var err error
		csrf, err = fetchCSRFTokenFromPath(client, baseURL, "/diag_backup.php")
		if err != nil {
			return err
		}
		if !csrf.valid() {
			return fmt.Errorf("no se pudo obtener el token CSRF antes de restaurar la configuración")
		}
	}

	if verbose {
		fmt.Printf("[set-ssl] Usando token CSRF %s para diag_backup\n", csrf.Key)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	if verbose {
		fmt.Printf("[set-ssl] Restaurando config con token %s\n", csrf.Key)
	}
	if err := writer.WriteField(csrf.Key, csrf.Value); err != nil {
		return err
	}
	if err := writer.WriteField("restore", "1"); err != nil {
		return err
	}
	if err := writer.WriteField("rebootafterrestore", "1"); err != nil {
		return err
	}
	if err := writer.WriteField("keepconsole", "1"); err != nil {
		return err
	}
	if err := writer.WriteField("flush_history", "1"); err != nil {
		return err
	}

	fileWriter, err := writer.CreateFormFile("conffile", "config.xml")
	if err != nil {
		return err
	}
	if _, err := fileWriter.Write(xml); err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest("POST", strings.TrimRight(baseURL, "/")+"/diag_backup.php", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	if verbose {
		fmt.Println("[set-ssl] Enviando configuración a diag_backup.php")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		if verbose {
			fmt.Printf("[set-ssl] Restauración respondió %d\n", resp.StatusCode)
			fmt.Printf("[set-ssl] Contenido: %s\n", strings.TrimSpace(string(respBody)))
		}
		return fmt.Errorf("la restauración retornó estado %d", resp.StatusCode)
	}

	if verbose {
		fmt.Printf("[set-ssl] Respuesta de restauración (%d bytes)\n", len(respBody))
		// Buscar mensajes de éxito o error en la respuesta
		if strings.Contains(string(respBody), "alert-success") {
			fmt.Println("[set-ssl] Encontrado mensaje de éxito en respuesta")
		}
		if strings.Contains(string(respBody), "alert-danger") {
			fmt.Println("[set-ssl] Encontrado mensaje de error en respuesta")
		}
	}

	// Verificar si hay errores solo si contiene alert-danger explícitamente en un div
	// Buscar patrón específico: <div class="alert alert-danger"> o similar
	alertDangerRe := regexp.MustCompile(`(?i)(?s)<div[^>]*class=['"][^'"]*alert[^'"]*danger[^'"]*['"][^>]*>(.*?)</div>`)
	alertDangerMatches := alertDangerRe.FindSubmatch(respBody)
	hasAlertDanger := len(alertDangerMatches) > 0
	
	// Extraer el mensaje si hay alert-danger
	var dangerMsg string
	if hasAlertDanger && len(alertDangerMatches) > 1 {
		dangerMsg = strings.TrimSpace(string(alertDangerMatches[1]))
		// Limpiar HTML del mensaje
		dangerMsg = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(dangerMsg, " ")
		dangerMsg = regexp.MustCompile(`\s+`).ReplaceAllString(dangerMsg, " ")
		dangerMsg = strings.TrimSpace(dangerMsg)
	}
	
	hasAlertSuccess := bytes.Contains(respBody, []byte("alert-success")) || bytes.Contains(respBody, []byte("Configuration restored")) || bytes.Contains(respBody, []byte("configuration has been restored"))
	
	// Solo fallar si hay un mensaje de error claro y no hay éxito
	if hasAlertDanger && !hasAlertSuccess && dangerMsg != "" && len(dangerMsg) > 10 {
		if verbose {
			fmt.Printf("[set-ssl] OPNsense rechazó la restauración: %s\n", dangerMsg)
		}
		return fmt.Errorf("OPNsense rechazó la restauración: %s", dangerMsg)
	}
	
	// Si no hay alert-danger claro, considerar como exitoso (OPNsense muestra la página normal después de restaurar)
	if verbose && !hasAlertSuccess {
		fmt.Println("[set-ssl] Restauración aparentemente exitosa (sin errores detectados)")
	}

	if verbose {
		if bytes.Contains(respBody, []byte("alert-success")) || bytes.Contains(respBody, []byte("Configuration restored")) || bytes.Contains(respBody, []byte("configuration has been restored")) {
			fmt.Println("[set-ssl] Restauración exitosa según respuesta de OPNsense")
		}
		fmt.Printf("[set-ssl] Primeros 500 bytes de respuesta: %s\n", string(respBody[:min(500, len(respBody))]))
	}

	return nil
}

func extractCurrentCertID(configXML []byte) string {
	re := regexp.MustCompile(`(?i)(?s)<\s*ssl-certref\s*>\s*([^<]+?)\s*</\s*ssl-certref\s*>`)
	matches := re.FindSubmatch(configXML)
	if len(matches) >= 2 {
		return strings.TrimSpace(string(matches[1]))
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fetchCSRFTokenFromPath(client *http.Client, baseURL, path string) (csrfToken, error) {
	fullURL := strings.TrimRight(baseURL, "/") + ensureLeadingSlash(path)
	resp, err := client.Get(fullURL)
	if err != nil {
		return csrfToken{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return csrfToken{}, fmt.Errorf("estado inesperado al obtener CSRF (%d) en %s", resp.StatusCode, path)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return csrfToken{}, err
	}
	if verbose && strings.Contains(path, "diag_command") {
		snippet := body
		if len(snippet) > 1200 {
			snippet = snippet[:1200]
		}
		fmt.Printf("[set-ssl] diag_command HTML preview:\\n%s\\n", snippet)
	}
	return extractCSRFToken(body)
}

func extractCSRFToken(html []byte) (csrfToken, error) {
	inputs := regexp.MustCompile(`(?is)<input[^>]+type=['"]hidden['"][^>]*>`).FindAll(html, -1)
	for _, input := range inputs {
		name := extractAttr(input, "name")
		value := extractAttr(input, "value")
		if name == "" || value == "" {
			continue
		}
		if strings.Contains(strings.ToLower(name), "csrf") || strings.HasPrefix(name, "__") {
			return csrfToken{Key: name, Value: value}, nil
		}
	}
	if len(inputs) > 0 {
		if name := extractAttr(inputs[0], "name"); name != "" {
			if value := extractAttr(inputs[0], "value"); value != "" {
				return csrfToken{Key: name, Value: value}, nil
			}
		}
	}
	scripts := regexp.MustCompile(`var\s+csrfMagicName\s*=\s*['"]([^'"]+)['"];\s*var\s+csrfMagicToken\s*=\s*['"]([^'"]+)['"]`).FindSubmatch(html)
	if len(scripts) == 3 {
		return csrfToken{Key: string(scripts[1]), Value: string(scripts[2])}, nil
	}
	return csrfToken{}, fmt.Errorf("no se encontró token CSRF en la respuesta del WebGUI")
}

func extractAttr(tag []byte, attr string) string {
	re := regexp.MustCompile(`(?i)` + attr + `\s*=\s*['"]([^'"]+)['"]`)
	match := re.FindSubmatch(tag)
	if len(match) >= 2 {
		return string(match[1])
	}
	return ""
}

func ensureLeadingSlash(path string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func extractAlertMessage(body []byte) string {
	re := regexp.MustCompile(`(?s)<div class="alert[^"]*">(.*?)</div>`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return "respuesta desconocida"
	}
	msg := regexp.MustCompile(`\s+`).ReplaceAllString(matches[1], " ")
	return strings.TrimSpace(msg)
}

func promptLine(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	disable := exec.Command("stty", "-echo")
	disable.Stdin = os.Stdin
	if err := disable.Run(); err != nil {
		return "", fmt.Errorf("no se pudo desactivar eco del terminal: %w", err)
	}
	defer func() {
		enable := exec.Command("stty", "echo")
		enable.Stdin = os.Stdin
		_ = enable.Run()
	}()

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
