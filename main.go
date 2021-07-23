package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
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
		if len(req.URL.RawQuery) > 0 {
			qp = "?" + req.URL.RawQuery
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
		fmt.Println("\n")
		fmt.Println(string(body))
		req.Body.Close() //  must close
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		fmt.Println("-------------------------------------------------------------------------------------", Reset)

	}

}

func ServeFiles(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := CheckAuth(r)
		DumpReq(w, r, auth)
		if !auth {
			return
		}
		h.ServeHTTP(w, r) // call original

	})
}

func listURLs(addr, port string, ssl bool) {
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

func main() {

	port := flag.String("port", "8000", "Listen port")
	addr := flag.String("addr", "", "Listen address")
	dump := flag.Bool("dump", false, "dump full requests")
	workdir := flag.String("dir", "./", "Working directory")
	auth := flag.String("auth", "", "Enable basic auth (-auth user:password)")
	ssl := flag.Bool("ssl", false, "Enable TLS/SSL, requires -key and -cert")
	sslcrt := flag.String("cert", "", "Path to SSL .crt file")
	sslkey := flag.String("key", "", "Path to SSL .key file")

	flag.Parse()

	WorkDir = *workdir
	Dump = *dump

	if *ssl {
		if *sslcrt == "" || *sslkey == "" {
			fmt.Println(Red+"[ERROR] -cert and -key are required for SSL.", Reset)
			os.Exit(1)
		}
	}

	if *auth != "" {
		parts := strings.Split(*auth, ":")
		if len(parts) != 2 {
			fmt.Println(Red+"[ERROR] invalid auth string: must be 'user:password'", Reset)
			os.Exit(1)
		} else {
			DoAuth = true
			Username = parts[0]
			Password = parts[1]
		}
	}

	fmt.Println(Blue+"[!] Dump Requests:", *dump, Reset)
	fmt.Println(Blue+"[!] Auth Enabled:", DoAuth, Reset)
	fmt.Println(Blue+"[!] Working Directory:", *workdir, Reset)
	fmt.Println(Blue+"[!] SSL Enabled:", *ssl, Reset)
	listURLs(*addr, *port, *ssl)
	http.HandleFunc("/loot", DropLoot)
	http.Handle("/", ServeFiles(http.FileServer(http.Dir(*workdir))))

	if *ssl {
		err := http.ListenAndServeTLS(*addr+":"+*port, *sslcrt, *sslkey, nil)
		if err != nil {
			log.Fatal("ListenAndServeTLS: ", err)
		}
	} else {
		err := http.ListenAndServe(*addr+":"+*port, nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}
}
