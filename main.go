package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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

func DropLoot(w http.ResponseWriter, r *http.Request) {
	DumpReq(w, r)
	r.ParseMultipartForm(10 << 20)

	file, handler, err := r.FormFile("file")
	if err != nil {
		fmt.Println(Red, "[ERROR] Retrieving the File", Reset)
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
		fmt.Println(Red, "[ERROR] Failed to write local file:", WorkDir+"/"+handler.Filename, Reset)
		return
	}
	fmt.Println(Green, "[+] Uploaded File:", handler.Filename, Reset)
}

func DumpReq(w http.ResponseWriter, req *http.Request) {
	log.Println(req.Method, "from", req.RemoteAddr+":", req.URL.Path)
	if Dump {
		qp := ""
		if len(req.URL.RawQuery) > 0 {
			qp = "?" + req.URL.RawQuery
		}

		// fmt.Println(req.Method + " " + req.URL.Path + qp + " " + req.Proto)

		body, err := ioutil.ReadAll(req.Body)

		if err != nil {
			log.Printf(Red, "[ERROR] reading body: %v", err, Reset)
			return
		}

		fmt.Println()
		fmt.Println()

		fmt.Println("-------------------------------------------------------------------------------------")

		fmt.Println(req.Method + " " + req.URL.Path + qp + " " + req.Proto)
		fmt.Println("Host: " + req.Host)
		for k := range req.Header {
			fmt.Println(k + ": " + req.Header.Get(k))
		}
		fmt.Println("\n")
		fmt.Println(string(body))
		req.Body.Close() //  must close
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}

}

func ServeFiles(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		DumpReq(w, r)
		h.ServeHTTP(w, r) // call original

	})
}

func main() {

	port := flag.String("port", "8000", "Listen port")
	addr := flag.String("addr", "", "Listen address")
	dump := flag.Bool("dump", false, "dump full requests")
	workdir := flag.String("dir", "./", "Working directory")
	flag.Parse()

	WorkDir = *workdir
	Dump = *dump
	fmt.Println(Blue, "[!] Starting web server at:", *addr+":"+*port, Reset)
	// http.HandleFunc("/dump", DumpReq)
	http.HandleFunc("/loot", DropLoot)
	// http.Handle("/", http.FileServer(http.Dir(*workdir)))
	http.Handle("/", ServeFiles(http.FileServer(http.Dir(*workdir))))
	http.ListenAndServe(*addr+":"+*port, nil)
}
