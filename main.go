package main

import (
	"flag"
	"fmt"
	"goserver/goserver"
	"os"
	"strings"
)

type HeaderSlice []string

var RespHeaders HeaderSlice

func (i *HeaderSlice) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *HeaderSlice) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	// add domain name flag for cert generation
	// add custom responses.
	port := flag.String("port", "8000", "Listen port")
	redirect := flag.String("redirect", "", "Redirect to [STRING] via 301")
	addr := flag.String("addr", "", "Listen address")
	dump := flag.Bool("dump", false, "dump full requests")
	workdir := flag.String("dir", "./", "Working directory")
	auth := flag.String("auth", "", "Enable basic auth (-auth user:password)")
	ssl := flag.Bool("ssl", false, "Enable TLS/SSL, if no -cert/-key then one will be generated.")
	domain := flag.String("domain", "", "domain name for cert generation")
	respfile := flag.String("respfile", "", "yaml containing custom responses")
	sslcrt := flag.String("cert", "", "Path to SSL .crt file")
	sslkey := flag.String("key", "", "Path to SSL .key file")
	flag.Var(&RespHeaders, "H", "Add response header, use multiple times")

	flag.Parse()

	fmt.Println("------ TODO: finish -domain flag", domain)
	fmt.Println("------ TODO: finish -respfile flag", respfile)

	goserver.WorkDir = *workdir
	goserver.Dump = *dump
	goserver.RedirectURL = *redirect
	goserver.Addr = *addr
	goserver.Port = *port
	goserver.SSL = *ssl
	goserver.SSLCert = *sslcrt
	goserver.SSLKey = *sslkey

	goserver.Headers = make(map[string]string)
	for _, h := range RespHeaders {
		tmp := strings.Replace(h, ": ", ":", 1)
		prts := strings.SplitN(tmp, ":", 2)
		goserver.Headers[prts[0]] = prts[1]
	}

	if *auth != "" {
		parts := strings.Split(*auth, ":")
		if len(parts) != 2 {
			fmt.Println(goserver.Red+"[ERROR] invalid auth string: must be 'user:password'", goserver.Reset)
			os.Exit(1)
		} else {
			goserver.DoAuth = true
			goserver.Username = parts[0]
			goserver.Password = parts[1]
		}
	}

	goserver.Run()

}
