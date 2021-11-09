package main

import (
	"flag"
	"fmt"
	"goserver/goserver"
	"os"
	"strings"
)

type HeaderSlice []string
type CustomRespSlice []string

var RespHeaders HeaderSlice
var CustomResponse CustomRespSlice

func (i *CustomRespSlice) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *CustomRespSlice) Set(value string) error {
	*i = append(*i, value)
	return nil
}
func (i *HeaderSlice) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *HeaderSlice) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	// add custom responses.
	port := flag.String("port", "8000", "Listen port")
	redirect := flag.String("redirect", "", "Redirect to [STRING] via 301")
	addr := flag.String("addr", "", "Listen address")
	dump := flag.Bool("dump", false, "dump full requests")
	workdir := flag.String("dir", "./", "Working directory")
	auth := flag.String("auth", "", "Enable basic auth (-auth user:password)")
	ssl := flag.Bool("ssl", false, "Enable TLS/SSL, if no -sslcert/-sslkey then one will be generated.")
	domain := flag.String("ssldomain", "localhost", "domain name for ssl cert generation")
	flag.Var(&CustomResponse, "resp", "custom response pair [server_path]:[path_to_raw_response], use multiple times")
	sslcrt := flag.String("sslcert", "", "Path to SSL .crt file, if ommitted self signed will be generated")
	sslkey := flag.String("sslkey", "", "Path to SSL .key file, if ommitted self signed will be generated")
	flag.Var(&RespHeaders, "H", "Add response header 'name: value', use multiple times")
	flag.Parse()

	goserver.WorkDir = *workdir
	goserver.Dump = *dump
	goserver.RedirectURL = *redirect
	goserver.Addr = *addr
	goserver.Port = *port
	goserver.SSL = *ssl
	goserver.SSLCert = *sslcrt
	goserver.SSLKey = *sslkey
	goserver.SSLDomain = *domain
	goserver.Headers = make(map[string]string)
	goserver.CustomResponses = make(map[string]string)

	for _, h := range RespHeaders {
		tmp := strings.Replace(h, ": ", ":", 1)
		prts := strings.SplitN(tmp, ":", 2)
		goserver.Headers[prts[0]] = prts[1]
	}

	for _, r := range CustomResponse {
		prts := strings.SplitN(r, ":", 2)
		_, err := os.Stat(prts[1])
		if err != nil {
			panic(err)
		}
		goserver.CustomResponses[prts[0]] = prts[1]
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
