package goserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"
)

type RequestLog struct {
	Timestamp  string `json:"timestamp"`
	RemoteAddr string `json:"remote_addr"`
	Path       string `json:"url"`
	Request    string `json:"request"`
	Exfil      string `json:"exfil"`
	Auth       string `json:"auth"`
}

var JSON []RequestLog

func (hc *HTTPConfig) LogRequest(r *http.Request) {
	if !hc.JSONDoLog {
		return
	}
	rl := &RequestLog{}
	rl.Timestamp = time.Now().Format("2006/02/01 15:04:05")
	rl.RemoteAddr = r.RemoteAddr
	rl.Path = r.URL.String()
	u, p, ok := r.BasicAuth()
	rl.Auth = u + ":" + p + ":" + strconv.FormatBool(ok)
	req, err := httputil.DumpRequest(r, true)
	rl.Request = "ERROR DECODING"
	if err == nil {
		rl.Request = base64.StdEncoding.EncodeToString(req)
	}
	tmp := []string{}
	exfil := hc.parseExfil(r)
	if len(exfil) > 0 {
		for k, v := range exfil {
			tmp = append(tmp, k+"="+strings.TrimRight(v, "\n"))
		}
		rl.Exfil = strings.Join(tmp, ",") //strings.TrimRight(exmsg, "\n")
	}
	hc.appendJSONFile(*rl)
}

func (hc *HTTPConfig) appendJSONFile(rl RequestLog) {
	// assume err is because new file/no data
	tmpdata, _ := os.ReadFile(hc.JSONLogFile)
	json.Unmarshal(tmpdata, &JSON)
	JSON = append(JSON, rl)

	data, err := json.MarshalIndent(JSON, "", "     ")
	if err != nil {
		fmt.Println("[ERROR] JSON Logger:", err)
		return
	}
	err = os.WriteFile(hc.JSONLogFile, data, 0755)
	if err != nil {
		log.Fatal("Failed to log JSON to file")
	}
}
