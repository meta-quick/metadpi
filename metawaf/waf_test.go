package metawaf

import "testing"

func TestNew(t *testing.T) {
	waf := Metawaf{}
	waf.Init()
}

func TestWAFRequest(t *testing.T) {
	waf := Metawaf{}
	waf.Init()
	tx := waf.Begin()
	uri := "/index?q=1==1;1==1;1=1"
	method := "GET"
	httpVersion := "1.0"
	waf.ProcessURI(tx, uri, method, httpVersion)
	//headers := make(map[string]string)
	//headers["Content-Type"] = "application/x-www-form-urlencoded"
	//headers["Content-Length"] = "20"
	//headers["Host"] = "localhost"
	//headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like"
	//headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	//headers["Accept-Language"] = "en-US,en;q=0.5"
	//headers["Accept-Encoding"] = "gzip, deflate"
	//headers["Connection"] = "keep-alive"
	//headers["Upgrade-Insecure-Requests"] = "1"
	//headers["Cache-Control"] = "max-age=0"
	//headers["Referer"] = "http://localhost/index"
	//headers["Cookie"] = "PHPSESSID=538764901; PHPSESSID=538764902"
	//headers["X-Forwarded-Proto"] = "https"
	//waf.ProcessRequestHeaders(tx, headers)
	//body := []byte("username=admin' OR 1=1--&password=password")
	//waf.ProcessRequestBody(tx, body)
}
