package metawaf

import (
	"bufio"
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"io"
	"log"
	"net/http"
	"strings"
)

type Metawaf struct {
	waf coraza.WAF
	cfg coraza.WAFConfig
}

func (m *Metawaf) Init() {
	config := coraza.NewWAFConfig().
		WithDirectivesFromFile("./coreruleset/coraza.conf").
		WithDirectivesFromFile("./coreruleset/crs-setup.conf").
		WithDirectivesFromFile("./coreruleset/rules/*.conf")

	waf, err := coraza.NewWAF(config)
	if err != nil {
		panic(err)
	}
	m.waf = waf
	m.cfg = config
}

func (m *Metawaf) Begin() types.Transaction {
	tx := m.waf.NewTransaction()
	return tx
}

func (m *Metawaf) ProcessURI(tx types.Transaction, uri string, method string, httpVersion string) {
	tx.ProcessURI(uri, method, httpVersion)
}

func (m *Metawaf) ProcessConnection(tx types.Transaction, client string, cPort int, server string, sPort int) {
	tx.ProcessConnection(client, cPort, server, sPort)
}

func (m *Metawaf) ProcessRequestArguments(tx types.Transaction, args map[string]string) {
	for key, value := range args {
		tx.AddGetRequestArgument(key, value)
	}
}

func (m *Metawaf) ProcessRequestPathArguments(tx types.Transaction, args map[string]string) {
	for key, value := range args {
		tx.AddPathRequestArgument(key, value)
	}
}

func (m *Metawaf) ProcessRequestPostArguments(tx types.Transaction, args map[string]string) {
	for key, value := range args {
		tx.AddPostRequestArgument(key, value)
	}
}

func (m *Metawaf) ProcessRequestHeaders(tx types.Transaction, headers map[string]string) {
	for key, value := range headers {
		tx.AddRequestHeader(key, value)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		if it.Action == "deny" {
			fmt.Println("deny")
		}

		if it.Action == "drop" {
			fmt.Println("drop")
		}
	}
}

func (m *Metawaf) ProcessRequestBody(tx types.Transaction, body []byte) {
	it, _, err := tx.WriteRequestBody(body)
	if err != nil {
		return
	}
	if it != nil {
		if it.Action == "deny" {
			fmt.Println("deny")
		}

		if it.Action == "drop" {
			fmt.Println("drop")
		}
	}

	it, err = tx.ProcessRequestBody()
	if it != nil {
		if it.Action == "deny" {
			fmt.Println("deny")
		}

		if it.Action == "drop" {
			fmt.Println("drop")
		}
	}
}

func (m *Metawaf) ProcessRequest(requestData string) {
	tx := m.waf.NewTransaction()
	defer tx.Close()

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(requestData)))
	if err != nil {
		log.Printf("Error reading request: %v", err)
		return
	}

	// Process request headers
	for name, values := range req.Header {
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}

	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		tx.SetServerName(req.Host)
	}

	if req.TransferEncoding != nil {
		tx.AddRequestHeader("Transfer-Encoding", req.TransferEncoding[0])
	}

	tx.ProcessRequestHeaders()

	if tx.IsResponseBodyProcessable() {
		if req.Body != nil && req.Body != http.NoBody {
			it, _, err := tx.ReadRequestBodyFrom(req.Body)
			if err != nil {
				return
			}

			if it != nil {
				return
			}

			rbr, err := tx.RequestBodyReader()
			if err != nil {
				return
			}
			body := io.MultiReader(rbr, req.Body)
			if rwt, ok := body.(io.WriterTo); ok {
				req.Body = struct {
					io.Reader
					io.WriterTo
					io.Closer
				}{body, rwt, req.Body}
			} else {
				req.Body = struct {
					io.Reader
					io.Closer
				}{body, req.Body}
			}
		}
	}

	tx.ProcessRequestBody()
	// Check for WAF intervention
	if tx.IsInterrupted() {
		intervention := tx.Interruption()
		log.Printf("!!!!!Request blocked by WAF: %d, %s, %s", intervention.RuleID, intervention.Data, intervention.Action)
	} else {
		log.Println("!!!!!Request allowed by WAF")
	}
}

func (m *Metawaf) ProcessResponse(responseData string) {
	tx := m.waf.NewTransaction()
	defer tx.Close()

	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(responseData)), nil)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		return
	}
	fmt.Println(resp)
}

func New() *Metawaf {
	m := &Metawaf{}
	m.Init()
	return m
}
