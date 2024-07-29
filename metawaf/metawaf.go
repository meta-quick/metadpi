package metawaf

import "C"
import (
	"bufio"
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	yara_x "github.com/meta-quick/metadpi/yarax"
	"io/ioutil"
	"os"
	"path/filepath"

	//"github.com/meta-quick/metadpi/yarax"
	"io"
	"log"
	"net/http"
	"strings"
)

type Metawaf struct {
	waf      coraza.WAF
	compiler *yara_x.Compiler
	scanner  *yara_x.Scanner
	cfg      coraza.WAFConfig
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

	m.InitYaraCompiler()
	m.AddRuleFromPath("./dataruleset", "datasafe")
	m.buildScanner()
}

func (m *Metawaf) InitYaraCompiler() {
	m.compiler, _ = yara_x.NewCompiler()
}

func (m *Metawaf) buildScanner() {
	m.scanner = yara_x.NewScanner(m.compiler.Build())
}

func (m *Metawaf) AddNamespace(ns string) {
	m.compiler.NewNamespace(ns)
}

func (m *Metawaf) AddRule(rule string, ns string) {
	if ns == "" {
		err := m.compiler.AddSource(rule)
		if err != nil {
			return
		}
	} else {
		m.compiler.NewNamespace(ns)
		err := m.compiler.AddSource(rule)
		if err != nil {
			return
		}
	}
}

func (m *Metawaf) AddRuleFromPath(path string, ns string) {
	if ns == "" {
		m.AddRulePth(path)
	} else {
		m.AddNamespace(ns)
		m.AddRulePth(path)
	}
}

func (m *Metawaf) AddRulePth(path string) {
	//walk the directory to list all files with yar or yara
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Check if the file has a .yar or .yara extension
		if !info.IsDir() && (filepath.Ext(filePath) == ".yar" || filepath.Ext(filePath) == ".yara") {
			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %v", filePath, err)
			}

			// Add the file content to the compiler
			m.compiler.AddSource(string(content))
		}
		return nil
	})
	if err != nil {
		return
	}
}

func (m *Metawaf) YaraScan(data []byte) ([]*yara_x.Rule, error) {
	if m.scanner == nil {
		return nil, fmt.Errorf("scanner is not initialized")
	}

	rules, err := m.scanner.Scan(data)
	if err != nil {
		return nil, err
	}
	return rules, nil
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
		log.Printf("\n!!!!!Request blocked by WAF: %d, %s, %s", intervention.RuleID, intervention.Data, intervention.Action)
	} else {
		log.Println("\n!!!!!Request allowed by WAF")
	}
}

func (m *Metawaf) ProcessResponse(responseData string) {
	matchingRules, err := m.YaraScan([]byte(responseData))
	if err != nil {
		log.Printf("Error scanning response: %v", err)
	}

	if len(matchingRules) > 0 {
		printRules(matchingRules)
	}
}

func printRules(rules []*yara_x.Rule) {
	for _, rule := range rules {
		fmt.Printf("Namespace: %s\n", rule.Namespace())
		fmt.Printf("Identifier: %s\n", rule.Identifier())

		metas := rule.Metadata()
		if metas != nil {
			fmt.Printf("Metadata:\n")
			for _, meta := range metas {
				fmt.Printf(" Identifier: %s; ", meta.Identifier)

				switch meta.Value.(type) {
				case string:
					fmt.Printf(" Value: %s\n", meta.Value.(string))
				case int64:
					fmt.Printf(" Value: %d\n", meta.Value.(int64))
				case float64:
					fmt.Printf(" Value: %f\n", meta.Value.(float64))
				case bool:
					fmt.Printf(" Value: %t\n", meta.Value.(bool))
				}
			}
		}

		patterns := rule.Patterns()
		if patterns != nil {
			fmt.Printf("Patterns:")
			for _, pattern := range patterns {
				fmt.Printf("\n Identifier: %s; ", pattern.Identifier())
				for _, match := range pattern.Matches() {
					fmt.Printf("\n   match: offset:%d,length:%d", match.Offset(), match.Length())
				}
			}
		}
	}
}

func New() *Metawaf {
	m := &Metawaf{}
	m.Init()
	return m
}
