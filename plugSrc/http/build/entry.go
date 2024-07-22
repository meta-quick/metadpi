package build

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/meta-quick/metadpi/metawaf"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

const (
	Port    = 80
	Version = "0.1"
)

const (
	CmdPort = "-p"
)

type H struct {
	port    int
	version string
}

var hp *H

func NewInstance() *H {
	if hp == nil {
		hp = &H{
			port:    Port,
			version: Version,
		}
	}
	return hp
}

func isRequestLine(peek []byte) bool {
	line := string(peek)
	return strings.Contains(line, "GET") ||
		strings.Contains(line, "POST") ||
		strings.Contains(line, "PUT") ||
		strings.Contains(line, "DELETE") ||
		strings.Contains(line, "HEAD") ||
		strings.Contains(line, "OPTIONS") ||
		strings.Contains(line, "TRACE") ||
		strings.Contains(line, "CONNECT") ||
		strings.Contains(line, "PATCH") ||
		strings.Contains(line, "OPTIONS") ||
		strings.Contains(line, "TRACE")
}

func findRequstKey(peek []byte) string {
	line := string(peek)
	if strings.Contains(line, "GET") {
		return "GET"
	} else if strings.Contains(line, "POST") {
		return "POST"
	} else if strings.Contains(line, "PUT") {
		return "PUT"
	} else if strings.Contains(line, "DELETE") {
		return "DELETE"
	} else if strings.Contains(line, "HEAD") {
		return "HEAD"
	} else if strings.Contains(line, "OPTIONS") {
		return "OPTIONS"
	} else if strings.Contains(line, "TRACE") {
		return "TRACE"
	} else if strings.Contains(line, "CONNECT") {
		return "CONNECT"
	} else if strings.Contains(line, "PATCH") {
		return "PATCH"
	} else if strings.Contains(line, "PROPFIND") {
		return "PROPFIND"
	} else if strings.Contains(line, "PROPPATCH") {
		return "PROPPATCH"
	} else if strings.Contains(line, "MKCOL") {
		return "MKCOL"
	} else if strings.Contains(line, "COPY") {
		return "COPY"
	} else if strings.Contains(line, "MOVE") {
		return "MOVE"
	} else if strings.Contains(line, "LOCK") {
		return "LOCK"
	} else if strings.Contains(line, "UNLOCK") {
		return "UNLOCK"
	}
	return ""
}

func isResponseLine(peek []byte) bool {
	line := string(peek)
	return strings.Contains(line, "HTTP")
}

var seq int = 0

func (m *H) ResolveStream(net, transport gopacket.Flow, buf io.Reader) {
	bio := bufio.NewReader(buf)
	sb := strings.Builder{}
	waf := metawaf.Metawaf{}
	waf.Init()

	var isRequestStream = false
	//lseq := seq
	//seq++
	for {
		line, _, err := bio.ReadLine()
		if err == io.EOF {
			break // End of stream
		} else if err != nil {
			log.Printf("Error peeking at stream: %v", err)
			continue // Skip to the next iteration
		}

		//fmt.Printf("seq : %d >", lseq)
		//fmt.Println(string(line))
		if isRequestLine(line) || isRequestStream == true {
			isRequestStream = true
			if isRequestLine(line) {
				//Split if combing multiple bytes
				key := findRequstKey(line)
				if sb.Len() > 0 {
					if key != "" {
						lindex := strings.Index(string(line), key)
						if lindex > 0 {
							sb.Write(line[:lindex])
							waf.ProcessRequest(sb.String())
							sb.Reset()
							sb.Write(line[lindex:])
							sb.WriteString("\n")
							continue
						} else if 0 == lindex {
							waf.ProcessRequest(sb.String())
							sb.Reset()
							sb.Write(line)
							sb.WriteString("\n")
							continue
						}
					}
				}
			}

			if string(line) == "" {
				sb.WriteString("\r\n")
				continue
			}
			sb.Write(line)
			sb.WriteString("\n")
		} else if isResponseLine(line) || isRequestStream != true {
			isRequestStream = false
			if isResponseLine(line) {
				if sb.Len() > 0 {
					peek := string(line)
					if strings.Contains(peek, "HTTP") {
						lindex := strings.Index(string(line), "HTTP")
						if lindex > 0 {
							sb.Write(line[:lindex])
							waf.ProcessResponse(sb.String())
							sb.Reset()
							sb.Write(line[lindex:])
							sb.WriteString("\n")
							continue
						} else if 0 == lindex {
							waf.ProcessResponse(sb.String())
							sb.Reset()
							sb.Write(line)
							sb.WriteString("\n")
							continue
						}
					}
				}
			}
			sb.Write(line)
			sb.WriteString("\n")
		}
	}

	if isRequestStream {
		waf.ProcessRequest(sb.String())
	} else {
		waf.ProcessResponse(sb.String())
	}
}

func (m *H) BPFFilter() string {
	return "tcp and port " + strconv.Itoa(m.port)
}

func (m *H) Version() string {
	return Version
}

func (m *H) SetFlag(flg []string) {

	c := len(flg)

	if c == 0 {
		return
	}
	if c>>1 == 0 {
		fmt.Println("ERR : Http Number of parameters")
		os.Exit(1)
	}
	for i := 0; i < c; i = i + 2 {
		key := flg[i]
		val := flg[i+1]

		switch key {
		case CmdPort:
			port, err := strconv.Atoi(val)
			m.port = port
			if err != nil {
				panic("ERR : port")
			}
			if port < 0 || port > 65535 {
				panic("ERR : port(0-65535)")
			}
			break
		default:
			panic("ERR : mysql's params")
		}
	}
}
