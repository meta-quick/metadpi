package build

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/meta-quick/gocodec"
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
	source  map[string]*gocodec.Buffer
}

var hp *H

func NewInstance() *H {
	if hp == nil {
		hp = &H{
			port:    Port,
			version: Version,
			source:  make(map[string]*gocodec.Buffer),
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
	uuid := fmt.Sprintf("%v:%v:%v:%v", net.Src(), transport.Src(), net.Dst(), transport.Dst())

	if _, ok := m.source[uuid]; !ok {
		m.source[uuid] = &gocodec.Buffer{}
	}

	waf := metawaf.Metawaf{}
	waf.Init()

	var isRequestStream = false
	var contentLength int64 = 0
	var reqState int = 0
	var respState int = 0
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

		if isRequestLine(line) || isRequestStream == true {
			isRequestStream = true
			if isRequestLine(line) || reqState == 2 { //All line recieve
				key := findRequstKey(line)
				sb, _ := m.source[uuid]
				if sb.Len() > 0 {
					if key != "" {
						lindex := strings.Index(string(line), key)
						if lindex > 0 {
							if reqState == 2 {
								reqState = 0
							}
							sb.Write(line[:lindex])
							//take all bytes
							databuf := make([]byte, sb.Len())
							sb.Read(databuf)
							waf.ProcessRequest(string(databuf))
							//we assume only one request in queue
							sb.Reset()
							sb.Write(line[lindex:])
							sb.WriteString("\n")
							continue
						} else {
							if reqState == 2 {
								reqState = 0
							}
							databuf := make([]byte, sb.Len())
							sb.Read(databuf)
							waf.ProcessRequest(string(databuf))

							sb.Reset()
							sb.Write(line)
							sb.WriteString("\n")
							continue
						}
					}
				}
			}

			sb, _ := m.source[uuid]
			if string(line) == "" {
				sb.WriteString("\r\n")
				reqState = 1
				continue
			}

			//if Content-Length line
			if strings.Contains(string(line), "Content-Length") {
				//Calcluate Content-Length
				lindex := strings.Index(string(line), ":")
				if lindex > 0 {
					clen := strings.TrimSpace(string(line[lindex+1:]))
					if clen != "" {
						//Convert 0x123 to int
						contentLength, _ = strconv.ParseInt(clen, 16, 64)
					}
				}
			}

			if reqState == 1 {
				lenx := len(line)
				contentLength = contentLength - int64(lenx)
				if contentLength <= 0 {
					reqState = 2
				}
			}

			sb.Write(line)
			sb.WriteString("\n")
		} else if isResponseLine(line) || isRequestStream != true {
			isRequestStream = false
			sb, _ := m.source[uuid]

			if respState == 2 && string(line) == "0" { //Last chunk
				respState = 3 //Last chunk
			}

			if 1 == respState && string(line) == "0" { //Header complete
				respState = 2 //First chunk
			}

			//Transfer-Encoding: chunked
			if strings.Contains(string(line), "Transfer-Encoding") {
				respState = 1 //Chunked
			}

			if isResponseLine(line) || respState == 3 {
				if sb.Len() > 0 {
					peek := string(line)
					if strings.Contains(peek, "HTTP") || respState == 3 {
						lindex := strings.Index(string(line), "HTTP")
						if lindex > 0 {
							respState = 0
							sb.Write(line[:lindex])

							databuf := make([]byte, sb.Len())
							sb.Read(databuf)
							waf.ProcessResponse(string(databuf))
							sb.Reset()
							sb.Write(line[lindex:])
							sb.WriteString("\n")
							continue
						} else {
							respState = 0
							databuf := make([]byte, sb.Len())
							sb.Read(databuf)

							waf.ProcessResponse(string(databuf))
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
	sb, _ := m.source[uuid]
	if isRequestStream {
		databuf := make([]byte, sb.Len())
		sb.Read(databuf)
		waf.ProcessRequest(string(databuf))
	} else {
		databuf := make([]byte, sb.Len())
		sb.Read(databuf)
		waf.ProcessResponse(string(databuf))
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
