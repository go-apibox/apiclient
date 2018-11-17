package apiclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-apibox/pki"
	"github.com/go-apibox/utils"
	"github.com/gorilla/websocket"
)

// websocket client 不允许出现的header，出现可能报类似错误：
// websocket: duplicate header not allowed: Connection
var wsClientDisallowedHeaderKeyMap map[string]bool

func init() {
	// 移除以下header，否则可能报类似错误：
	// websocket: duplicate header not allowed: Connection
	wsClientDisallowedHeaderKeyMap = map[string]bool{
		"Upgrade":                  true,
		"Connection":               true,
		"Sec-Websocket-Key":        true,
		"Sec-Websocket-Version":    true,
		"Sec-Websocket-Extensions": true,
		"Sec-Websocket-Protocol":   true,
	}
}

func (client *Client) WsDial(u string, header http.Header, addr string) (ws *websocket.Conn, resp *http.Response, err error) {
	return client.WsDialWithLocalAddr(u, header, addr, nil)
}

func (client *Client) WsDialWithLocalAddr(u string, header http.Header, addr string, localAddr net.Addr) (ws *websocket.Conn, resp *http.Response, err error) {
	urlInfo, err := url.Parse(u)
	if err != nil {
		return nil, nil, err
	}

	network := "tcp"
	if addr != "" {
		if strings.IndexByte(addr, ':') == -1 {
			// unix domain socket
			addr = utils.AbsPath(addr)
			network = "unix"
		}
	} else {
		addr = urlInfo.Host
	}

	// var conn net.Conn
	wsDialer := &websocket.Dialer{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	wsDialer.NetDial = func(string, string) (net.Conn, error) {
		if client.SSHTunnelEnabled {
			if client.SSHClient == nil {
				return nil, errors.New("ssh tunnel is not ready")
			}
			if network == "unix" {
				return client.SSHClient.WsDialUnix(addr)
			} else {
				return client.SSHClient.WsDial(network, addr)
			}
		} else {
			if network != "unix" {
				dialer := &net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 10 * time.Second,
					LocalAddr: localAddr,
				}

				conn, err := dialer.Dial(network, addr)
				// 不要尝试，如果绑定有误就返回错误
				// if err != nil {
				// 	if localAddr != nil {
				// 		// 尝试不指定LocalAddr
				// 		dialer.LocalAddr = nil
				// 		conn, err = dialer.Dial(network, addr)
				// 	}
				// }
				if err != nil {
					return nil, err
				}
				FixKeepAlive(conn)
				return conn, nil
			} else {
				return net.Dial(network, addr)
			}

		}
	}

	switch urlInfo.Scheme {
	case "ws":
		break
	case "wss":
		tlsConfig := &tls.Config{
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			},
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS12,
		}
		certs := x509.NewCertPool()
		certs.AppendCertsFromPEM([]byte(pki.ROOT_CERT))
		certs.AppendCertsFromPEM([]byte(pki.ROOT_CERT_1))
		tlsConfig.RootCAs = certs

		host := urlInfo.Host
		colonPos := strings.LastIndex(host, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		hostname := host[:colonPos]
		tlsConfig.ServerName = hostname

		wsDialer.TLSClientConfig = tlsConfig
	default:
		err = errors.New("Unknown protocol.")
	}
	if err != nil {
		return nil, nil, err
	}

	// 删除客户端不允许存在的header
	newHeader := make(http.Header)
	for k, v := range header {
		if _, has := wsClientDisallowedHeaderKeyMap[k]; !has {
			newHeader[k] = v
		}
	}

	return wsDialer.Dial(urlInfo.String(), newHeader)
}

var upgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// WsConn make a websocket connection to the backend websocket server.
func (client *Client) WsConn(action string, params url.Values, header http.Header) (*websocket.Conn, *http.Response, error) {
	// 分析网关
	gwURLInfo, err := url.Parse(client.GWURL)
	if err != nil {
		return nil, nil, err
	}

	urlStr, _, err := client.buildRequest("GET", action, params, nil)
	if err != nil {
		return nil, nil, err
	}
	if gwURLInfo.Scheme == "http" {
		urlStr = "ws" + urlStr[4:]
	} else if gwURLInfo.Scheme == "https" {
		urlStr = "wss" + urlStr[5:]
	}

	if header == nil {
		header = make(http.Header)
	}

	return client.WsDialWithLocalAddr(urlStr, header, client.GWADDR, client.LocalAddr)
}

// Websocket make a websocket request to the backend websocket server and upgrade current request.
func (client *Client) Websocket(action string, params url.Values, header http.Header, w http.ResponseWriter, r *http.Request) (*Response, error) {
	return client.WebsocketHandleFunc(action, params, header, w, r, WebsocketCopy)
}

// WebsocketFunc make a websocket request to the backend websocket server and upgrade current request, and deal with request and response by proxyFunc.
func (client *Client) WebsocketHandleFunc(action string, params url.Values, header http.Header, w http.ResponseWriter, r *http.Request,
	proxyFunc func(reqConn *websocket.Conn, backendConn *websocket.Conn) error) (*Response, error) {
	backendConn, resp, err := client.WsConn(action, params, header)
	if err != nil {
		return nil, err
	}

	reqConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}

	proxyErr := proxyFunc(reqConn, backendConn)

	return &Response{resp, nil}, proxyErr
}

func WebsocketCopy(reqConn *websocket.Conn, backendConn *websocket.Conn) error {
	var closeReqConnOnce, closeBackendConnOnce sync.Once
	closeReqConnFunc := func() {
		reqConn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "close request"),
			time.Time{})
		reqConn.Close()
	}
	closeBackendConnFunc := func() {
		backendConn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "close backend"),
			time.Time{})
		backendConn.Close()
	}

	// read local -> write backend
	wErrCh := make(chan error, 1)
	go func(wErrCh chan error) {
		var msgType int
		var err error
		var r io.Reader
		var w io.WriteCloser

		for {
			msgType, r, err = reqConn.NextReader()
			if err != nil {
				break
			}

			w, err = backendConn.NextWriter(msgType)
			if err != nil {
				break
			}

			_, err = io.Copy(w, r)
			if err != nil {
				w.Close()
				break
			}
			w.Close()
		}

		wErrCh <- err
		closeReqConnOnce.Do(closeReqConnFunc)
		closeBackendConnOnce.Do(closeBackendConnFunc)
	}(wErrCh)

	// read backend -> write local
	rErrCh := make(chan error, 1)
	go func(rErrCh chan error) {
		var msgType int
		var err error
		var r io.Reader
		var w io.WriteCloser

		for {
			msgType, r, err = backendConn.NextReader()
			if err != nil {
				break
			}

			w, err = reqConn.NextWriter(msgType)
			if err != nil {
				break
			}

			_, err = io.Copy(w, r)
			if err != nil {
				w.Close()
				break
			}
			w.Close()
		}

		rErrCh <- err
		closeReqConnOnce.Do(closeReqConnFunc)
		closeBackendConnOnce.Do(closeBackendConnFunc)
	}(rErrCh)

	rErr := ignoreCloseError(<-rErrCh)
	wErr := ignoreCloseError(<-wErrCh)
	if rErr != nil {
		return rErr
	} else {
		return wErr
	}
}

// 忽略关闭连接的错误
func ignoreCloseError(err error) error {
	if err == nil {
		return nil
	}

	// websocket failed: websocket: close 1005
	if _, ok := err.(*websocket.CloseError); ok {
		return nil
	}

	errStr := err.Error()
	if strings.Contains(errStr, "use of closed network connection") {
		// go库net/net.go中获取到的网络错误，如：
		// websocket failed: read tcp 192.168.1.140:8888->192.168.1.52:51058: use of closed network connection
		return nil
	}
	if strings.Contains(errStr, "broken pipe") {
		// write unix /opt/appnode/agent/run/bus.sock->@: write: broken pipe
		return nil
	}
	if strings.Contains(errStr, "unexpected EOF") {
		// websocket: close 1006 unexpected EOF
		return nil
	}

	return err
}
