package apiclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-apibox/pki"
	"github.com/go-apibox/utils"
)

type Client struct {
	LocalAddr net.Addr

	// 网关设置，如果GWADDR为空，则通过DNS查询服务器IP
	GWURL  string
	GWADDR string

	// 签名设置，SignKey为空表示不进行签名
	AppId   string
	SignKey string

	// Nonce设置，长度为0表示不添加Nonce参数
	NonceEnabled bool
	NonceLength  int

	// 默认请求参数设置
	DefaultParams map[string]string

	// 要强制覆盖的请求参数设置
	OverrideParams map[string]string

	// 是否启用SSH隧道，如果启用而SSHClient为空，则API调用返回错误
	SSHTunnelEnabled bool
	// SSH客户端
	SSHClient *SSHClient
}

// NewClient return a new api client.
func NewClient(gwURL string) *Client {
	client := new(Client)
	client.GWURL = gwURL
	client.NonceEnabled = false
	client.NonceLength = 16
	client.DefaultParams = make(map[string]string, 0)
	client.OverrideParams = make(map[string]string, 0)

	return client
}

// Clone clone a new client.
func (client *Client) Clone() *Client {
	newClient := new(Client)
	newClient.LocalAddr = client.LocalAddr
	newClient.GWURL = client.GWURL
	newClient.GWADDR = client.GWADDR
	newClient.AppId = client.AppId
	newClient.SignKey = client.SignKey
	newClient.NonceEnabled = client.NonceEnabled
	newClient.NonceLength = client.NonceLength
	newClient.DefaultParams = make(map[string]string, len(client.DefaultParams))
	newClient.SSHTunnelEnabled = client.SSHTunnelEnabled
	newClient.SSHClient = client.SSHClient
	for k, v := range client.DefaultParams {
		newClient.DefaultParams[k] = v
	}
	newClient.OverrideParams = make(map[string]string, len(client.OverrideParams))
	for k, v := range client.OverrideParams {
		newClient.OverrideParams[k] = v
	}
	return newClient
}

// SetDefaultParam set default param when request.
func (client *Client) SetDefaultParam(paramName, paramValue string) *Client {
	client.DefaultParams[paramName] = paramValue
	return client
}

// SetOverrideParam set param need be override when request.
func (client *Client) SetOverrideParam(paramName, paramValue string) *Client {
	client.OverrideParams[paramName] = paramValue
	return client
}

func (client *Client) newHttpClient() *http.Client {
	c := &http.Client{}

	transport := &http.Transport{}
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
	transport.TLSClientConfig = tlsConfig
	transport.TLSHandshakeTimeout = 30 * time.Second
	c.Transport = transport

	if client.GWADDR == "" {
		transport.Dial = func(network, addr string) (net.Conn, error) {
			if client.SSHTunnelEnabled {
				if client.SSHClient == nil {
					return nil, errors.New("ssh tunnel is not ready")
				}
				if network == "unix" {
					return client.SSHClient.DialUnix(addr)
				} else {
					return client.SSHClient.Dial(network, addr)
				}
			} else {
				if network != "unix" {
					dialer := &net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 10 * time.Second,
						LocalAddr: client.LocalAddr,
					}

					// 不要尝试，如果绑定有误就返回错误
					// conn, err := dialer.Dial(network, addr)
					// if err != nil {
					// 	if client.LocalAddr != nil {
					// 		// 尝试不指定LocalAddr
					// 		dialer.LocalAddr = nil
					// 		conn, err = dialer.Dial(network, addr)
					// 	}
					// }
					// return conn, err
					return dialer.Dial(network, addr)
				} else {
					return net.Dial(network, addr)
				}
			}
		}
		return c
	}

	var network, gwAddr string
	if strings.Index(client.GWADDR, ":") == -1 {
		// unix domain socket
		network = "unix"
		gwAddr = utils.AbsPath(client.GWADDR)
	} else {
		// ip:port
		network = "tcp"
		gwAddr = client.GWADDR
	}

	transport.Dial = func(n, a string) (net.Conn, error) {
		if client.SSHTunnelEnabled {
			if client.SSHClient == nil {
				return nil, errors.New("ssh tunnel is not ready")
			}
			if network == "unix" {
				return client.SSHClient.DialUnix(gwAddr)
			} else {
				return client.SSHClient.Dial(network, gwAddr)
			}
		} else {
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 10 * time.Second,
				LocalAddr: client.LocalAddr,
			}

			// 不要尝试，如果绑定有误就返回错误
			// conn, err := dialer.Dial(network, gwAddr)
			// if err != nil {
			// 	if client.LocalAddr != nil {
			// 		// 尝试不指定LocalAddr
			// 		dialer.LocalAddr = nil
			// 		conn, err = dialer.Dial(network, gwAddr)
			// 	}
			// }
			// return conn, err
			return dialer.Dial(network, gwAddr)
		}
	}

	return c
}

// Get make a HTTP GET request and return as *Response.
func (client *Client) Get(action string, params url.Values, header http.Header) (*Response, error) {
	return client.Request("GET", action, params, header, nil)
}

// Post make a HTTP POST request and return as *Response.
func (client *Client) Post(action string, params url.Values, header http.Header) (*Response, error) {
	return client.Request("POST", action, params, header, nil)
}

// Upload make a HTTP upload request and return as *Response.
func (client *Client) Upload(action string, params url.Values, header http.Header, multipartBody io.Reader) (*Response, error) {
	return client.Request("POST", action, params, header, multipartBody)
}

func (client *Client) buildRequest(method, action string, params url.Values, multipartBody io.Reader) (urlStr string, body io.Reader, err error) {
	p := make(url.Values)
	if params != nil {
		for k, v := range params {
			p[k] = v
		}
	}

	// 分析网关
	urlInfo, err := url.Parse(client.GWURL)
	if err != nil {
		return "", nil, err
	}
	if method == "GET" {
		queryParams := urlInfo.Query()
		for k, v := range queryParams {
			p[k] = v
		}

	}

	// 默认参数处理
	for k, v := range client.DefaultParams {
		if _, has := p[k]; !has {
			p.Set(k, v)
		}
	}

	// 强制覆盖参数处理
	for k, v := range client.OverrideParams {
		p.Set(k, v)
	}

	if action != "" {
		p.Set("api_action", action)
		p.Set("api_format", "json")
	}

	if client.AppId != "" {
		p.Set("api_appid", client.AppId)
	}
	if client.NonceEnabled && client.NonceLength > 0 || client.SignKey != "" {
		p.Set("api_timestamp", fmt.Sprintf("%d", utils.Timestamp()))
		if client.NonceEnabled && client.NonceLength > 0 {
			nonce := utils.RandStringN(client.NonceLength)
			p.Set("api_nonce", nonce)
		}
		p.Del("api_sign") // 移除已有的api_sign，否则签名出错
		if client.SignKey != "" {
			sign := MakeSignString(p, client.SignKey)
			p.Set("api_sign", sign)
		}
	}

	if method == "GET" {
		urlInfo.RawQuery = p.Encode()
	} else if method == "POST" {
		if multipartBody == nil {
			body = strings.NewReader(p.Encode())
		} else {
			// 上传时，参数只能放在query string中
			urlInfo.RawQuery = p.Encode()
			body = multipartBody
		}
	}
	urlStr = urlInfo.String()

	return urlStr, body, nil
}

func (client *Client) newRequest(method, action string, params url.Values, header http.Header, multipartBody io.Reader) (*http.Request, error) {
	urlStr, body, err := client.buildRequest(method, action, params, multipartBody)
	if err != nil {
		return nil, errors.New("Wrong request: " + err.Error())
	}

	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}
	if header != nil {
		for k, v := range header {
			req.Header[k] = v
		}
	}
	req.Header.Set("User-Agent", "apibox/client")
	req.Header.Set("Connection", "close")
	if method == "POST" && multipartBody == nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return req, nil
}

// Request make a HTTP request and return as *Response.
func (client *Client) Request(method, action string, params url.Values, header http.Header, multipartBody io.Reader) (*Response, error) {
	if method != "GET" && method != "POST" {
		return nil, errors.New("unsupport method: " + method)
	}

	req, err := client.newRequest(method, action, params, header, multipartBody)
	if err != nil {
		return nil, err
	}

	c := client.newHttpClient()
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 400 {
		return &Response{resp, nil}, nil
	} else {
		return &Response{resp, nil}, errors.New("Gateway return with status: " + resp.Status)
	}
}
