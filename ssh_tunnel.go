package apiclient

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHTunnel struct {
	Hostname               string
	Port                   uint32
	Username               string
	AuthMethod             string
	Password               string
	IdentityFile           string
	IdentityFilePassphrase string
}

func (tunnel *SSHTunnel) Clone() *SSHTunnel {
	n := new(SSHTunnel)
	n.Hostname = tunnel.Hostname
	n.Port = tunnel.Port
	n.Username = tunnel.Username
	n.AuthMethod = tunnel.AuthMethod
	n.Password = tunnel.Password
	n.IdentityFile = tunnel.IdentityFile
	n.IdentityFilePassphrase = tunnel.IdentityFilePassphrase
	return n
}

func (tunnel *SSHTunnel) Client() (*SSHClient, error) {
	auths := []ssh.AuthMethod{}

	switch tunnel.AuthMethod {
	case "password":
		if tunnel.Password == "" {
			return nil, fmt.Errorf("missing password")
		}

		auths = append(auths, ssh.Password(tunnel.Password))

	case "publickey":
		if tunnel.IdentityFile == "" {
			return nil, fmt.Errorf("missing identity file")
		}

		pemBytes, err := ioutil.ReadFile(tunnel.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("read identity file failed: %s", err.Error())
		} else {
			pemBlock, _ := pem.Decode(pemBytes)
			if pemBlock == nil {
				return nil, fmt.Errorf("unrecognized identity file: %s", tunnel.IdentityFile)
			}

			var signer ssh.Signer
			if x509.IsEncryptedPEMBlock(pemBlock) {
				if tunnel.IdentityFilePassphrase == "" {
					return nil, fmt.Errorf("missing identity file passphrase: %s", tunnel.IdentityFile)
				}

				// 解除私钥上的密码
				derBytes, err := x509.DecryptPEMBlock(pemBlock, []byte(tunnel.IdentityFilePassphrase))
				if err != nil {
					return nil, fmt.Errorf("decrypt identity file failed: %s", err.Error())
				}

				var key interface{}
				switch pemBlock.Type {
				case "RSA PRIVATE KEY":
					key, err = x509.ParsePKCS1PrivateKey(derBytes)
				case "EC PRIVATE KEY":
					key, err = x509.ParseECPrivateKey(derBytes)
				case "DSA PRIVATE KEY":
					key, err = ssh.ParseDSAPrivateKey(derBytes)
				default:
					return nil, fmt.Errorf("unsupported identity key type: %s", pemBlock.Type)
				}
				if err != nil {
					return nil, fmt.Errorf("unrecognized key as type: %s", pemBlock.Type)
				}

				signer, err = ssh.NewSignerFromKey(key)
				if err != nil {
					return nil, fmt.Errorf("parse identity file failed: %s", err.Error())
				}
			} else {
				signer, err = ssh.ParsePrivateKey(pemBytes)
				if err != nil {
					return nil, fmt.Errorf("parse identity file failed: %s", err.Error())
				}
			}

			if signer != nil {
				auths = append(auths, ssh.PublicKeys(signer))
			}
		}

	default:
		return nil, fmt.Errorf("unsupported auth method: %s", tunnel.AuthMethod)
	}
	config := &ssh.ClientConfig{
		User: tunnel.Username,
		Auth: auths,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	addr := fmt.Sprintf("%s:%d", tunnel.Hostname, tunnel.Port)
	sshClient, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	c := new(SSHClient)
	c.sshClient = sshClient
	c.sshTunnel = tunnel
	return c, nil
}

type SSHClient struct {
	sshClient *ssh.Client
	sshTunnel *SSHTunnel
	mutex     sync.Mutex
}

func (client *SSHClient) Dial(network, addr string) (net.Conn, error) {
	if network == "unix" {
		return nil, errors.New("unsupport tunnel to unix domain socket")
	}

	return client.dial(network, addr)
}

func (client *SSHClient) WsDial(network, addr string) (net.Conn, error) {
	conn, err := client.dial(network, addr)
	if err != nil {
		return nil, err
	}

	return net.Conn(IgnoreDeadlineConn{conn}), nil
}

func (client *SSHClient) dial(network, addr string) (net.Conn, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()

	conn, err := client.sshClient.Dial(network, addr)
	if err != nil {
		// ssh连接失败，可能原因很多，如：
		// * ssh: unexpected packet in response to channel open => session失效了
		// * ssh: rejected: administratively prohibited
		// 需要重新生成client后再连接
		newClient, err := client.sshTunnel.Client()
		if err != nil {
			return nil, err
		}

		client.sshClient.Close()
		client.sshClient = newClient.sshClient

		// 重新连接
		conn, err = client.sshClient.Dial(network, addr)
		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}

func (client *SSHClient) DialUnix(addr string) (net.Conn, error) {
	session, err := client.newSession()
	if err != nil {
		return nil, err
	}

	return DialSSHCommand(session, "socat STDIO UNIX-CONNECT:"+addr)
}

func (client *SSHClient) WsDialUnix(addr string) (net.Conn, error) {
	session, err := client.newSession()
	if err != nil {
		return nil, err
	}

	conn, err := DialSSHCommand(session, "socat STDIO UNIX-CONNECT:"+addr)
	if err != nil {
		return nil, err
	}

	return net.Conn(IgnoreDeadlineConn{conn}), nil
}

func (client *SSHClient) newSession() (*ssh.Session, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()

	session, err := client.sshClient.NewSession()
	if err != nil {
		// ssh连接失败，可能原因很多，如：
		// * ssh: unexpected packet in response to channel open => session失效了
		// * ssh: rejected: administratively prohibited
		// 需要重新生成client后再连接
		newClient, err := client.sshTunnel.Client()
		if err != nil {
			return nil, err
		}

		client.sshClient.Close()
		client.sshClient = newClient.sshClient

		// 重新连接
		session, err = client.sshClient.NewSession()
		if err != nil {
			return nil, err
		}
	}

	return session, nil
}

func (client *SSHClient) Close() error {
	return client.sshClient.Close()
}

type SSHCommandConn struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
}

// ssh隧道不支持unix，需要用ssh+socat的方式来处理
// ssh root@ip socat STDIO UNIX-CONNECT:/path/to/unix.sock
func DialSSHCommand(session *ssh.Session, cmd string) (*SSHCommandConn, error) {
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, err
	}

	if err := session.Start(cmd); err != nil {
		session.Close()
		return nil, err
	}

	conn := new(SSHCommandConn)
	conn.session = session
	conn.stdin = stdin
	conn.stdout = stdout
	return conn, nil
}

func (conn *SSHCommandConn) Read(b []byte) (n int, err error) {
	return conn.stdout.Read(b)
}

func (conn *SSHCommandConn) Write(b []byte) (n int, err error) {
	return conn.stdin.Write(b)
}

func (conn *SSHCommandConn) Close() error {
	conn.session.Close()
	return conn.stdin.Close()
}

func (conn *SSHCommandConn) LocalAddr() net.Addr {
	return nil
}

func (conn *SSHCommandConn) RemoteAddr() net.Addr {
	return nil
}

func (conn *SSHCommandConn) SetDeadline(t time.Time) error {
	return nil
}

func (conn *SSHCommandConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (conn *SSHCommandConn) SetWriteDeadline(t time.Time) error {
	return nil
}
