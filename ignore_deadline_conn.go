package apiclient

import (
	"net"
	"time"
)

// ssh tunnel连接调用conn.SetDeadline会报错：
// tcpChan: deadline not supported
// 因此在此封装一层SetDeadline禁止调用
type IgnoreDeadlineConn struct {
	conn net.Conn
}

func (conn IgnoreDeadlineConn) Read(b []byte) (n int, err error) {
	return conn.conn.Read(b)
}

func (conn IgnoreDeadlineConn) Write(b []byte) (n int, err error) {
	return conn.conn.Write(b)
}

func (conn IgnoreDeadlineConn) Close() error {
	return conn.conn.Close()
}

func (conn IgnoreDeadlineConn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

func (conn IgnoreDeadlineConn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

func (conn IgnoreDeadlineConn) SetDeadline(t time.Time) error {
	return nil
}
func (conn IgnoreDeadlineConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (conn IgnoreDeadlineConn) SetWriteDeadline(t time.Time) error {
	return nil
}
