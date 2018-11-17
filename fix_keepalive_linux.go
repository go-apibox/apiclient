// +build linux

package apiclient

import (
	"net"
	"time"

	"github.com/felixge/tcpkeepalive"
)

// REF: http://felixge.de/2014/08/26/tcp-keepalive-with-golang.html
// calling SetKeepAlivePeriod with an argument of 30 seconds will cause
// a total timeout of 10 minutes and 30 seconds for OSX (30 + 8 * 75),
// but 4 minutes and 30 seconds on Linux (30 + 8 * 30).
func FixKeepAlive(conn net.Conn) {
	// 手工设置keepalive
	kaConn, err := tcpkeepalive.EnableKeepAlive(conn)
	if err == nil {
		kaConn.SetKeepAliveIdle(10 * time.Second)    // 正常情况10S一次检测
		kaConn.SetKeepAliveCount(4)                  // 失败后最多检测4次
		kaConn.SetKeepAliveInterval(2 * time.Second) // 失败时检测时间间隔为2秒
	}
}
