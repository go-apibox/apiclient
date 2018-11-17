// +build !linux

package apiclient

import (
	"net"
)

func FixKeepAlive(conn net.Conn) {
}
