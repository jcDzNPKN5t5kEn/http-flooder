package Utils

import (
	"crypto/tls"
	"net"
)

func ReadConn(conn net.Conn) ([]byte) {
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func ReadTLSConn(conn *tls.Conn) ([]byte) {
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}
