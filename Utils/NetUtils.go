package Utils

import (
	"crypto/tls"
	"fmt"
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

func StartProxyHTTP(conn net.Conn, targetAddr string) (bool) {
conn.Write([]byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n", targetAddr, targetAddr)))
		reply := ReadConn(conn)
		if reply == nil || len(string(reply)) < 14 || string(reply)[:14] != "HTTP/1.1 200 C" {
			return false
		}
		return true
}

