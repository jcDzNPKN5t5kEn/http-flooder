package Utils

import (
	"fmt"
	"net"
	"net/url"
)

func SetPort(host, port string) (string, error) {
	u, err := url.Parse(fmt.Sprintf("http://%s", host))
	if err != nil {
		return "", err
	}
	u.Host = fmt.Sprintf("%s:%s", u.Hostname(), port)
	return u.Host, nil
}

func ToIPWithPort(parsedTarget *url.URL, https bool) string{
	target := ""
	targetIPs, _ := net.LookupIP(parsedTarget.Hostname())
	if parsedTarget.Port() == "" {
		if https {
			parsedTarget.Host, _ = SetPort(parsedTarget.Host, "443")
		} else {
			parsedTarget.Host, _ = SetPort(parsedTarget.Host, "80")
		}
	}
	if targetIPs[0].To4() != nil {
		// IPv4 address
		target = targetIPs[0].String() + ":" + parsedTarget.Port()
	} else {
		// IPv6 address
		target = "[" + targetIPs[0].String() + "]:" + parsedTarget.Port()
	}
	return target
}
func IsValidIPPort(ipPort string) bool {
	host, port, err := net.SplitHostPort(ipPort)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	if _, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(ip.String(), port)); err != nil {
		return false
	}

	return true
}
