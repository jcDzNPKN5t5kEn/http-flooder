package Utils

import (
	"fmt"
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
