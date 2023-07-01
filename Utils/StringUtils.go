package Utils

import (
	"io/ioutil"
	"strings"
)

func FileToList(file string) []string {
		proxyListBytes, err := ioutil.ReadFile(file)
		if err != nil {
			panic(err)
		}
		return strings.Split(string(proxyListBytes), "\n")
}
