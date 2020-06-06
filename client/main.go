package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"

	"github.com/fari/client/util"
)


func main() {
	var conf string
	var config map[string]interface{}
	flag.StringVar(&conf, "c", ".client.json", "client config")
	flag.Parse()

	bytes, err := ioutil.ReadFile(conf)
	if err != nil {
		log.Fatalf("Reading %s failed.", conf)
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("Parsing %s failed.", conf)
	}

	var forceIP, forceURL []string
	url, _ := config["url"].([]interface{})

	for _, url := range url {
		forceURL = append(forceURL, url.(string))
	}

	for _, url := range forceURL {
		ipAddr, _ := net.LookupIP(url)
		for _, ip := range ipAddr {
			forceIP = append(forceIP, ip.String())
		}
	}

	var proxyIP []string
	proxy, _ := config["remote_addr"].([]interface{})

	for _, ip := range proxy {
		proxyIP = append(proxyIP, ip.(string))
	}

	clientImpl := client.NewClient(proxyIP, config["listen_addr"].(string), config["password"].(string), forceIP)
	clientImpl.Listen()
}
