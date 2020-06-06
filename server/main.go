package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"

	"github.com/fari/server/util"
)

func main() {
	var conf string
	var config map[string]interface{}
	flag.StringVar(&conf, "c", ".server.json", "server config")
	flag.Parse()

	bytes, err := ioutil.ReadFile(conf)
	if err != nil {
		log.Fatalf("read %s failed.", conf)
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("parse %s failed.", conf)
	}
	s := server.NewServer(config["listen_addr"].(string), config["password"].(string))
	s.Listen()
}
