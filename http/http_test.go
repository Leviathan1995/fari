package http

import (
	"log"
	"testing"
)

var plaintext = "uzon57jd0v869t7w"
var incompleteHttpRequest = []byte("GET /blog.html HTTP/1.1\r\n" +
	"Accept:image/gif.image/jpeg,*/*\r\n" +
	"Accept-Language:zh-cn\r\n" +
	"Connection:Keep-Alive\r\n")

var incompleteHttpResponse = []byte("HTTP/1.1 200 OK\r\n" +
	"Content-Type: text/html\r\n" +
	"Date: " +  GMT() + "\r\n" +
	"Server: Microsoft-IIS/6.0\r\n" +
	"Content-Type: text/html\r\n")

func TestGMT(t *testing.T) {
	timestamp := GMT()
	if "GMT" != timestamp[len(timestamp) -3:len(timestamp)] {
		log.Print("GMT() is invalid")
	} else {
		log.Print("GMT() is valid")
	}
}


func TestParseHttpRequest(t *testing.T) {
	/** Empty http request */
	msg := make([]byte, 0)
	msg = ParseHTTPRequest(msg)
	if len(msg) == 0 {
		log.Print("Empty http request test success.")
	} else {
		log.Print("Empty http request test failed.")
	}

	/** Incomplete http request */
	msg = ParseHTTPRequest(incompleteHttpRequest)
	if len(msg) == 0 {
		log.Print("Incomplete http request test success.")
	} else {
		log.Print("Incomplete http request test failed.")
	}

	/** Complete http request */
	msg = NewHTTPRequest([]byte(plaintext))
	msg = ParseHTTPRequest(msg)
	if string(msg) == plaintext {
		log.Print("Complete http request test success.")
	} else {
		log.Print("Complete http request test failed.")
	}
}

func TestParseHttpResponse(t *testing.T) {
	/** Empty http response */
	msg := make([]byte, 0)
	msg = ParseHTTPResponse(msg)
	if len(msg) == 0 {
		log.Print("Empty http response test success.")
	} else {
		log.Print("Empty http response test failed.")
	}

	/** Incomplete http response */
	msg = ParseHTTPResponse(incompleteHttpResponse)
	if len(msg) == 0 {
		log.Print("Incomplete http response test success.")
	} else {
		log.Print("Incomplete http response test failed.")
	}

	/** Complete http response */
	msg = NewHTTPResponse([]byte(plaintext))
	msg = ParseHTTPResponse(msg)
	if string(msg) == plaintext {
		log.Print("Complete http response test success.")
	} else {
		log.Print("Complete http response test failed.")
	}
}