package server

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/fari/encryption"
	"github.com/fari/service"
)

type server struct {
	*service.Service
}

func NewServer(addr, password string) *server {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", addr)
	c := encryption.NewCipher([]byte(password))
	return &server{
		&service.Service{
			Cipher:     c,
			ListenAddr: tcpAddr,
		},
	}
}

func (s *server) Listen() {
	listen, err := net.ListenTCP("tcp", s.ListenAddr)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("Server启动成功,监听在 %s:%d, 密码: %s", s.ListenAddr.IP, s.ListenAddr.Port, s.Cipher.Password)
	defer listen.Close()

	for {
		userConn, err := listen.AcceptTCP()
		if err != nil {
			log.Fatalf("%s", err.Error())
			continue
		}
		userConn.SetLinger(0)
		go s.handle(userConn)
	}
}

func (s *server) handle(userConn *net.TCPConn) {
	defer userConn.Close()
	/*
	 *  RFC 1928 - IETF
	 * https://www.ietf.org/rfc/rfc1928.txt
	 */

	/*	We already remove SOCKS5 parsing to the client, but if the client can't directly
	 *  connect to the destination address, the client must send the user the last request to the
	 *  proxy knows what address to connect, and if connect the destination success, we
	 *  also need to notify client.
	 */

	/** Get the connect command and the destination address */
	buf := make([]byte, service.BUFFSIZE)
	n, err := s.HTTPDecode(userConn, buf, service.SERVER)
	if err != nil {
		return
	}

	if buf[1] != 0x01 {	/** Only support connect */
		return
	}

	/** Parse destination addr and port */
	var desIP []byte
	switch buf[3] {
	case 0x01:
		desIP = buf[4 : 4+net.IPv4len]
	case 0x03:
		ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:n-2]))
		if err != nil {
			return
		}
		desIP = ipAddr.IP
	case 0x04:
		desIP = buf[4 : 4+net.IPv6len]
	default:
		return
	}
	dstPort := buf[n-2 : n]
	dstAddr := &net.TCPAddr{
		IP:   desIP,
		Port: int(binary.BigEndian.Uint16(dstPort)),
	}

	/** Step4: connect to the destination server and send a reply to client */
	dstServer, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		log.Printf("Connect to destination addr %s failed", dstAddr.String())
		return
	} else {
		defer dstServer.Close()
		dstServer.SetLinger(0)
		/** If connect to the dst addr success, we need to notify client */
		_, errWrite := s.HTTPEncode(userConn, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, service.SERVER)
		if errWrite != nil {
			return
		}
	}

	log.Printf("Connect to destination addr %s", dstAddr.String())

	go func() {
		err := s.DecodeTransfer(dstServer, userConn, service.SERVER)
		if err != nil {
			userConn.Close()
			dstServer.Close()
		}
	}()

	s.EncodeTransfer(userConn, dstServer, service.SERVER)
}
