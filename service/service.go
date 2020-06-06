package service

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/fari/encryption"
	"github.com/fari/http"
	)

const BUFFSIZE = 1024 * 4
const LINGTHPACKAGE = 8

type Type int

const (
	SERVER = iota
	CLIENT
)

type Service struct {
	ListenAddr *net.TCPAddr
	RemoteAddrs []*net.TCPAddr
	StableProxy *net.TCPAddr
	Cipher     *encryption.Cipher
}


func (s *Service) HTTPDecode(conn *net.TCPConn, src []byte, cs Type) (n int, err error) {
	lengthMsg := make([]byte, LINGTHPACKAGE)
	nRead, err := conn.Read(lengthMsg)
	if nRead == 0 || err != nil {
		return
	}

	length := http.BytesToInt32(lengthMsg)

	source := make([]byte, length)
	nRead, err = conn.Read(source)
	if nRead == 0 || err != nil {
		return
	}

	var cRead int
	for nRead != int(length) {
		cRead, err = conn.Read(source[nRead:])
		if err != nil {
			return
		}
		nRead += cRead
	}

	var encrypted []byte

	/** Parse net packet */
	if cs == SERVER {
		encrypted = http.ParseHTTPRequest(source)
	} else {
		encrypted = http.ParseHTTPResponse(source)
	}

	n = len(encrypted)
	iv := (s.Cipher.Password)[:aes.BlockSize]
	(*s.Cipher).AesDecrypt(src[:n], encrypted, iv)

	return
}


/** Warping the http packet with data */
func (s *Service) HTTPEncode(conn *net.TCPConn, src []byte, cs Type) (n int, err error) {
	iv := (s.Cipher.Password)[:aes.BlockSize]
	encrypted := make([]byte, len(src))
	(*s.Cipher).AesEncrypt(encrypted, src, iv)

	var httpMsg []byte
	if cs == SERVER {
		httpMsg = http.NewHTTPResponse(encrypted)
	} else {
		httpMsg = http.NewHTTPRequest(encrypted)
	}

	lengthMsg := http.Int32ToBytes(uint32(len(httpMsg)))

	/** [ length : content ] */
	msg := append(lengthMsg, httpMsg...)

	return conn.Write(msg)
}


func (s *Service) EncodeTransfer(dst *net.TCPConn, src *net.TCPConn, cs Type) error {
	buf := make([]byte, BUFFSIZE)

	for {
		readCount, errRead := src.Read(buf)
		if errRead != nil {
			if errRead != io.EOF {
				return nil
			} else {
				return errRead
			}
		}
		if readCount > 0 {
			_, errWrite := s.HTTPEncode(dst, buf[0:readCount], cs)
			if errWrite != nil {
				return errWrite
			}
		}
	}
}


func (s *Service) DecodeTransfer(dst *net.TCPConn, src *net.TCPConn, cs Type) error {
	buf := make([]byte, BUFFSIZE)

	for {
		readCount, errRead := s.HTTPDecode(src, buf, cs)
		if errRead != nil {
			if errRead != io.EOF {
				return nil
			} else {
				return errRead
			}
		}
		if readCount > 0 {
			writeCount, errWrite := dst.Write(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}


func (s *Service) Transfer(srcConn *net.TCPConn, dstConn *net.TCPConn) error {
	buf := make([]byte, BUFFSIZE * 2)
	for {
		readCount, errRead := srcConn.Read(buf)
		if errRead != nil {
			if errRead != io.EOF {
				return nil
			} else {
				return errRead
			}
		}
		if readCount > 0 {
			_, errWrite := dstConn.Write(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
		}
	}
}

func (s *Service) DialRemote() (*net.TCPConn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	remoteConn, err := d.Dial("tcp", s.StableProxy.String())
	if err != nil {
		log.Printf("连接到远程服务器 %s 失败:%s", s.StableProxy.String(), err)

		/** Try to connect the other proxies **/
		for _, proxy := range s.RemoteAddrs {
			log.Printf("尝试其他远程服务器: %s", proxy.String())
			remoteConn, err := d.Dial("tcp", proxy.String())
			if err == nil {
				s.StableProxy = proxy
				tcpConn, _ := remoteConn.(*net.TCPConn)
				return tcpConn, nil

			}
		}
		return nil, errors.New(fmt.Sprintf("所有远程服务器连接均失败"))
	}
	log.Printf("连接到远程服务器 %s 成功", s.StableProxy.String())
	tcpConn, _ := remoteConn.(*net.TCPConn)
	return tcpConn, nil
}


func (s *Service) CustomRead(userConn *net.TCPConn, buf [] byte) (int, error) {
	readCount, errRead := userConn.Read(buf)
	if errRead != nil {
		if errRead != io.EOF {
			return readCount, nil
		} else {
			return readCount, errRead
		}
	}
	return readCount, nil
}

func (s *Service) CustomWrite(userConn *net.TCPConn, buf [] byte, bufLen int) error {
	writeCount, errWrite := userConn.Write(buf)
	if errWrite != nil {
		return errWrite
	}
	if bufLen != writeCount {
		return io.ErrShortWrite
	}
	return nil
}

func (s *Service) ParseSOCKS5(userConn *net.TCPConn) (*net.TCPAddr, []byte, error){
	buf := make([]byte, BUFFSIZE)

	readCount, errRead := s.CustomRead(userConn, buf)
	if readCount > 0 && errRead == nil {
		if buf[0] != 0x05 {
			/** Version Number */
			return &net.TCPAddr{}, nil, errors.New("Only Support SOCKS5")
		} else {
			/** [SOCKS5, NO AUTHENTICATION REQUIRED]  */
			errWrite := s.CustomWrite(userConn, []byte{0x05, 0x00}, 2)
			if errWrite != nil {
				return &net.TCPAddr{}, nil, errors.New("Response SOCKS5 failed at the first stage.")
			}
		}
	}

	readCount, errRead = s.CustomRead(userConn, buf)
	if readCount > 0 && errRead == nil {
		if buf[1] != 0x01 {
			/** Only support CONNECT method */
			return &net.TCPAddr{}, nil, errors.New("Only support CONNECT and UDP ASSOCIATE method.")
		}

		var desIP []byte
		switch buf[3] { /** checking ATYPE */
		case 0x01: /* IPv4 */
			desIP = buf[4 : 4+net.IPv4len]
		case 0x03: /** DOMAINNAME */
			ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:readCount-2]))
			if err != nil {
				return &net.TCPAddr{}, nil, errors.New("Parse IP failed")
			}
			desIP = ipAddr.IP
		case 0x04: /** IPV6 */
			desIP = buf[4 : 4+net.IPv6len]
		default:
			return &net.TCPAddr{}, nil, errors.New("Wrong DST.ADDR and DST.PORT")
		}
		dstPort := buf[readCount-2 : readCount]
		dstAddr := &net.TCPAddr{
			IP:   desIP,
			Port: int(binary.BigEndian.Uint16(dstPort)),
		}

		return dstAddr, buf[:readCount], errRead
	}
	return &net.TCPAddr{}, nil, errRead
}
