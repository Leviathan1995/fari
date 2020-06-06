package encryption

import (
	"crypto/aes"
	"crypto/cipher"
)

type Cipher struct {
	cipher.Block
	Password []byte
}

func NewCipher(key []byte) *Cipher {
	c, _ := aes.NewCipher(key)
	return &Cipher{
		c,
		key,
	}
}
func (c *Cipher) AesEncrypt(dst, src, iv []byte) error {
	aesEncrypter := cipher.NewCFBEncrypter(c, iv)
	aesEncrypter.XORKeyStream(dst, src)
	return nil
}

func (c *Cipher) AesDecrypt(dst, src, iv []byte) []byte {
	aesDecrypter := cipher.NewCFBDecrypter(c, iv)
	aesDecrypter.XORKeyStream(dst, src)
	return nil
}
