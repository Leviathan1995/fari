package encryption

import (
	"crypto/aes"
	"testing"
)

var key = "1234567890123456"
var src = "wqfhiqhnfihqwiufhiquwhfanfajonfowiuewfniuwenfenwfewiufneiuwfniwenfinweifniewnfinweifneiwnfiwenfinweif" +
	"fioqjwiofjioqwjfioqwjfiojqiowfnqwifnoqwnfonqwiofnoqwinfioqwnfioqwnfioqnwfionqfqwfqwfqwfqwfqwfqwfqwfqwfq" +
	"fwqfqwfqwfqwfqfnfiquwnfiqunfnqwijufniquwnfqwfqwijufniqnwfiqwnfijqwnfijqwnfiqnwfijqnwfinqwjfnqijwfqiwnfi" +
	"fioqjnfiojqwfiojqfiowjioqwjfiojqwfiojqwiofjioqwfjioqjwfiojqiowfjioqwjfioqjwfiojqwiofjioqwjfioqwjfiojqwi"

func TestNewCipher(t *testing.T) {
	c := NewCipher([]byte(key))
	encrypted := make([]byte, len(src))
	iv := []byte(key)[:aes.BlockSize]
	c.AesEncrypt(encrypted, []byte(src), iv)

	decrypted := make([]byte, len(encrypted))
	c.AesDecrypt(decrypted, encrypted, iv)

	if src != string(decrypted) {
		t.Errorf("%s", "AES CFB failed.")
	}
}
