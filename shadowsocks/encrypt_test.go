package shadowsocks

import (
	"crypto/rand"
	"io"
	"reflect"
	"testing"
)

const text = "Don't tell me the moon is shining; show me the glint of light on broken glass."

func testCipher(t *testing.T, c *Cipher, msg string) {
	n := len(text)
	cipherBuf := make([]byte, n)
	originTxt := make([]byte, n)

	c.encrypt(cipherBuf, []byte(text))
	c.decrypt(originTxt, cipherBuf)

	if string(originTxt) != text {
		t.Error(msg, "encrypt then decrytp does not get original text")
	}
}

func TestEvpBytesToKey(t *testing.T) {
	// key, iv := evpBytesToKey("foobar", 32, 16)
	key := evpBytesToKey("foobar", 32)
	keyTarget := []byte{0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12, 0xc6, 0x3f, 0x56, 0x83, 0x78, 0x52, 0x96, 0x14, 0xd2, 0x2d, 0xdb, 0x49, 0x23, 0x7d, 0x2f, 0x60, 0xbf, 0xdf}
	// ivTarget := []byte{0x0e, 0xbf, 0x58, 0x78, 0xe8, 0x2a, 0xf7, 0xda, 0x61, 0x8e, 0xd5, 0x6f, 0xc6, 0x7d, 0x4a, 0xb7}
	if !reflect.DeepEqual(key, keyTarget) {
		t.Errorf("key not correct\n\texpect: %v\n\tgot:   %v\n", keyTarget, key)
	}
	// if !reflect.DeepEqual(iv, ivTarget) {
	// 	t.Errorf("iv not correct\n\texpect: %v\n\tgot:   %v\n", ivTarget, iv)
	// }
}

func testBlockCipher(t *testing.T, method string) {
	var cipher *Cipher
	var err error

	cipher, err = NewCipher(method, "foobar")
	if err != nil {
		t.Fatal(method, "NewCipher:", err)
	}
	cipherCopy := cipher.Copy()
	iv, err := cipher.initEncrypt()
	if err != nil {
		t.Error(method, "initEncrypt:", err)
	}
	if err = cipher.initDecrypt(iv); err != nil {
		t.Error(method, "initDecrypt:", err)
	}
	testCipher(t, cipher, method)

	iv, err = cipherCopy.initEncrypt()
	if err != nil {
		t.Error(method, "copy initEncrypt:", err)
	}
	if err = cipherCopy.initDecrypt(iv); err != nil {
		t.Error(method, "copy initDecrypt:", err)
	}
	testCipher(t, cipherCopy, method+" copy")
}

func TestAES128CFB(t *testing.T) {
	testBlockCipher(t, "aes-128-cfb")
}

func TestAES192CFB(t *testing.T) {
	testBlockCipher(t, "aes-192-cfb")
}

func TestAES256CFB(t *testing.T) {
	testBlockCipher(t, "aes-256-cfb")
}

func TestAES128CTR(t *testing.T) {
	testBlockCipher(t, "aes-128-ctr")
}

func TestAES192CTR(t *testing.T) {
	testBlockCipher(t, "aes-192-ctr")
}

func TestAES256CTR(t *testing.T) {
	testBlockCipher(t, "aes-256-ctr")
}

func TestDES(t *testing.T) {
	testBlockCipher(t, "des-cfb")
}

func TestRC4MD5(t *testing.T) {
	testBlockCipher(t, "rc4-md5")
}

func TestRC4MD56(t *testing.T) {
	testBlockCipher(t, "rc4-md5-6")
}

func TestChaCha20(t *testing.T) {
	testBlockCipher(t, "chacha20")
}

func TestChaCha20IETF(t *testing.T) {
	testBlockCipher(t, "chacha20-ietf")
}

var cipherKey = make([]byte, 64)
var cipherIv = make([]byte, 64)

const CIPHER_BENCHMARK_BUFFER_LEN = 4096

func init() {
	for i := 0; i < len(cipherKey); i++ {
		cipherKey[i] = byte(i)
	}
	io.ReadFull(rand.Reader, cipherIv)
}

func benchmarkCipherInit(b *testing.B, method string) {
	ci := cipherMethod[method]
	key := cipherKey[:ci.keyLen]
	buf := make([]byte, ci.ivLen)
	for i := 0; i < b.N; i++ {
		ci.newStream(key, buf, Encrypt)
	}
}

func BenchmarkAES128CFBInit(b *testing.B) {
	benchmarkCipherInit(b, "aes-128-cfb")
}

func BenchmarkAES19CFB2Init(b *testing.B) {
	benchmarkCipherInit(b, "aes-192-cfb")
}

func BenchmarkAES256CFBInit(b *testing.B) {
	benchmarkCipherInit(b, "aes-256-cfb")
}

func BenchmarkAES128CTRInit(b *testing.B) {
	benchmarkCipherInit(b, "aes-128-ctr")
}

func BenchmarkAES192CTRInit(b *testing.B) {
	benchmarkCipherInit(b, "aes-192-ctr")
}

func BenchmarkAES256CTRInit(b *testing.B) {
	benchmarkCipherInit(b, "aes-256-ctr")
}

func BenchmarkBlowFishInit(b *testing.B) {
	benchmarkCipherInit(b, "bf-cfb")
}

func BenchmarkCast5Init(b *testing.B) {
	benchmarkCipherInit(b, "cast5-cfb")
}

func BenchmarkDESInit(b *testing.B) {
	benchmarkCipherInit(b, "des-cfb")
}

func BenchmarkRC4MD5Init(b *testing.B) {
	benchmarkCipherInit(b, "rc4-md5")
}

func BenchmarkRC4MD56Init(b *testing.B) {
	benchmarkCipherInit(b, "rc4-md5-5")
}

func BenchmarkChaCha20Init(b *testing.B) {
	benchmarkCipherInit(b, "chacha20")
}

func BenchmarkChaCha20IETFInit(b *testing.B) {
	benchmarkCipherInit(b, "chacha20-ietf")
}

func BenchmarkSalsa20Init(b *testing.B) {
	benchmarkCipherInit(b, "salsa20")
}

func benchmarkCipherEncrypt(b *testing.B, method string) {
	ci := cipherMethod[method]
	key := cipherKey[:ci.keyLen]
	iv := cipherIv[:ci.ivLen]
	enc, err := ci.newStream(key, iv, Encrypt)
	if err != nil {
		b.Error(err)
	}
	src := make([]byte, CIPHER_BENCHMARK_BUFFER_LEN)
	dst := make([]byte, CIPHER_BENCHMARK_BUFFER_LEN)
	io.ReadFull(rand.Reader, src)
	for i := 0; i < b.N; i++ {
		enc.XORKeyStream(dst, src)
	}
}

func BenchmarkAES128CFBEncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-128-cfb")
}

func BenchmarkAES192CFBEncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-192-cfb")
}

func BenchmarkAES256CFBEncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-256-cfb")
}

func BenchmarkAES128CTREncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-128-ctr")
}

func BenchmarkAES192CTREncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-192-ctr")
}

func BenchmarkAES256CTREncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-256-ctr")
}

func BenchmarkBlowFishEncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "bf-cfb")
}

func BenchmarkCast5Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "cast5-cfb")
}

func BenchmarkDESEncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "des-cfb")
}

func BenchmarkRC4MD5Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "rc4-md5")
}

func BenchmarkRC4MD56Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "rc4-md5-6")
}

func BenchmarkChacha20Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "chacha20")
}

func BenchmarkChacha20IETFEncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "chacha20-ietf")
}

func BenchmarkSalsa20Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "salsa20")
}

func benchmarkCipherDecrypt(b *testing.B, method string) {
	ci := cipherMethod[method]
	key := cipherKey[:ci.keyLen]
	iv := cipherIv[:ci.ivLen]
	enc, err := ci.newStream(key, iv, Encrypt)
	if err != nil {
		b.Error(err)
	}
	dec, err := ci.newStream(key, iv, Decrypt)
	if err != nil {
		b.Error(err)
	}
	src := make([]byte, CIPHER_BENCHMARK_BUFFER_LEN)
	dst := make([]byte, CIPHER_BENCHMARK_BUFFER_LEN)
	io.ReadFull(rand.Reader, src)
	enc.XORKeyStream(dst, src)
	for i := 0; i < b.N; i++ {
		dec.XORKeyStream(src, dst)
	}
}

func BenchmarkAES128CFBDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "aes-128-cfb")
}

func BenchmarkAES192CFBDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "aes-192-cfb")
}

func BenchmarkAES256CFBDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "aes-256-cfb")
}

func BenchmarkAES128CTRDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "aes-128-ctr")
}

func BenchmarkAES192CTRDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "aes-192-ctr")
}

func BenchmarkAES256CTRDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "aes-256-ctr")
}

func BenchmarkBlowFishDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "bf-cfb")
}

func BenchmarkCast5Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "cast5-cfb")
}

func BenchmarkDESDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "des-cfb")
}

func BenchmarkRC4MD5Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "rc4-md5")
}

func BenchmarkRC4MD56Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "rc4-md5-6")
}

func BenchmarkChaCha20Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "chacha20")
}

func BenchmarkChaCha20IETFDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "chacha20-ietf")
}

func BenchmarkSalsa20Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "salsa20")
}
