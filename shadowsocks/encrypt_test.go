package shadowsocks

import (
	"crypto/rand"
	"crypto/rc4"
	"io"
	"reflect"
	"testing"
)

func TestEncrypTable1(t *testing.T) {
	encTarget := []byte{60, 53, 84, 138, 217, 94, 88, 23, 39, 242, 219, 35, 12, 157, 165, 181, 255, 143, 83, 247, 162, 16, 31, 209, 190, 171, 115, 65, 38, 41, 21, 245, 236, 46, 121, 62, 166, 233, 44, 154, 153, 145, 230, 49, 128, 216, 173, 29, 241, 119, 64, 229, 194, 103, 131, 110, 26, 197, 218, 59, 204, 56, 27, 34, 141, 221, 149, 239, 192, 195, 24, 155, 170, 183, 11, 254, 213, 37, 137, 226, 75, 203, 55, 19, 72, 248, 22, 129, 33, 175, 178, 10, 198, 71, 77, 36, 113, 167, 48, 2, 117, 140, 142, 66, 199, 232, 243, 32, 123, 54, 51, 82, 57, 177, 87, 251, 150, 196, 133, 5, 253, 130, 8, 184, 14, 152, 231, 3, 186, 159, 76, 89, 228, 205, 156, 96, 163, 146, 18, 91, 132, 85, 80, 109, 172, 176, 105, 13, 50, 235, 127, 0, 189, 95, 98, 136, 250, 200, 108, 179, 211, 214, 106, 168, 78, 79, 74, 210, 30, 73, 201, 151, 208, 114, 101, 174, 92, 52, 120, 240, 15, 169, 220, 182, 81, 224, 43, 185, 40, 99, 180, 17, 212, 158, 42, 90, 9, 191, 45, 6, 25, 4, 222, 67, 126, 1, 116, 124, 206, 69, 61, 7, 68, 97, 202, 63, 244, 20, 28, 58, 93, 134, 104, 144, 227, 147, 102, 118, 135, 148, 47, 238, 86, 112, 122, 70, 107, 215, 100, 139, 223, 225, 164, 237, 111, 125, 207, 160, 187, 246, 234, 161, 188, 193, 249, 252}
	decTarget := []byte{151, 205, 99, 127, 201, 119, 199, 211, 122, 196, 91, 74, 12, 147, 124, 180, 21, 191, 138, 83, 217, 30, 86, 7, 70, 200, 56, 62, 218, 47, 168, 22, 107, 88, 63, 11, 95, 77, 28, 8, 188, 29, 194, 186, 38, 198, 33, 230, 98, 43, 148, 110, 177, 1, 109, 82, 61, 112, 219, 59, 0, 210, 35, 215, 50, 27, 103, 203, 212, 209, 235, 93, 84, 169, 166, 80, 130, 94, 164, 165, 142, 184, 111, 18, 2, 141, 232, 114, 6, 131, 195, 139, 176, 220, 5, 153, 135, 213, 154, 189, 238, 174, 226, 53, 222, 146, 162, 236, 158, 143, 55, 244, 233, 96, 173, 26, 206, 100, 227, 49, 178, 34, 234, 108, 207, 245, 204, 150, 44, 87, 121, 54, 140, 118, 221, 228, 155, 78, 3, 239, 101, 64, 102, 17, 223, 41, 137, 225, 229, 66, 116, 171, 125, 40, 39, 71, 134, 13, 193, 129, 247, 251, 20, 136, 242, 14, 36, 97, 163, 181, 72, 25, 144, 46, 175, 89, 145, 113, 90, 159, 190, 15, 183, 73, 123, 187, 128, 248, 252, 152, 24, 197, 68, 253, 52, 69, 117, 57, 92, 104, 157, 170, 214, 81, 60, 133, 208, 246, 172, 23, 167, 160, 192, 76, 161, 237, 45, 4, 58, 10, 182, 65, 202, 240, 185, 241, 79, 224, 132, 51, 42, 126, 105, 37, 250, 149, 32, 243, 231, 67, 179, 48, 9, 106, 216, 31, 249, 19, 85, 254, 156, 115, 255, 120, 75, 16}
	key := evpBytesToKey("foobar!", 16)
	enc, dec := newTableCipher(key)
	if !reflect.DeepEqual([]byte(enc), encTarget) {
		t.Error("Password foobar encrypt table wrong")
	}
	if !reflect.DeepEqual([]byte(dec), decTarget) {
		t.Error("Password foobar decrypt table wrong")
	}
}

func TestEncryptTable2(t *testing.T) {
	encTarget := []byte{124, 30, 170, 247, 27, 127, 224, 59, 13, 22, 196, 76, 72, 154, 32, 209, 4, 2, 131, 62, 101, 51, 230, 9, 166, 11, 99, 80, 208, 112, 36, 248, 81, 102, 130, 88, 218, 38, 168, 15, 241, 228, 167, 117, 158, 41, 10, 180, 194, 50, 204, 243, 246, 251, 29, 198, 219, 210, 195, 21, 54, 91, 203, 221, 70, 57, 183, 17, 147, 49, 133, 65, 77, 55, 202, 122, 162, 169, 188, 200, 190, 125, 63, 244, 96, 31, 107, 106, 74, 143, 116, 148, 78, 46, 1, 137, 150, 110, 181, 56, 95, 139, 58, 3, 231, 66, 165, 142, 242, 43, 192, 157, 89, 175, 109, 220, 128, 0, 178, 42, 255, 20, 214, 185, 83, 160, 253, 7, 23, 92, 111, 153, 26, 226, 33, 176, 144, 18, 216, 212, 28, 151, 71, 206, 222, 182, 8, 174, 205, 201, 152, 240, 155, 108, 223, 104, 239, 98, 164, 211, 184, 34, 193, 14, 114, 187, 40, 254, 12, 67, 93, 217, 6, 94, 16, 19, 82, 86, 245, 24, 197, 134, 132, 138, 229, 121, 5, 235, 238, 85, 47, 103, 113, 179, 69, 250, 45, 135, 156, 25, 61, 75, 44, 146, 189, 84, 207, 172, 119, 53, 123, 186, 120, 171, 68, 227, 145, 136, 100, 90, 48, 79, 159, 149, 39, 213, 236, 126, 52, 60, 225, 199, 105, 73, 233, 252, 118, 215, 35, 115, 64, 37, 97, 129, 161, 177, 87, 237, 141, 173, 191, 163, 140, 234, 232, 249}
	decTarget := []byte{117, 94, 17, 103, 16, 186, 172, 127, 146, 23, 46, 25, 168, 8, 163, 39, 174, 67, 137, 175, 121, 59, 9, 128, 179, 199, 132, 4, 140, 54, 1, 85, 14, 134, 161, 238, 30, 241, 37, 224, 166, 45, 119, 109, 202, 196, 93, 190, 220, 69, 49, 21, 228, 209, 60, 73, 99, 65, 102, 7, 229, 200, 19, 82, 240, 71, 105, 169, 214, 194, 64, 142, 12, 233, 88, 201, 11, 72, 92, 221, 27, 32, 176, 124, 205, 189, 177, 246, 35, 112, 219, 61, 129, 170, 173, 100, 84, 242, 157, 26, 218, 20, 33, 191, 155, 232, 87, 86, 153, 114, 97, 130, 29, 192, 164, 239, 90, 43, 236, 208, 212, 185, 75, 210, 0, 81, 227, 5, 116, 243, 34, 18, 182, 70, 181, 197, 217, 95, 183, 101, 252, 248, 107, 89, 136, 216, 203, 68, 91, 223, 96, 141, 150, 131, 13, 152, 198, 111, 44, 222, 125, 244, 76, 251, 158, 106, 24, 42, 38, 77, 2, 213, 207, 249, 147, 113, 135, 245, 118, 193, 47, 98, 145, 66, 160, 123, 211, 165, 78, 204, 80, 250, 110, 162, 48, 58, 10, 180, 55, 231, 79, 149, 74, 62, 50, 148, 143, 206, 28, 15, 57, 159, 139, 225, 122, 237, 138, 171, 36, 56, 115, 63, 144, 154, 6, 230, 133, 215, 41, 184, 22, 104, 254, 234, 253, 187, 226, 247, 188, 156, 151, 40, 108, 51, 83, 178, 52, 3, 31, 255, 195, 53, 235, 126, 167, 120}
	key := evpBytesToKey("barfoo!", 16)
	enc, dec := newTableCipher(key)
	if !reflect.DeepEqual([]byte(enc), encTarget) {
		t.Error("Password barfoo! encrypt table wrong")
	}
	if !reflect.DeepEqual([]byte(dec), decTarget) {
		t.Error("Password barfoo! decrypt table wrong")
	}
}

const text = "Don't tell me the moon is shining; show me the glint of light on broken glass."

func testCiphter(t *testing.T, c *Cipher, msg string) {
	n := len(text)
	cipherBuf := make([]byte, n)
	originTxt := make([]byte, n)

	c.encrypt(cipherBuf, []byte(text))
	c.decrypt(originTxt, cipherBuf)

	if string(originTxt) != text {
		t.Error(msg, "encrypt then decrytp does not get original text")
	}
}

func TestTableCipher(t *testing.T) {
	cipher, err := NewCipher("", "OpenSesame!")
	if err != nil {
		t.Fatal("Should not get error generating table cipher")
	}
	if _, ok := cipher.enc.(tableCipher); !ok {
		t.Error("Should get table cipher")
	} else {
		testCiphter(t, cipher, "TableCipher")
	}
}

func TestRC4Cipher(t *testing.T) {
	cipher, err := NewCipher("no-such-method", "foobar")
	if err == nil {
		t.Error("Should return error for unsupported encryption method")
	}

	cipher, err = NewCipher("rc4", "")
	if err == nil {
		t.Error("Should get error for empty key creating rc4 cipher")
	}
	cipher, err = NewCipher("rc4", "Alibaba")
	ciphercopy := cipher.Copy()
	if err != nil {
		t.Error("Should not error creating rc4 cipher with key Alibaba")
	}
	if _, ok := cipher.enc.(*rc4.Cipher); !ok {
		t.Error("Should get rc4 cipher")
	} else {
		testCiphter(t, cipher, "RC4Cipher")
		testCiphter(t, ciphercopy, "RC4Cipher copy")
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
	testCiphter(t, cipher, method)

	iv, err = cipherCopy.initEncrypt()
	if err != nil {
		t.Error(method, "copy initEncrypt:", err)
	}
	if err = cipherCopy.initDecrypt(iv); err != nil {
		t.Error(method, "copy initDecrypt:", err)
	}
	testCiphter(t, cipherCopy, method+" copy")
}

func TestAES128(t *testing.T) {
	testBlockCipher(t, "aes-128-cfb")
}

func TestAES192(t *testing.T) {
	testBlockCipher(t, "aes-192-cfb")
}

func TestAES256(t *testing.T) {
	testBlockCipher(t, "aes-256-cfb")
}

func TestDES(t *testing.T) {
	testBlockCipher(t, "des-cfb")
}

func TestRC4MD5(t *testing.T) {
	testBlockCipher(t, "rc4-md5")
}

func TestChaCha20(t *testing.T) {
	testBlockCipher(t, "chacha20")
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

func BenchmarkRC4Init(b *testing.B) {
	key := cipherKey[:16]
	for i := 0; i < b.N; i++ {
		rc4.NewCipher(key)
	}
}

func benchmarkCipherInit(b *testing.B, method string) {
	ci := cipherMethod[method]
	key := cipherKey[:ci.keyLen]
	buf := make([]byte, ci.ivLen)
	for i := 0; i < b.N; i++ {
		ci.newStream(key, buf, Encrypt)
	}
}

func BenchmarkAES128Init(b *testing.B) {
	benchmarkCipherInit(b, "aes-128-cfb")
}

func BenchmarkAES192Init(b *testing.B) {
	benchmarkCipherInit(b, "aes-192-cfb")
}

func BenchmarkAES256Init(b *testing.B) {
	benchmarkCipherInit(b, "aes-256-cfb")
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

func BenchmarkChaCha20Init(b *testing.B) {
	benchmarkCipherInit(b, "chacha20")
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

func BenchmarkAES128Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-128-cfb")
}

func BenchmarkAES192Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-192-cfb")
}

func BenchmarkAES256Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-256-cfb")
}

func BenchmarkBlowFishEncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "bf-cfb")
}

func BenchmarkCast5Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "bf-cfb")
}

func BenchmarkDESEncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "des-cfb")
}

func BenchmarkRC4MD5Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "rc4-md5")
}

func BenchmarkChacha20Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "chacha20")
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

func BenchmarkAES128Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "aes-128-cfb")
}

func BenchmarkAES192Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "aes-192-cfb")
}

func BenchmarkAES256Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "aes-256-cfb")
}

func BenchmarkBlowFishDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "bf-cfb")
}

func BenchmarkCast5Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "bf-cfb")
}

func BenchmarkDESDecrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "des-cfb")
}

func BenchmarkRC4MD5Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "rc4-md5")
}

func BenchmarkChaCha20Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "chacha20")
}

func BenchmarkSalsa20Decrypt(b *testing.B) {
	benchmarkCipherDecrypt(b, "salsa20")
}
