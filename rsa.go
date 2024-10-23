package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
)

// EncryptByPublicKey encrypts by public key.
func EncryptByPublicKey(src, publicKey []byte) (dst []byte, err error) {
	dst = []byte("")
	if len(src) == 0 {
		return
	}

	pub, err := ParsePublicKey(publicKey)
	if err != nil {
		err = invalidPublicKeyError()
		return
	}

	buffer := bytes.NewBufferString("")
	for _, chunk := range bytesSplit(src, pub.Size()-11) {
		dst, err = rsa.EncryptPKCS1v15(rand.Reader, pub, chunk)
		buffer.Write(dst)
	}
	dst = buffer.Bytes()

	return
}

// DecryptByPrivateKey decrypts by private key.
func DecryptByPrivateKey(src, privateKey []byte) (dst []byte, err error) {
	dst = []byte("")
	if len(src) == 0 {
		return
	}

	pri, err := ParsePrivateKey(privateKey)
	if err != nil {
		err = invalidPrivateKeyError()
		return
	}

	buffer := bytes.NewBufferString("")
	for _, chunk := range bytesSplit(src, pri.Size()) {
		dst, err = rsa.DecryptPKCS1v15(rand.Reader, pri, chunk)
		buffer.Write(dst)
	}
	dst = buffer.Bytes()

	return
}

// EncryptByPrivateKey encrypts by private key.
func EncryptByPrivateKey(src, privateKey []byte) (dst []byte, err error) {
	dst = []byte("")
	if len(src) == 0 {
		return
	}

	pri, err := ParsePrivateKey(privateKey)
	if err != nil {
		err = invalidPrivateKeyError()
		return
	}

	buffer := bytes.NewBufferString("")
	for _, chunk := range bytesSplit(src, pri.Size()-11) {
		dst, err = rsa.SignPKCS1v15(nil, pri, crypto.Hash(0), chunk)
		buffer.Write(dst)
	}
	dst = buffer.Bytes()

	return
}

// DecryptByPublicKey decrypts by public key.
func DecryptByPublicKey(src, publicKey []byte) (dst []byte, err error) {
	dst = []byte("")
	if len(src) == 0 {
		return
	}

	pub, err := ParsePublicKey(publicKey)
	if err != nil {
		err = invalidPublicKeyError()
		return
	}

	buffer := bytes.NewBufferString("")
	bigInt := new(big.Int)
	for _, chunk := range bytesSplit(src, pub.Size()) {
		bigInt.Exp(new(big.Int).SetBytes(chunk), big.NewInt(int64(pub.E)), pub.N)
		dst = leftUnPad(leftPad(bigInt.Bytes(), pub.Size()))
		buffer.Write(dst)
	}
	dst = buffer.Bytes()

	return
}

// SignByPrivateKey signs by private key.
func SignByPrivateKey(src, privateKey []byte, hash crypto.Hash) (dst []byte, err error) {
	dst = []byte("")
	pri, err := ParsePrivateKey(privateKey)
	if err != nil {
		err = invalidPrivateKeyError()
		return
	}

	hasher := hash.New()
	hasher.Write(src)
	hashed := hasher.Sum(nil)
	dst, err = rsa.SignPKCS1v15(rand.Reader, pri, hash, hashed)

	return
}

// VerifyByPublicKey verify by public key.
func VerifyByPublicKey(src, sign, publicKey []byte, hash crypto.Hash) (err error) {
	pub, err := ParsePublicKey(publicKey)
	if err != nil {
		err = invalidPublicKeyError()
		return
	}

	hasher := hash.New()
	hasher.Write(src)
	hashed := hasher.Sum(nil)

	return rsa.VerifyPKCS1v15(pub, hash, hashed, sign)
}

// GenKeyPair generates key pair.
func GenKeyPair(pkcs KeyFormat, bits int) (publicKey, privateKey []byte) {
	pri, _ := rsa.GenerateKey(rand.Reader, bits)

	if pkcs == PKCS1 {
		privateBytes := x509.MarshalPKCS1PrivateKey(pri)
		privateKey = pem.EncodeToMemory(&pem.Block{
			Type:  PKCS1PrivateKey,
			Bytes: privateBytes,
		})
		publicBytes := x509.MarshalPKCS1PublicKey(&pri.PublicKey)
		publicKey = pem.EncodeToMemory(&pem.Block{
			Type:  PKCS1PublicKey,
			Bytes: publicBytes,
		})
	} else if pkcs == PKCS8 {
		privateBytes, _ := x509.MarshalPKCS8PrivateKey(pri)
		privateKey = pem.EncodeToMemory(&pem.Block{
			Type:  PKCS8PrivateKey,
			Bytes: privateBytes,
		})
		publicBytes, _ := x509.MarshalPKIXPublicKey(&pri.PublicKey)
		publicKey = pem.EncodeToMemory(&pem.Block{
			Type:  PKCS8PublicKey,
			Bytes: publicBytes,
		})
	}

	return
}

// VerifyKeyPair verify key pairs.
func VerifyKeyPair(publicKey, privateKey []byte) bool {
	pub, err := ExportPublicKey(privateKey)
	if err != nil {
		return false
	}
	if bytes2string(publicKey) == bytes2string(pub) {
		return true
	}
	return false
}

// ParsePublicKey parses public key.
func ParsePublicKey(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, invalidPublicKeyError()
	}

	if block.Type == PKCS1PublicKey {
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, invalidPublicKeyError()
		}
		return pub, nil
	}

	if block.Type == PKCS8PublicKey {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, invalidPublicKeyError()
		}
		return pub.(*rsa.PublicKey), err
	}

	return nil, invalidPublicKeyError()
}

// ParsePrivateKey parses private key.
func ParsePrivateKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, invalidPrivateKeyError()
	}

	if block.Type == PKCS1PrivateKey {
		pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, invalidPrivateKeyError()
		}
		return pri, err
	}

	if block.Type == PKCS8PrivateKey {
		pri, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, invalidPrivateKeyError()
		}
		return pri.(*rsa.PrivateKey), err
	}

	return nil, invalidPrivateKeyError()
}

// ExportPublicKey exports public key from private key.
func ExportPublicKey(privateKey []byte) (publicKey []byte, err error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		err = invalidPrivateKeyError()
		return
	}

	pri, err := ParsePrivateKey(privateKey)
	if err != nil {
		return
	}

	blockType, blockBytes := "", []byte("")
	if block.Type == PKCS1PrivateKey {
		blockType = PKCS1PublicKey
		blockBytes = x509.MarshalPKCS1PublicKey(&pri.PublicKey)
	} else if block.Type == PKCS8PrivateKey {
		blockType = PKCS8PublicKey
		blockBytes, err = x509.MarshalPKIXPublicKey(&pri.PublicKey)
	}

	publicKey = pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: blockBytes,
	})

	return
}

// IsPublicKey checks whether is public key.
func IsPublicKey(publicKey []byte) bool {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return false
	}

	return block.Type == PKCS1PublicKey || block.Type == PKCS8PublicKey
}

// IsPrivateKey checks whether is private key.
func IsPrivateKey(privateKey []byte) bool {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return false
	}

	return block.Type == PKCS1PrivateKey || block.Type == PKCS8PrivateKey
}

// CompressKey compresses key, removes the head, tail and newline character.
func CompressKey(key []byte) ([]byte, error) {
	str := strings.Replace(bytes2string(key), "\n", "", -1)

	if IsPublicKey(key) {
		str = strings.Replace(str, PKCS1PublicHeader, "", -1)
		str = strings.Replace(str, PKCS1PublicTail, "", -1)
		str = strings.Replace(str, PKCS8PublicHeader, "", -1)
		str = strings.Replace(str, PKCS8PublicTail, "", -1)
	} else if IsPrivateKey(key) {
		str = strings.Replace(str, PKCS1PrivateHeader, "", -1)
		str = strings.Replace(str, PKCS1PrivateTail, "", -1)
		str = strings.Replace(str, PKCS8PrivateHeader, "", -1)
		str = strings.Replace(str, PKCS8PrivateTail, "", -1)
	} else {
		return nil, invalidRSAKeyError()
	}

	return string2bytes(str), nil
}

// FormatPublicKey formats public key, adds header, tail and newline character.
func FormatPublicKey(pkcs KeyFormat, publicKey []byte) []byte {
	var keyHeader, keyTail string
	if pkcs == PKCS1 {
		keyHeader = PKCS1PublicHeader + "\n"
		keyTail = PKCS1PublicTail + "\n"
	} else if pkcs == PKCS8 {
		keyHeader = PKCS8PublicHeader + "\n"
		keyTail = PKCS8PublicTail + "\n"
	}
	keyBody := stringSplit(strings.Replace(bytes2string(publicKey), "\n", "", -1), 64)

	return string2bytes(keyHeader + keyBody + keyTail)
}

// FormatPrivateKey formats private key, adds header, tail and newline character.
func FormatPrivateKey(pkcs KeyFormat, privateKey []byte) []byte {
	var keyHeader, keyTail string
	if pkcs == PKCS1 {
		keyHeader = PKCS1PrivateHeader + "\n"
		keyTail = PKCS1PrivateTail + "\n"
	} else if pkcs == PKCS8 {
		keyHeader = PKCS8PrivateHeader + "\n"
		keyTail = PKCS8PrivateTail + "\n"
	}
	keyBody := stringSplit(strings.Replace(bytes2string(privateKey), "\n", "", -1), 64)

	return string2bytes(keyHeader + keyBody + keyTail)
}
