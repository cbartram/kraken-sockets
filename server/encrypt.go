package server

import (
	"crypto/aes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
)

// Hash implements SHA256 encryption
func Hash(text string) string {
	hasher := sha1.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// PKCS5Padding adds padding to the data
func PKCS5Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// PKCS5Unpadding removes padding from the data
func PKCS5Unpadding(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}

	padding := int(data[length-1])
	if padding > length {
		return data
	}
	return data[:length-padding]
}

// GenerateAESKey generates a 16-byte key using SHA1
func GenerateAESKey(secret string) []byte {
	hasher := sha1.New()
	hasher.Write([]byte(secret))
	key := hasher.Sum(nil)

	return key[:16]
}

// EncryptAES encrypts plaintext using AES/ECB/PKCS5Padding
func EncryptAES(secret, plaintext string) string {
	key := GenerateAESKey(secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	data := PKCS5Padding([]byte(plaintext), block.BlockSize())

	encrypted := make([]byte, len(data))
	size := block.BlockSize()

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Encrypt(encrypted[bs:be], data[bs:be])
	}

	return base64.StdEncoding.EncodeToString(encrypted)
}

// DecryptAES decrypts ciphertext using AES/ECB/PKCS5Padding
func DecryptAES(secret, ciphertext string) string {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return ""
	}

	key := GenerateAESKey(secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	decrypted := make([]byte, len(data))
	size := block.BlockSize()

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return string(PKCS5Unpadding(decrypted))
}
