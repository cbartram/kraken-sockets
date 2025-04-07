package server

import (
	"crypto/aes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	log "github.com/sirupsen/logrus"
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
	// Generate key using SHA1 as in Java implementation
	hasher := sha1.New()
	hasher.Write([]byte(secret))
	key := hasher.Sum(nil)

	// Truncate to 16 bytes (128 bits for AES)
	return key[:16]
}

// EncryptAES encrypts plaintext using AES/ECB/PKCS5Padding
func EncryptAES(secret, plaintext string) string {
	// Generate key
	key := GenerateAESKey(secret)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("Encryption error:", err)
		return ""
	}

	// Add padding
	data := PKCS5Padding([]byte(plaintext), block.BlockSize())

	// ECB mode encryption
	encrypted := make([]byte, len(data))
	size := block.BlockSize()

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Encrypt(encrypted[bs:be], data[bs:be])
	}

	// Convert to base64
	return base64.StdEncoding.EncodeToString(encrypted)
}

// DecryptAES decrypts ciphertext using AES/ECB/PKCS5Padding
func DecryptAES(secret, ciphertext string) string {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		log.Println("Decryption base64 error:", err)
		return ""
	}

	// Generate key
	key := GenerateAESKey(secret)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("Decryption cipher error:", err)
		return ""
	}

	// ECB mode decryption
	decrypted := make([]byte, len(data))
	size := block.BlockSize()

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return string(PKCS5Unpadding(decrypted))
}
