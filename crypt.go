package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"os"
)

var secret string = os.Getenv("ODOO_PROTOCOL")
var defaultSecret string = "40e48c860f643ec9f2201ac7adb0737d540bc2f9edcbe97d913476c62d0352f4f185effd509594104a98a708a508d9f5ba60bd341471a20e1235d474"

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Encrypt returns an encrypted version of the data
func Encrypt(data []byte) []byte {
	if secret == "" {
		secret = defaultSecret
	}
	block, _ := aes.NewCipher([]byte(createHash(secret)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// Decrypt returns an un-ecrypted version of the data
func Decrypt(data []byte) []byte {
	if secret == "" {
		secret = defaultSecret
	}

	key := []byte(createHash(secret))
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err.Error())
	}
	return plaintext
}
