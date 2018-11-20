package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

func main() {
	// Prepare a serverKey
	serverKey, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")

	// Encode.
	{
		var (
			data           = []byte("secret message")
			userName       = "john"
			expirationTime = time.Now().Unix()
			sessionKey     = "1"
		)
		secureCookie, err := encode(userName, expirationTime, sessionKey, data, serverKey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("secure cookie: %s\n", secureCookie)
	}

	// Decode.
	{
		sessionKey := "1"
		secureCookie := "john|1257894000|zs6iXECrhwoE/0sTqV3Tn80oG6VgmZkMpimNtWpKrUuMxXAVmL4BdVJL|i+IPZCnmsor3PndTEsNVpxUX/+izSkl2aHwmXqTBI/4="
		// More like verify.
		plaintext, isValid, err := decode(secureCookie, sessionKey, serverKey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("is valid cookie:", isValid)
		fmt.Printf("decrypted message is: %s\n", plaintext)
	}
}

func encode(userName string, expirationTime int64, sessionKey string, data, serverKey []byte) (string, error) {
	// Create a key, k
	// where k=HMAC(user name|expiration time, serverKey)
	mac := hmac.New(sha256.New, serverKey)
	msg := fmt.Sprintf("%s|%d", userName, expirationTime)
	mac.Write([]byte(msg))
	key := mac.Sum(nil)

	// Use the generated key to encrypt the data, (data)k.
	ciphertext, err := encrypt(data, key)
	if err != nil {
		return "", err
	}
	// Create a key-message hash of the data before encryption and other parameters.
	// HMAC( user name|expiration time|data|session key, k)
	mac = hmac.New(sha256.New, key)
	mac.Write([]byte(fmt.Sprintf("%s|%d|%b|%s", userName, expirationTime, data, sessionKey)))
	kmh := mac.Sum(nil)

	// Secure cookie format: username|expiration time|(data)k|HMAC( user name|expiration time|data|session key, k).
	return fmt.Sprintf("%s|%d|%s|%s",
		userName,
		expirationTime,
		base64.StdEncoding.EncodeToString(ciphertext),
		base64.StdEncoding.EncodeToString(kmh),
	), nil
}

func decode(secureCookie, sessionKey string, serverKey []byte) ([]byte, bool, error) {
	parts := strings.Split(secureCookie, "|")
	var (
		userName          = parts[0]
		expirationTime    = parts[1]
		encCiphertext     = parts[2]
		encKeyMessageHash = parts[3]
	)

	// Create a key, k
	// where k=HMAC(user name|expiration time, serverKey)
	mac := hmac.New(sha256.New, serverKey)
	msg := fmt.Sprintf("%s|%s", userName, expirationTime)
	mac.Write([]byte(msg))
	key := mac.Sum(nil)

	// Decode from base64.
	ciphertext, err := base64.StdEncoding.DecodeString(encCiphertext)
	if err != nil {
		return nil, false, err
	}
	keyMessageHash, err := base64.StdEncoding.DecodeString(encKeyMessageHash)
	if err != nil {
		return nil, false, err
	}
	// Decrypt the data with the key generated.
	plaintext, err := decrypt(ciphertext, key)
	if err != nil {
		return nil, false, err
	}
	// Create the keyMessageHash based on the data.
	// HMAC( user name|expiration time|data|session key, k)
	mac = hmac.New(sha256.New, key)
	mac.Write([]byte(fmt.Sprintf("%s|%s|%b|%s", userName, expirationTime, plaintext, sessionKey)))
	kmh := mac.Sum(nil)
	return plaintext, hmac.Equal(kmh, keyMessageHash), nil
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, data := ciphertext[:12], ciphertext[12:]
	plaintext, err := aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func testEncryptDecryptData() {
	serverKey, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")

	// Example on encrypting data.
	ciphertext, err := encrypt([]byte("hello"), serverKey)
	if err != nil {
		log.Fatal(err)
	}

	// EncodeToString
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Println("base64(ciphertext):", encoded)

	// Check if the content can be decrypted.
	plaintext, err := decrypt(ciphertext, serverKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("plaintext:", string(plaintext))
}
