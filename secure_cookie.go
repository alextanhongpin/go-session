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
	"time"
)

func main() {
	// Prepare a serverKey
	serverKey, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
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

	// Test hash cookie
	oriData := []byte("greeting")
	userName := "john"
	expirationTime := time.Now().Unix()
	sessionKey := "1"

	{
		encryptedData, err := encrypt(oriData, serverKey)
		mac := hmac.New(sha256.New, serverKey)
		m := fmt.Sprintf("%s|%d|%s|%s", userName, expirationTime, oriData, sessionKey)
		hashedData, err := mac.Write([]byte(m))
		if err != nil {
			log.Fatal(err)
		}
		output := fmt.Sprintf("%s|%d|%s|%s", userName, expirationTime, encryptedData, hashedData)
		fmt.Println(output)
	}
	/*messsage := fmt.Sprintf("%s|%d", userName, expirationTime)
	mac := hmac.New(sha256.New, serverKey)
	key, err := mac.Write([]byte(messsage))
	if err != nil {
		log.Fatal(err)
	}
	data, err := decrypt(data, key)
	if err != nil {
		log.Fatal(err)
	}
	mac = hmac.New(sha256.New, serverKey)
	key := mac.Write([]byte(fmt.Sprintf("%s|%d|%s|%s", userName, expirationTime, data, sessionKey)))*/

	// cookieHash "username|expiration time|(data)k|HMAC( user name|expiration time|data|session key, k)"
	// where k=HMAC(user name|expiration time, sk)
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
