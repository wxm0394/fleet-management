package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

var (
	encryptionKey []byte
	keyOnce       sync.Once
)

func InitEncryptionKey() {
	keyOnce.Do(func() {
		keyStr := os.Getenv("FLEET_ENCRYPTION_KEY")
		if keyStr == "" {
			// Auto-generate random 32-byte key if not configured
			key := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, key); err != nil {
				log.Fatalf("[!] Failed to generate random encryption key: %v", err)
			}
			encryptionKey = key
			hexKey := hex.EncodeToString(key)
			log.Println("====================================================")
			log.Println("[WARNING] FLEET_ENCRYPTION_KEY environment variable is not set!")
			log.Printf("[WARNING] Auto-generated AES-256 key for DNS Provider credentials: %s", hexKey)
			log.Println("[WARNING] Please save this key and set FLEET_ENCRYPTION_KEY on future restarts to decrypt existing records.")
			log.Println("====================================================")
			return
		}

		// Support hex (64 chars) or base64 (44 chars) or raw 32-byte string
		var decoded []byte
		var err error
		if len(keyStr) == 64 {
			decoded, err = hex.DecodeString(keyStr)
		} else {
			decoded, err = base64.StdEncoding.DecodeString(keyStr)
			if err != nil && len(keyStr) == 32 {
				decoded = []byte(keyStr)
				err = nil
			}
		}

		if err != nil || len(decoded) != 32 {
			log.Fatalf("Fatal: FLEET_ENCRYPTION_KEY must be a valid 32-byte key (64 hex characters or 32 raw bytes / base64), got decoded length %d", len(decoded))
		}
		encryptionKey = decoded
	})
}

func EncryptCredentials(plaintext string) (string, error) {
	InitEncryptionKey()

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptCredentials(ciphertext string) (string, error) {
	InitEncryptionKey()

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		// Fallback to legacy plaintext if base64 decoding fails
		log.Printf("[!] Legacy plaintext DNS provider record detected, recommend saving again to encrypt")
		return ciphertext, nil
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		// Fallback to legacy plaintext
		log.Printf("[!] Legacy plaintext DNS provider record detected, recommend saving again to encrypt")
		return ciphertext, nil
	}

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		// Fallback to legacy plaintext if decryption fails (e.g. unencrypted raw JSON string)
		log.Printf("[!] Legacy unencrypted DNS provider record detected, recommend saving again to encrypt")
		return ciphertext, nil
	}

	return string(plaintext), nil
}
