package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

type CryptoHandler struct {
	key        []byte
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func NewCryptoHandler(key string) *CryptoHandler {
	salt := []byte("RhinoC2-SecureSalt-v1.2.2")
	derivedKey := argon2.IDKey([]byte(key), salt, 3, 64*1024, 4, 32)
	return &CryptoHandler{
		key: derivedKey,
	}
}

func (c *CryptoHandler) GenerateRSAKeyPair() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	c.privateKey = privateKey
	c.publicKey = &privateKey.PublicKey
	return nil
}

func (c *CryptoHandler) ExportPublicKey() (string, error) {
	if c.publicKey == nil {
		return "", errors.New("public key not set")
	}
	pubASN1, err := x509.MarshalPKIXPublicKey(c.publicKey)
	if err != nil {
		return "", err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubBytes), nil
}

func (c *CryptoHandler) ImportPublicKey(pemKey string) error {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return errors.New("failed to parse PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	c.publicKey = pub.(*rsa.PublicKey)
	return nil
}

func (c *CryptoHandler) Encrypt(data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("empty data")
	}
	if len(data) > 10485760 {
		return "", errors.New("data too large")
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM creation failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (c *CryptoHandler) Decrypt(encodedData string) ([]byte, error) {
	if len(encodedData) == 0 {
		return nil, errors.New("empty encoded data")
	}

	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d", len(data), nonceSize)
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (c *CryptoHandler) RSAEncrypt(data []byte) ([]byte, error) {
	if c.publicKey == nil {
		return nil, errors.New("public key not set")
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, c.publicKey, data, nil)
}

func (c *CryptoHandler) RSADecrypt(ciphertext []byte) ([]byte, error) {
	if c.privateKey == nil {
		return nil, errors.New("private key not set")
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privateKey, ciphertext, nil)
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}
