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
)

type CryptoHandler struct {
	key        []byte
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func NewCryptoHandler(key string) *CryptoHandler {
	hash := sha256.Sum256([]byte(key))
	return &CryptoHandler{
		key: hash[:],
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
