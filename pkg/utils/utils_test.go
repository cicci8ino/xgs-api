package utils_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/cicci8ino/xgs-api/pkg/utils"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestEncryptPassword(t *testing.T) {
	privateKey, err := generatePrivateKey(2024)
	if err != nil {
		log.Fatal().Msg("public key cannot be generated")
	}
	password := "asdasd"
	encryptedPassword, err := utils.EncryptPassword(&privateKey.PublicKey, password)
	assert.NoError(t, err)
	decodedEncryptedPassword, err := base64.StdEncoding.DecodeString(encryptedPassword)
	assert.NoError(t, err)
	decryptedBinPassword, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, []byte(decodedEncryptedPassword))
	assert.NoError(t, err)
	decryptedPassword := string(decryptedBinPassword)
	assert.Equal(t, password, decryptedPassword)
}

func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Debug().Msg("Private Key generated")
	return privateKey, nil
}
