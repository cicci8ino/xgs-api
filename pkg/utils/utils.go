package utils

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// compute the md5 of the path
func ComputeMD5(completePath string) string {
	result := strings.Split(completePath, "?")
	hash := md5.Sum([]byte(result[1]))
	md5String := hex.EncodeToString(hash[:])
	return md5String
}

// prepare the url for the request, appending the md5 as bj4 parameter
func GetURL(baseURL string, basePath string, action string) string {
	params := url.Values{}
	params.Add("cmd", action)
	params.Add("dummy", fmt.Sprint(time.Now().UnixMilli()))
	url := fmt.Sprintf("%s%s?%s", baseURL, basePath, params.Encode())
	url = url + "?bj4=" + ComputeMD5(url)
	log.Debug().Msg(url)
	return url
}

func EncryptPassword(pubKey *rsa.PublicKey, password string) (string, error) {
	passwordBytes := []byte(password)
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, passwordBytes)
	if err != nil {
		log.Fatal().Err(err).Msg("error in encryption")
		return "", err
	}
	encryptedString := fmt.Sprintf("%x", encryptedBytes)
	if len(encryptedString)%2 != 0 {
		encryptedString = "0" + encryptedString
		log.Debug().Msg("detected odd lenght")
	}
	encryptedBytes, err = hex.DecodeString(encryptedString)
	if err != nil {
		log.Fatal().Err(err).Msg("error in reencoding")
	}
	encryptedPassword := base64.StdEncoding.EncodeToString(encryptedBytes)
	log.Debug().Msg(fmt.Sprintf("base64 encoded encrypted password: %s", encryptedPassword))
	return encryptedPassword, nil
}

func CreatePublicKey(modulusHex string, exponentInt string) (*rsa.PublicKey, error) {
	modulusBytes, err := hex.DecodeString(modulusHex)
	if err != nil {
		log.Fatal().Err(err).Msg("failed decoding modulus")
		return nil, err
	}
	modulus := new(big.Int).SetBytes(modulusBytes)

	exponent, err := strconv.ParseInt(exponentInt, 16, 64)

	if err != nil {
		log.Fatal().Err(err).Msg("cannot convert exponent")
	}

	pubKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent),
	}
	log.Debug().Interface("pubKey", pubKey).Msg("pubKey")

	return pubKey, nil
}

func GenXSRFToken() (string, error) {
	bytes := make([]byte, 8)

	// Genera bytes casuali
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Converti in stringa esadecimale
	return hex.EncodeToString(bytes), nil
}
