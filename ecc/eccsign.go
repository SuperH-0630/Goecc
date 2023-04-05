package ecc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"runtime"
)

func _sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}

func eccSign(msg []byte, priKey []byte) (rSign []byte, sSign []byte, err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				// TODO 加入到日志中
			default:
				// TODO 加入到日志中
			}
		}
	}()
	privateKey, err := x509.ParseECPrivateKey(priKey)
	if err != nil {
		return nil, nil, err
	}
	resultHash := _sha256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, resultHash)
	if err != nil {
		return nil, nil, err
	}

	rText, err := r.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	sText, err := s.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	return rText, sText, nil
}

func eccVerifySign(msg []byte, pubKey []byte, rText, sText []byte) bool {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				// TODO 加入到日志中
			default:
				// TODO 加入到日志中
			}
		}
	}()
	publicKeyInterface, _ := x509.ParsePKIXPublicKey(pubKey)
	publicKey := publicKeyInterface.(*ecdsa.PublicKey)
	resultHash := _sha256(msg)

	var r, s big.Int
	err := r.UnmarshalText(rText)
	if err != nil {
		return false
	}

	err = s.UnmarshalText(sText)
	if err != nil {
		return false
	}

	result := ecdsa.Verify(publicKey, resultHash, &r, &s)
	return result
}

func EccSignBase64(msg []byte, base64PriKey string) (base64rSign, base64sSign string, err error) {
	priBytes, err := base64.StdEncoding.DecodeString(base64PriKey)
	if err != nil {
		return "", "", err
	}
	rSign, sSign, err := eccSign(msg, priBytes)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(rSign), base64.StdEncoding.EncodeToString(sSign), nil
}

func EccVerifySignBase64(msg []byte, base64rSign, base64sSign, base64PubKey string) bool {
	rSignBytes, err := base64.StdEncoding.DecodeString(base64rSign)
	if err != nil {
		return false
	}
	sSignBytes, err := base64.StdEncoding.DecodeString(base64sSign)
	if err != nil {
		return false
	}
	pubBytes, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return false
	}
	return eccVerifySign(msg, pubBytes, rSignBytes, sSignBytes)
}

func EccSignHex(msg []byte, hexPriKey string) (hexrSign, hexsSign string, err error) {
	priBytes, err := hex.DecodeString(hexPriKey)
	if err != nil {
		return "", "", err
	}
	rSign, sSign, err := eccSign(msg, priBytes)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(rSign), hex.EncodeToString(sSign), nil
}

func EccVerifySignHex(msg []byte, hexrSign, hexsSign, hexPubKey string) bool {
	rSignBytes, err := hex.DecodeString(hexrSign)
	if err != nil {
		return false
	}
	sSignBytes, err := hex.DecodeString(hexsSign)
	if err != nil {
		return false
	}
	pubBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return false
	}
	return eccVerifySign(msg, pubBytes, rSignBytes, sSignBytes)
}

func EccSign(msg []byte, priKey string) (hexrSign, hexsSign string, err error) {
	block, _ := pem.Decode([]byte(priKey))
	if block == nil {
		// TODO 记录日志
		return "", "", fmt.Errorf("bad private key")
	}

	rSign, sSign, err := eccSign(msg, block.Bytes)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(rSign), hex.EncodeToString(sSign), nil
}

func EccVerifySign(msg []byte, hexrSign, hexsSign, pubKey string) bool {
	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		// TODO 记录日志
		return false
	}

	rSignBytes, err := hex.DecodeString(hexrSign)
	if err != nil {
		return false
	}
	sSignBytes, err := hex.DecodeString(hexsSign)
	if err != nil {
		return false
	}
	return eccVerifySign(msg, block.Bytes, rSignBytes, sSignBytes)
}
