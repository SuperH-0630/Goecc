package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
)

type EccKey struct {
	PrivateKey string
	PublicKey  string
}

func GenerateEccKeyHex() (EccKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return EccKey{}, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return EccKey{}, err
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return EccKey{}, err
	}

	return EccKey{
		PrivateKey: hex.EncodeToString(privateBytes),
		PublicKey:  hex.EncodeToString(publicBytes),
	}, nil
}

func GenerateEccKeyBase64() (EccKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return EccKey{}, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return EccKey{}, err
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return EccKey{}, err
	}
	return EccKey{
		PrivateKey: base64.StdEncoding.EncodeToString(privateBytes),
		PublicKey:  base64.StdEncoding.EncodeToString(publicBytes),
	}, nil
}

func GenerateEccKeyPem() (EccKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return EccKey{}, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return EccKey{}, err
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return EccKey{}, err
	}

	priBlock := &pem.Block{
		Type:  "WUNCHAIN PRIVATE KEY",
		Bytes: privateBytes,
	}
	priKey := pem.EncodeToMemory(priBlock)

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}
	pubKey := pem.EncodeToMemory(pubBlock)

	return EccKey{
		PrivateKey: string(priKey),
		PublicKey:  string(pubKey),
	}, nil
}
