package main

import (
	"fmt"
	"git.wuntsong.com/wunchain/goecc/ecc"
)

func main() {
	fmt.Printf("CryptPem:\n")
	cryptPem()

	fmt.Printf("CryptBase64:\n")
	cryptBase64()

	fmt.Printf("CryptHex:\n")
	cryptHex()

	fmt.Printf("SignPem:\n")
	signPem()

	fmt.Printf("SignBase64:\n")
	signBase64()

	fmt.Printf("SignHex:\n")
	signHex()
}

func cryptPem() {
	msg := "ABCDEFG"
	eccKey, err := ecc.GenerateEccKeyPem()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Pri: %s\n", eccKey.PrivateKey)
	fmt.Printf("Pub: %s\n", eccKey.PublicKey)

	base64Text, err := ecc.EccEncrypt([]byte(msg), eccKey.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Secret:%s\n", base64Text)

	plaintext, err := ecc.EccDecrypt(base64Text, eccKey.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Plain:%s\n", string(plaintext))
}

func cryptBase64() {
	msg := "ABCDEFG"
	eccBase64Key, err := ecc.GenerateEccKeyBase64()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Pri: %s\n", eccBase64Key.PrivateKey)
	fmt.Printf("Pub: %s\n", eccBase64Key.PublicKey)

	base64Text, err := ecc.EccEncryptToBase64([]byte(msg), eccBase64Key.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Secret:%s\n", base64Text)

	plaintext, err := ecc.EccDecryptByBase64(base64Text, eccBase64Key.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Plain:%s\n", string(plaintext))
}

func cryptHex() {
	msg := "ABCDEFG"
	eccHexKey, err := ecc.GenerateEccKeyHex()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Pri: %s\n", eccHexKey.PrivateKey)
	fmt.Printf("Pub: %s\n", eccHexKey.PublicKey)

	base64Text, err := ecc.EccEncryptToHex([]byte(msg), eccHexKey.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Secret:%s\n", base64Text)

	plaintext, err := ecc.EccDecryptByHex(base64Text, eccHexKey.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Plain:%s\n", string(plaintext))
}

func signPem() {
	msg := "ABCDEFG"
	eccKey, err := ecc.GenerateEccKeyPem()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Pri: %s\n", eccKey.PrivateKey)
	fmt.Printf("Pub: %s\n", eccKey.PublicKey)

	rSign, sSign, err := ecc.EccSign([]byte(msg), eccKey.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("R_Sign: %s\nS_Sign: %s\n", rSign, sSign)
	res := ecc.EccVerifySign([]byte(msg), rSign, sSign, eccKey.PublicKey)
	fmt.Printf("Sign: %v\n", res)
}

func signBase64() {
	msg := "ABCDEFG"
	eccBase64Key, err := ecc.GenerateEccKeyBase64()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Pri: %s\n", eccBase64Key.PrivateKey)
	fmt.Printf("Pub: %s\n", eccBase64Key.PublicKey)

	rSign, sSign, err := ecc.EccSignBase64([]byte(msg), eccBase64Key.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("R_Sign: %s\nS_Sign: %s\n", rSign, sSign)
	res := ecc.EccVerifySignBase64([]byte(msg), rSign, sSign, eccBase64Key.PublicKey)
	fmt.Printf("Sign:%v\n", res)
}

func signHex() {
	msg := "ABCDEFG"
	eccHexKey, err := ecc.GenerateEccKeyHex()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Pri: %s\n", eccHexKey.PrivateKey)
	fmt.Printf("Pub: %s\n", eccHexKey.PublicKey)

	rSign, sSign, err := ecc.EccSignHex([]byte(msg), eccHexKey.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("R_Sign: %s\nS_Sign: %s\n", rSign, sSign)
	res := ecc.EccVerifySignHex([]byte(msg), rSign, sSign, eccHexKey.PublicKey)
	fmt.Printf("Sign: %v\n", res)
}
