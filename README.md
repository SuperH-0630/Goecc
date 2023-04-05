# GoECC
`golang`语言的ecc实现。

## PEM密钥使用指南
PEM密钥是类似于如下的密钥：
```
-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7JMlqc5lUMKLSS8U5+NANi7qjewn
FhPsZT67kzVBgdxZGnPjbF3+2n8F8lxl/+sckTDyXTnevT6Q6iBBJyHkvg==
-----END EC PUBLIC KEY-----
```
和
```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBjEsBOdIT5m5eJ9jIQ9lrUBCsXLMTC5QgmdDXKsV1oMoAoGCCqGSM49
AwEHoUQDQgAE7JMlqc5lUMKLSS8U5+NANi7qjewnFhPsZT67kzVBgdxZGnPjbF3+
2n8F8lxl/+sckTDyXTnevT6Q6iBBJyHkvg==
-----END EC PRIVATE KEY-----
```

使用PEM密钥加密：
```go
func cryptPem() {
	msg := "ABCDEFG"
	eccKey, err := ecc.GenerateEccKeyPem()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Pri: %s\n", eccKey.PrivateKey)
	fmt.Printf("Pub: %s\n", eccKey.PublicKey)

	text, err := ecc.EccEncrypt([]byte(msg), eccKey.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Secret:%s\n", text)

	plaintext, err := ecc.EccDecrypt(text, eccKey.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Plain:%s\n", string(plaintext))
}
```
`GenerateEccKeyPem`生成密钥。
`EccEncrypt`加密字节，返回字节。
`EccDecrypt`解密字节。

使用PEM签名：
```go
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
```
`EccSign`生成签名的`rSign`和`sSign`。
`EccSign`验证签名的（传入文件字节）。

## HEX密钥使用指南
类似于PEM密钥，函数带有Hex后缀。

## Base64密钥使用指南
类似于PEM密钥，函数带有Base64后缀。
