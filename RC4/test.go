package main

import (
	"crypto/rc4"
	"encoding/base64"
	"fmt"
)

func Test() {
	key := []byte("mysecretkey")
	plaintext := []byte("Hi,this is RC4")

	// 创建 RC4 加密器
	c, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 加密
	ciphertext := make([]byte, len(plaintext))
	c.XORKeyStream(ciphertext, plaintext)
	fmt.Println("加密后的结果：", base64.StdEncoding.EncodeToString(ciphertext))

	// 创建新的解密器（密钥相同）
	d, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 解密
	decrypted := make([]byte, len(ciphertext))
	d.XORKeyStream(decrypted, ciphertext)
	fmt.Println("解密后的结果：", string(decrypted))
}
