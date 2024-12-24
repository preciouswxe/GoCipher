package main

import (
	"encoding/base64"
	"fmt"
)

type RC4 struct {
	sbox []byte
	i    int // 使用 int 类型
	j    int // 使用 int 类型
}

// KSA阶段
func (r *RC4) InitSbox(key []byte) {
	if len(key) == 0 {
		panic("key cannot be empty")
	}

	r.sbox = make([]byte, 256)
	for i := 0; i < 256; i++ {
		r.sbox[i] = byte(i)
	}

	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(r.sbox[i]) + int(key[i%len(key)])) % 256 // 确保 j 在范围内
		r.sbox[i], r.sbox[j] = r.sbox[j], r.sbox[i]           // 交换
	}
	r.i = 0
	r.j = 0
}

// PRGA加密解密
func Encrypt(key []byte, plaintext []byte) []byte {
	var rc RC4
	rc.InitSbox(key)

	ciphertext := make([]byte, len(plaintext))
	for index, plainByte := range plaintext {
		rc.i = (rc.i + 1) % 256
		rc.j = (rc.j + int(rc.sbox[rc.i])) % 256

		rc.sbox[rc.i], rc.sbox[rc.j] = rc.sbox[rc.j], rc.sbox[rc.i]

		tmp := (int(rc.sbox[rc.i]) + int(rc.sbox[rc.j])) % 256
		ciphertext[index] = rc.sbox[tmp] ^ plainByte
	}
	return ciphertext
}

func Decrypt(key []byte, ciphertext []byte) []byte {
	return Encrypt(key, ciphertext)
}

func main() {
	plain := "Hi, this is RC4"
	plaintext := []byte(plain)
	key := []byte("cyptography")

	fmt.Println("原文如下：", plain)

	encrypted := Encrypt(key, plaintext)
	fmt.Println("加密如下：", base64.StdEncoding.EncodeToString(encrypted))

	decrypted := Decrypt(key, encrypted)
	fmt.Println("解密如下：", string(decrypted))
}
