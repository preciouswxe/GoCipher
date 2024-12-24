package main

import (
	"bufio"
	"fmt"
	"os"
)

type sm4Test struct {
	out string
	in  []byte
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	println("请输入要加密的明文：")
	input, err := reader.ReadString('\n')
	if err != nil {
		panic("输入报错！")
	}
	input = input[:len(input)-1] // 去除换行符

	// 将输入字符串转为字节切片
	inputBytes := []byte(input)
	var segments [][]byte
	for i := 0; i < len(inputBytes); i += 16 {
		end := i + 16
		if end > len(inputBytes) {
			end = len(inputBytes)
		}
		segment := inputBytes[i:end]
		// 如果该段长度小于16字节，进行填充
		if len(segment) < 16 {
			segment = PKCS7Padding(segment, 16)
		}
		segments = append(segments, segment)
	}

	// 原始密钥
	rawkey := "Feistel"
	key := []byte(rawkey)
	key = PaddingKey(key)

	// 存储最终拼接后的解密结果
	var finalResult []byte

	// 对每一段进行加密、解密并拼接结果
	for _, segment := range segments {
		c, err := NewCipher(key)
		if err != nil {
			panic("NewCipher works defeat!")
		}
		encryptedSegment := make([]byte, 16)
		c.Encrypt(encryptedSegment, segment)

		decryptedSegment := make([]byte, 16)
		c.Decrypt(decryptedSegment, encryptedSegment)

		// 如果最初输入长度小于16字节且有填充，去除填充部分（针对每一段解密结果处理）
		if len(segment) < 16 {
			decryptedSegment = PKCS7UnPadding(decryptedSegment)
		}

		finalResult = append(finalResult, decryptedSegment...)
	}

	fmt.Println("解密合并后的结果:", string(finalResult))
}
