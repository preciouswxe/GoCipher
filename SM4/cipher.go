package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/bits"
	"strconv"
)

// 16*8 = 128位 16指的是几个Byte
// 明文密文都是128位
const BlockSize = 16

type SM4Keys struct {
	subkeys [32]uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "SM4: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (*SM4Keys, error) {
	if len := len(key); len != BlockSize {
		fmt.Println("key len: ", len)
		panic("panic:key len not right!")
	}
	c := new(SM4Keys)
	c.GenerateKeys(key)
	return c, nil
}

// pkcs填充
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// pkcs填充取下
func PKCS7UnPadding(orignData []byte) []byte {
	length := len(orignData)
	unpadding := int(orignData[length-1])
	return orignData[:(length - unpadding)]
}

// 填充密钥
func PaddingKey(key []byte) []byte {
	fmt.Println("原始密钥长度：", len(key))

	padLen := 16 - len(key)
	newKey := make([]byte, 16)

	copy(newKey, key)

	randomBytes := make([]byte, padLen)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}

	// 将随机字节添加到密钥
	for i := len(key); i < 16; i++ {
		newKey[i] = randomBytes[i-len(key)]
	}
	fmt.Println("填充后的密钥长度：", len(newKey))

	return newKey
}

func (c *SM4Keys) GenerateKeys(key []byte) {
	// 先把 key 变 uint32，左移挨个填到位置上
	// 且分4组和 FK 进行异或
	k := []uint32{
		((uint32(key[0]) << 24) | (uint32(key[1]) << 16) | (uint32(key[2]) << 8) | (uint32(key[3]))) ^ FK[0],
		((uint32(key[4]) << 24) | (uint32(key[5]) << 16) | (uint32(key[6]) << 8) | (uint32(key[7]))) ^ FK[1],
		((uint32(key[8]) << 24) | (uint32(key[9]) << 16) | (uint32(key[10]) << 8) | (uint32(key[11]))) ^ FK[2],
		((uint32(key[12]) << 24) | (uint32(key[13]) << 16) | (uint32(key[14]) << 8) | (uint32(key[15]))) ^ FK[3],
	}

	for i := 0; i < 32; i++ {
		// 每四个k的后三个参数和 CK 异或得到也是32位的 A
		A := k[1] ^ k[2] ^ k[3] ^ CK[i]
		// 将 A 拆分为4个8bit的字节进行 S盒变换
		// 例：输入01100101，取前4位0110转换成16进制为6，也就是对应的x轴为6。后4位的0101转换成16进制为5，对应的y轴也就为5
		// 这里uint8（取出8bit然后盒子里找到值）加移位（各个8bit）已经取出S盒值了， 然后再移位回到原位到一起得到新的A
		A = S_Box[uint8(A)] | (S_Box[uint8(A>>8)] << 8) | (S_Box[uint8(A>>16)] << 16) | (S_Box[uint8(A>>24)] << 24)

		// 将A与左移13位及左移23位的A进行异或处理作为函数T的输出C
		A = A ^ bits.RotateLeft32(A, 13) ^ bits.RotateLeft32(A, 23)

		// 用函数来让A循环移位 进行下一轮函数 T
		c.subkeys[i] = k[0] ^ A

		// k分组交换 子密钥k4继续参与下一轮
		k[0] = k[1]
		k[1] = k[2]
		k[2] = k[3]
		k[3] = c.subkeys[i]
	}
}

func (c *SM4Keys) Encrypt(dst, src []byte) {
	EncryptOn(c.subkeys[:], dst, src)
}

func (c *SM4Keys) Decrypt(dst, src []byte) {
	DecryptOn(c.subkeys[:], dst, src)
}

func f(x uint32) uint32 {
	// 操作和扩展密钥类似 区别是这里有四个循环异或
	b := S_Box[uint8(x)] | (S_Box[uint8(x>>8)] << 8) | (S_Box[uint8(x>>16)] << 16) | (S_Box[uint8(x>>24)] << 24)
	return b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^ bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
}

func EncryptOn(subkeys []uint32, dst []byte, src []byte) {
	m := []uint32{
		(uint32(src[0]) << 24) | (uint32(src[1]) << 16) | (uint32(src[2]) << 8) | (uint32(src[3])),
		(uint32(src[4]) << 24) | (uint32(src[5]) << 16) | (uint32(src[6]) << 8) | (uint32(src[7])),
		(uint32(src[8]) << 24) | (uint32(src[9]) << 16) | (uint32(src[10]) << 8) | (uint32(src[11])),
		(uint32(src[12]) << 24) | (uint32(src[13]) << 16) | (uint32(src[14]) << 8) | (uint32(src[15])),
	}
	// 函数 T2 类似扩展密钥
	for i := 0; i < 32; i++ {
		tmp := m[0] ^ f(m[1]^m[2]^m[3]^subkeys[i])
		m[0] = m[1]
		m[1] = m[2]
		m[2] = m[3]
		m[3] = tmp
	}
	// 反序交换
	for j := 0; j < 4; j++ {
		dst[j*4] = uint8(m[3-j] >> 24)
		dst[j*4+1] = uint8(m[3-j] >> 16)
		dst[j*4+2] = uint8(m[3-j] >> 8)
		dst[j*4+3] = uint8(m[3-j])
	}
	fmt.Println("加密：", dst)

}

func DecryptOn(subkeys []uint32, dst []byte, src []byte) {
	m := []uint32{
		(uint32(src[0]) << 24) | (uint32(src[1]) << 16) | (uint32(src[2]) << 8) | (uint32(src[3])),
		(uint32(src[4]) << 24) | (uint32(src[5]) << 16) | (uint32(src[6]) << 8) | (uint32(src[7])),
		(uint32(src[8]) << 24) | (uint32(src[9]) << 16) | (uint32(src[10]) << 8) | (uint32(src[11])),
		(uint32(src[12]) << 24) | (uint32(src[13]) << 16) | (uint32(src[14]) << 8) | (uint32(src[15])),
	}
	// 函数 T2 类似扩展密钥
	for i := 0; i < 32; i++ {
		tmp := m[0] ^ f(m[1]^m[2]^m[3]^subkeys[31-i])
		m[0] = m[1]
		m[1] = m[2]
		m[2] = m[3]
		m[3] = tmp
	}
	// 反序交换
	for j := 0; j < 4; j++ {
		dst[j*4] = uint8(m[3-j] >> 24)
		dst[j*4+1] = uint8(m[3-j] >> 16)
		dst[j*4+2] = uint8(m[3-j] >> 8)
		dst[j*4+3] = uint8(m[3-j])
	}

	fmt.Println("解密：", string(dst))
}
