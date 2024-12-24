package main

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	println("请输入要加密的明文：")
	input, err := reader.ReadString('\n')
	if err != nil {
		panic("输入报错！")
	}
	input = input[:len(input)-1] // 去除换行符
	fmt.Println("明文为：", input)

	var p int64
	var q int64

	print("请输入要生成的p的位数: ")
	fmt.Scanf("%d", &p)
	fmt.Scanln() //吸收回车符

	print("请输入要生成的q的位数: ")
	fmt.Scanf("%d", &q)

	HugeP := GenerateBigPrimeP(p)
	HugeQ := GenerateBigPrimeP(q)
	fmt.Println("生成的p：", HugeP)
	fmt.Println("生成的q：", HugeQ)

	n := Calculate_n(HugeP, HugeQ)
	varphi := Calculate_varphi(HugeP, HugeQ)
	fmt.Println("计算varphi = (p-1)*(q-1)结果为:", varphi)

	e := big.NewInt(65537)
	fmt.Println("公钥是：", e)

	// 开始加密
	ciphertext, err := Encrypt(e, n, input)
	if err != nil {
		fmt.Println("加密失败:", err)
		return
	}

	// 输出密文
	fmt.Println("密文为：")
	for _, c := range ciphertext {
		fmt.Print(c, " ")
	}
	fmt.Println()

	// 开始解密
	fmt.Println("----------------------\n")
	fmt.Println("解密验证之\n")
	d, err := GetPrivate_d(e, varphi)
	if err != nil {
		fmt.Println(err)
	}

	// 解密
	decryptedMessage, err := Decrypt(d, n, ciphertext)
	if err != nil {
		fmt.Println("解密失败:", err)
		return
	}

	fmt.Println("\n解密后的明文是：", decryptedMessage, "\n")

}
