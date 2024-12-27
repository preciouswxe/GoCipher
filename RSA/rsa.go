package main

import (
	"fmt"
	"math/big"
)

func Calculate_n(HugeP *big.Int, HugeQ *big.Int) *big.Int {
	result := new(big.Int)
	result.Mul(HugeP, HugeQ)
	fmt.Println("计算n=p*q结果为:", result)
	return result
}

func Calculate_varphi(HugeP *big.Int, HugeQ *big.Int) *big.Int {
	one := big.NewInt(1)
	// 计算p - 1
	pSubOne := new(big.Int).Sub(HugeP, one)
	// 计算q - 1
	qSubOne := new(big.Int).Sub(HugeQ, one)

	result := new(big.Int)
	// 计算(p - 1) * (q - 1)
	result.Mul(pSubOne, qSubOne)

	return result
}

// 扩展欧几里得蒜法 ，返回 gcd, x, y 使得 a * x + b * y = gcd
func Extended_gcd(a, b, x, y *big.Int) (*big.Int, *big.Int, *big.Int) {
	// 基本情况，如果 b == 0，则返回 a 和 1, 0
	if b.Cmp(big.NewInt(0)) == 0 {
		return a, big.NewInt(1), big.NewInt(0)
	}

	// 递归调用
	gcd, x1, y1 := Extended_gcd(b, new(big.Int).Mod(a, b), x, y)

	// 算新的 x 和 y
	xResult := y1
	yResult := new(big.Int).Sub(x1, new(big.Int).Mul(new(big.Int).Div(a, b), y1))

	// 打印当前的 gcd 和 x, y
	fmt.Println("本轮gcd=", gcd, " x=", xResult, " y=", yResult)

	return gcd, xResult, yResult
}

// 计算私钥 d，计算 e 对于 φ(n) 的模反元素 d
func GetPrivate_d(e, varphi *big.Int) (*big.Int, error) {
	fmt.Println("传入的参数e=", e, " , varphi=", varphi)

	// 初始化x和yds
	x := big.NewInt(1)
	y := big.NewInt(0)

	gcd, x, y := Extended_gcd(e, varphi, x, y)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("e和varphi不互质，无法计算私钥！")
	}

	fmt.Println("扩展欧几里得算法结果：gcd = ", gcd, ", x = ", x, " y = ", y)

	// 确保结果为正
	if x.Cmp(big.NewInt(0)) < 0 {
		x.Add(x, varphi) // 如果 x 是负数，转为正数，通过加上 varphi (n = p * q)
		fmt.Println("x 计算为负数，正在加上 varphi 后为：", x)
	}

	// 确保私钥 d 小于 varphi(n)
	if x.Cmp(varphi) >= 0 {
		x.Sub(x, varphi)
	}

	// 验证 ed ≡ 1 mod φ(n)
	ed := new(big.Int).Mul(e, x)
	ed.Mod(ed, varphi)
	if ed.Cmp(big.NewInt(1)) == 0 {
		fmt.Println("公钥 e 和 私钥 d 满足 ed ≡ 1 mod φ(n)")
	} else {
		fmt.Println("公钥 e 和 私钥 d 不满足 ed ≡ 1 mod φ(n)")
		return nil, fmt.Errorf("ed ≡ 1 mod φ(n) 不成立")
	}

	fmt.Println("最终计算出的私钥 d = ", x)

	return x, nil
}

// 将字符串转化为数字
func stringToIntArray(input string) ([]*big.Int, *big.Int) {
	var mArray []*big.Int
	var maxDigitLen int64 = 0
	for _, char := range input {
		// 计算每个字符的ASCII码值
		m := big.NewInt(int64(char))
		mArray = append(mArray, m)
		// 寻找最大值来判断n的大小
		if m.Cmp(big.NewInt(maxDigitLen)) > 0 {
			maxDigitLen = m.Int64()
		}
	}
	return mArray, big.NewInt(maxDigitLen)
}

// 加密函数
func Encrypt(e, n *big.Int, input string) ([]*big.Int, error) {
	mArray, _ := stringToIntArray(input)
	var cipherArray []*big.Int
	for _, m := range mArray {
		// 加密公式 c = m^e mod n
		c := new(big.Int).Exp(m, e, n)
		cipherArray = append(cipherArray, c)
	}
	return cipherArray, nil
}

// 解密函数
func Decrypt(d, n *big.Int, cipherArray []*big.Int) (string, error) {
	var decryptedMessage string
	for _, c := range cipherArray {
		// 解密公式 m = c^d mod n
		m := new(big.Int).Exp(c, d, n)
		decryptedMessage += string(m.Int64())
	}
	return decryptedMessage, nil
}
