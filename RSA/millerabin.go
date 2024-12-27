package main

import (
	"math/big"
	"math/rand"
	"time"
)

// 1.费马
// 如果a是素数，则(p ^ (a - 1)) % a恒等于1
func fmod(a *big.Int, p int64) bool {
	one, _ := new(big.Int).SetString("1", 10)
	a_ := new(big.Int).Sub(a, one)
	result := new(big.Int).Exp(new(big.Int).SetInt64(p), a_, a)
	if result.String() != "1" {
		return false //此时出错 返回false 结果必须要为1
	}
	return true
}

// 2. MillerRabbin 素性检验
func MillerRabbin(a *big.Int) bool {
	p := new(big.Int).Set(a)

	// 1. 将 p-1 拆分为 2^s * d
	d := new(big.Int).Sub(p, big.NewInt(1))
	s := int64(0)
	for d.Bit(0) == 0 {
		s++
		d.Div(d, big.NewInt(2)) // d 被 2 除尽，直到 d 变为奇数
	}

	rand.Seed(time.Now().UnixNano())

	// 2. 进行 100 次检验
	for i := 0; i < 100; i++ {
		// 随机选择基数 a，满足 1 < a < p-1
		n := rand.Int63()
		if new(big.Int).SetInt64(n).Cmp(p) >= 0 || n <= 1 {
			n = rand.Int63n(p.Int64()-1) + 1
		}
		a := new(big.Int).SetInt64(n)

		// 3. 计算 a^d % p 结果儿是不是1和 p-1 是就通过~
		x := new(big.Int).Exp(a, d, p)
		if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(new(big.Int).Sub(p, big.NewInt(1))) == 0 {
			continue // 该次检验通过，继续测试下一个基数
		}

		// 4. 计算 a^(2^r * d) % p
		passed := false
		for r := int64(0); r < s; r++ {
			x = new(big.Int).Exp(x, big.NewInt(2), p) // x = x^2 % p
			if x.Cmp(big.NewInt(1)) == 0 {
				return false // 如果中途 x 变为 1，则 p 不是素数
			}
			if x.Cmp(new(big.Int).Sub(p, big.NewInt(1))) == 0 {
				passed = true
				break // x 成为 p-1，说明通过了该基数的检验
			}
		}

		if !passed {
			return false // 没有通过检验，p 不是素数
		}
	}
	return true
}

/*
3. 用于提供长度为n的数，用于提取大素数
*/
func GenerateBigRange(n int64) *big.Int {
	length := new(big.Int).SetInt64(n)
	re, _ := new(big.Int).SetString("10", 10) // 比如10的几次
	re.Exp(re, length, nil)
	return re
}

/*
4. 用于生成大素数
*/
func GenerateBigPrimeP(n int64) *big.Int {
	numRange := GenerateBigRange(n)
	ran := rand.New(rand.NewSource(time.Now().UnixNano())) //创建的时候需要初始化其中一个值 用于生成随机数
	ran.Seed(time.Now().UnixNano())

	p := new(big.Int).Rand(ran, numRange)
	for !MillerRabbin(p) {
		p.Rand(ran, numRange) //更新p
	}

	return p
}
