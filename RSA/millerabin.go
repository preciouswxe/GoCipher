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

	rand.Seed(time.Now().UnixNano())
	//进行1000次检验
	for i := 1; i < 100; i++ {
		//判断失败则退出
		n := rand.Int63()
		if new(big.Int).SetInt64(n).Cmp(p) == 1 {
			n = rand.Int63n(p.Int64()-1) + 1
		}
		if !fmod(p, n) {
			return false
		}
	}
	return true
}

/*
3. 用于提供长度为n的数，用于提取大素数
*/
func GenerateBigRange(n int64) *big.Int {
	length := new(big.Int).SetInt64(n)
	re, _ := new(big.Int).SetString("10", 10)
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
