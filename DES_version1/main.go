package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"main/src"
	"os"
	"strings"
)

// 如果不足六十四位密钥 进行随机填充
func PadKeyWithRandom(key []byte) []byte {
	// 输出原始密钥长度
	fmt.Println("原始密钥长度：", len(key))
	// 计算需要填充的字节数
	padLen := 8 - len(key)
	// 创建一个新的字节切片，长度为64位 8字节
	newKey := make([]byte, 8)
	// 复制原始密钥到新密钥的开头
	copy(newKey, key)
	// 生成随机字节填充剩余字节
	randomBytes := make([]byte, padLen)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	// 将随机字节添加到密钥
	for i := len(key); i < 8; i++ {
		newKey[i] = randomBytes[i-len(key)]
	}
	// 输出填充后的密钥长度
	fmt.Println("填充后的密钥长度：", len(newKey))

	return newKey
}

// 如果明文不足64位bit 就填充
func PadPlaintext(plaintext []byte) []byte {
	for len(plaintext) < 8 {
		plaintext = append(plaintext, 0x00)
	}
	return plaintext
}

// 初始置换 最开始
func InitialPermutation(text []byte) []byte {
	if len(text) != 8 {
		panic("Invalid len of 64 bits for Init")
	}
	var piece = [][]int{
		{58, 50, 42, 34, 26, 18, 10, 2},
		{60, 52, 44, 36, 28, 20, 12, 4},
		{62, 54, 46, 38, 30, 22, 14, 6},
		{64, 56, 48, 40, 32, 24, 16, 8},
		{57, 49, 41, 33, 25, 17, 9, 1},
		{59, 51, 43, 35, 27, 19, 11, 3},
		{61, 53, 45, 37, 29, 21, 13, 5},
		{63, 55, 47, 39, 31, 23, 15, 7},
	}
	result := make([]byte, 8)
	for i := 0; i < len(piece); i++ {
		for j := 0; j < 8; j++ {
			index := piece[i][j] - 1
			// 确定该比特位所在的字节在整个密钥字节切片中的某个字节索引
			byteIndex := index / 8
			// 在当前字节内，要处理的比特位相对于字节最高位（第 7 位）的偏移量   就是先确定某个字节再瞬移到要取的比特位
			bitOffset := 7 - (index % 8)
			// 分前后四字节的两段

			// key[bitIndex/8]就是简单的选定要找的字节
			// (1 << (7 - (bitIndex % 8)))作用是挪动1去某个位置，通过与操作来提取出原始字节中我们想要的那个比特位
			// 然后开始为放入c0服务
			// 将前面提取出的比特位再向右移动 7 - (bitIndex % 8) 位，这一步的目的是将提取出的比特位调整到最低位
			// 最后将调整到最低位的比特位再向左移动 bitOffset 位，这样就可以将该比特位设置到 c0 中相应字节的正确位置上
			result[byteIndex] |= (text[index/8] & (1 << (7 - (index % 8)))) >> (7 - (index % 8)) << bitOffset

		}
	}
	fmt.Printf("明文/密文 初始置换结果：%v\n", result)
	return result
}

// 逆置换 最后
func ReversePermutation(text []byte) []byte {
	if len(text) != 8 {
		panic("Invalid len of 64 bits for Reverse")
	}

	var piece = [][]int{
		{40, 8, 48, 16, 56, 24, 64, 32},
		{39, 7, 47, 15, 55, 23, 63, 31},
		{38, 6, 46, 14, 54, 22, 62, 30},
		{37, 5, 45, 13, 53, 21, 61, 29},
		{36, 4, 44, 12, 52, 20, 60, 28},
		{35, 3, 43, 11, 51, 19, 59, 27},
		{34, 2, 42, 10, 50, 18, 58, 26},
		{33, 1, 41, 9, 49, 17, 57, 25},
	}
	result := make([]byte, 8)
	for i := 0; i < len(piece); i++ {
		for j := 0; j < 8; j++ {
			index := piece[i][j] - 1
			// 确定该比特位所在的字节在整个密钥字节切片中的某个字节索引
			byteIndex := index / 8
			// 在当前字节内，要处理的比特位相对于字节最高位（第 7 位）的偏移量   就是先确定某个字节再瞬移到要取的比特位
			bitOffset := 7 - (index % 8)
			result[byteIndex] |= (text[index/8] & (1 << (7 - (index % 8)))) >> (7 - (index % 8)) << bitOffset

		}
	}
	return result
}

// 拆开得L0和R0
func SplitLR(text []byte) ([]byte, []byte) {
	if len(text) != 8 {
		panic("Invalid SplitLR of 64 bits")
	}
	left := text[0:4]
	right := text[4:8]
	return left, right
}

// 拼起来L16和R16
func MergeLR(left, right []byte) []byte {
	if len(left) != 4 || len(right) != 4 {
		panic("Invalid left or right for MergeLR 64 bits size")
	}
	text := make([]byte, 8)
	copy(text[0:4], left)
	copy(text[4:8], right)
	return text
}

/*
// 每个加密轮应该包括扩展、生成每轮子密钥、进行异或、S盒、P盒
func Encrypt(L, R []byte) ([]byte, []byte) {
	Expand32To48(R)
}
*/

// 1. 扩展32->48
func Expand32To48(input []byte) []byte {
	if len(input) != 4 {
		panic("Invalid len of 32bits(4 bytes) for Expand32To48")
	}
	// 置换表
	fmt.Printf("扩展前：%v\n", input)
	permutationTable := [][]int{
		{32, 1, 2, 3, 4, 5},
		{4, 5, 6, 7, 8, 9},
		{8, 9, 10, 11, 12, 13},
		{12, 13, 14, 15, 16, 17},
		{16, 17, 18, 19, 20, 21},
		{20, 21, 22, 23, 24, 25},
		{24, 25, 26, 27, 28, 29},
		{28, 29, 30, 31, 32, 1},
	}

	result := make([]byte, 6)
	var bitcount = 0  //用于统计result的比特位置
	var bittarget = 0 //统计result放入的具体偏移量
	for row := 0; row < len(permutationTable); row++ {
		for col := 0; col < len(permutationTable[row]); col++ {
			index := permutationTable[row][col] - 1

			bittarget = bitcount % 8
			result[bitcount/8] |= input[index/8] & (1 << (7 - (index % 8))) >> (7 - (index % 8)) << bittarget

			bitcount++
		}
	}
	fmt.Printf("扩展后：%v\n", result)
	return result
}

// 2. 生成子密钥
// 密钥调度算法可以将64位的主密钥分成16个子密钥，每个子密钥48位，用于每轮加密中与输入数据进行异或运算。
func GenerateSubkey(key []byte) [][]byte {
	// 置换选择1
	C0, D0 := PC1Permutation(key)
	var subkeys [][]byte
	for i := 1; i <= 16; i++ {
		c := CircularLeftShift(C0, i)
		d := CircularLeftShift(D0, i)
		subkey := PC2Permutation(c, d)
		subkeys = append(subkeys, subkey)

		// 详细打印当前生成的子密钥内容
		fmt.Printf("生成第 %d 个 子密钥：\n", i)
		fmt.Printf("子密钥内容（十六进制）：")
		for _, b := range subkey {
			fmt.Printf("%02x ", b)
		}
		fmt.Println()

		// 更新左移结果 一共十六轮
		C0 = c
		D0 = d
	}

	fmt.Println()

	return subkeys

}

// 2.1 实现PC - 1置换操作
func PC1Permutation(key []byte) ([]byte, []byte) {
	if len(key) != 8 {
		panic("Invalid key length for PC1Permutation. Expected 8 bytes (64 bits).")
	}
	pc1Table := [][]int{
		{57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18},
		{10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36},
		{63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22},
		{14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4},
	}
	c0 := make([]byte, 4)
	d0 := make([]byte, 4)
	for i := 0; i < len(pc1Table); i++ {
		for j := 0; j < len(pc1Table[i]); j++ {
			// 要处理原始密钥中的第 pc表值-1 个比特位
			bitIndex := pc1Table[i][j] - 1
			// 确定该比特位所在的字节在整个密钥字节切片中的某个字节索引
			byteIndex := bitIndex / 8
			// 在当前字节内，要处理的比特位相对于字节最高位（第 7 位）的偏移量   就是先确定某个字节再瞬移到要取的比特位
			bitOffset := 7 - (bitIndex % 8)
			// 分前后四字节的两段
			if byteIndex < 4 {
				// key[bitIndex/8]就是简单的选定要找的字节
				// (1 << (7 - (bitIndex % 8)))作用是挪动1去某个位置，通过与操作来提取出原始字节中我们想要的那个比特位
				// 然后开始为放入c0服务
				// 将前面提取出的比特位再向右移动 7 - (bitIndex % 8) 位，这一步的目的是将提取出的比特位调整到最低位
				// 最后将调整到最低位的比特位再向左移动 bitOffset 位，这样就可以将该比特位设置到 c0 中相应字节的正确位置上
				c0[byteIndex] |= (key[bitIndex/8] & (1 << (7 - (bitIndex % 8)))) >> (7 - (bitIndex % 8)) << bitOffset
				// 输出提取后比特位在c0中的位置
				//fmt.Printf("提取后比特位在c0中的位置: %d\n", byteIndex)

				// 输出c0的当前状态
				//fmt.Printf("c0当前状态: %v\n", c0)
			} else {
				// 减去 4，因为 d0 是从原始密钥经过处理后得到的后半部分  其他类同
				d0[byteIndex-4] |= (key[bitIndex/8] & (1 << (7 - (bitIndex % 8)))) >> (7 - (bitIndex % 8)) << bitOffset
			}
		}
	}

	fmt.Println("PC-1置换结果如下：")
	fmt.Println("c0 length:", len(c0))
	fmt.Println("c0 content:", c0)
	fmt.Println("d0 length:", len(d0))
	fmt.Println("d0 content:", d0)

	return c0, d0

}

// 2.2 循环左移操作
func CircularLeftShift(data []byte, times int) []byte {
	num := binary.BigEndian.Uint32(data)

	// 将uint32转换为二进制字符串
	binaryStr := fmt.Sprintf("%032b", num)
	fmt.Printf("num的二进制表示: %s\n", binaryStr)

	result := make([]byte, 4)
	if times > 16 || times < 1 {
		panic("ShiftLeft Error")
	}

	var shiftTable = [16]int{
		1, 1, 2, 2, 2, 2, 2, 2,
		1, 2, 2, 2, 2, 2, 2, 1,
	}
	// 由于在数值中，高位在左，低位在右，所以采用右移，在大端模式下是左移
	var out uint32 = num
	for i := 0; i < shiftTable[times-1]; i++ {
		// 获取最低位
		h := num & 1
		//fmt.Printf("h:%d\n", h)

		outStr := fmt.Sprintf("%032b", out)
		fmt.Printf("out之前的二进制表示: %s\n", outStr)

		// 先将out整体左移一位
		out <<= 1

		// 当h为0时，进行特殊处理将num的最高位补到out的最低位
		if h == 0 {
			// 获取num的最高位
			highestBit := num >> 31
			// 将num的最高位补到out的最低位
			out |= highestBit
		} else {
			// 当h不为0时，直接将h补到out的最低位
			out |= h
		}

		outStr = fmt.Sprintf("%032b", out)
		fmt.Printf("out左移1次后的二进制表示: %s\n", outStr)

		// 同时对num也进行类似的左移操作，保持数据状态的一致性
		num <<= 1

		// 如果num超过了uint32的范围，进行处理（比如截断等，这里简单示例截断）
		if num > (1<<32 - 1) {
			num &= (1<<32 - 1)
		}
	}

	binary.BigEndian.PutUint32(result, out)

	// 将uint32转换为二进制字符串
	resStr := fmt.Sprintf("%08b", result)
	fmt.Printf("result的二进制表示: %s\n", resStr)

	return result
}

// 2.3 PC-2置换
func PC2Permutation(c []byte, d []byte) []byte {
	// totalBits := 56
	// 这里totalBits应该是56，因为c0和d0都是4字节（32位），拼接起来就是56位
	// fmt.Printf("totalbits:%d\n", totalBits)

	// 不含奇偶校验位第 8、16、24、32、40、48、56位
	pc2Table := [][]int{
		{14, 17, 11, 24, 1, 5},
		{3, 28, 15, 6, 21, 10},
		{23, 19, 12, 4, 26, 8},
		{16, 7, 27, 20, 13, 2},
		{41, 52, 31, 37, 47, 55},
		{30, 40, 51, 45, 33, 48},
		{44, 49, 39, 56, 34, 53},
		{46, 42, 50, 36, 29, 32},
	}
	result := make([]byte, 6)

	// 将切片 d 中的所有元素逐个添加到切片 c 的末尾，然后返回一个新的切片
	combined := append(c, d...)
	fmt.Println("combined: ", combined)

	var bitcount = 0  //用于统计result的比特位置
	var bittarget = 0 //统计result放入的具体偏移量

	for i := 0; i < 8; i++ {
		for j := 0; j < 6; j++ {
			// 获取 表值-1 的真正的索引去cd合体的里面找
			bitIndex := pc2Table[i][j] - 1

			// 获取字节的索引
			byteIndex := bitIndex / 8

			// 根据byteIndex确定从combined中选取比特位所在的字节
			byteValue := combined[byteIndex]

			// 从combined特定字节bytevalue的特定比特位里取出 放入result
			bittarget = bitcount % 8
			result[bitcount/8] |= (byteValue & (1 << (7 - (bitIndex % 8)))) >> (7 - (bitIndex % 8)) << bittarget

			bitcount++

			// 记录所有子密钥的步骤在上面subkey
		}
	}
	fmt.Println("本轮PC-2完成。")
	return result
}

// 3. 异或
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("输入的两个字节切片长度不相等")
	}
	result := make([]byte, len(a))
	// fmt.Println(len(a), len(b))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// 4. S盒  6位变4位
func Sbox48To32(input []byte) []byte {
	if len(input) != 6 {
		panic("Invalid input length for SBox48To32. Expected 6 bytes (48 bits).")
	}

	fmt.Printf("S盒前：%v\n", input)

	output := make([]byte, 4)
	var out uint32 = 0

	// 定义一个掩码，用于提取6位数据块中的每一位
	const bitMask uint8 = 0x20

	// 遍历8个6位数据块
	for i := 0; i < 8; i++ {
		// 提取当前6位数据块
		var b uint8
		for j := 0; j < 6; j++ {
			// 根据当前循环的索引和位掩码，从输入字节切片中提取相应的位
			bitIndex := (i*6 + j) % 6
			// 按位或
			// 可以提取出 input[bitIndex] 字节中与 bitMask 对应的那一位。
			b |= (input[bitIndex] & bitMask) >> (7 - (j % 6))
		}

		// 计算行索引：第1位和第6位
		r := (b&1)<<1 + (b >> 5)

		// 计算列索引：第2到第5位
		c := ((b>>1)&1)<<3 + ((b>>2)&1)<<2 + ((b>>3)&1)<<1 + ((b >> 4) & 1)

		// 从对应的S盒中获取值
		o := src.SBoxes[i][r][c]

		// 将获取的值设置到输出结果中，按位或
		out |= uint32(o) << (i * 4)
	}

	// 将处理后的结果填充到输出切片
	for i := 0; i < 4; i++ {
		output[i] = byte((out >> (i * 8)) & 0xff)
	}

	fmt.Printf("S盒结果：%v\n", output)

	return output
}

// 5. P盒
func PboxExchange(input []byte) []byte {
	Pbox := [][]int{
		{16, 7, 20, 21},
		{29, 12, 28, 17},
		{1, 15, 23, 26},
		{5, 18, 31, 10},
		{2, 8, 24, 14},
		{32, 27, 3, 9},
		{19, 13, 30, 6},
		{22, 11, 4, 25},
	}
	if len(input) != 4 {
		panic("Invalid input length for PboxExchange. Expected 4 bytes(32bits).")
	}
	// 将输入的字节切片转换为uint32类型
	var inputUint32 uint32
	for i, b := range input {
		inputUint32 |= uint32(b) << (uint32(i) * 8)
	}
	fmt.Println("转换为uint32后的输入值: ", inputUint32)

	var out uint32 = 0
	for i := 0; i < 8; i++ {
		for j := 0; j < 4; j++ {
			index := Pbox[i][j] - 1

			bit := (inputUint32 >> uint32(31-index)) & 1
			out |= bit << uint32(i*4+j)
		}

		//fmt.Printf("经过第%d行Pbox置换操作后out的值（十六进制）: %x\n", i, out)
	}

	// 将置换后的结果转换为字节切片返回
	output := make([]byte, 4)
	for i := 0; i < 4; i++ {
		output[i] = byte((out >> (i * 8)) & 0xff)
	}

	fmt.Println("P盒output: ", output)

	return output
}

// 解密函数，执行与加密相反的操作流程
func Decrypt(ciphertext []byte, subkeys [][]byte) []byte {
	fmt.Println("开始解密……")
	// 用于存储每组解密后的结果

	// 转换成字节切片组，8个字节一组
	var cipherGroups [][]byte
	for i := 0; i < len(ciphertext); i += 8 {
		endIndex := i + 8
		if endIndex > len(ciphertext) {
			endIndex = len(ciphertext)
		}
		cipherGroups = append(cipherGroups, []byte(ciphertext[i:endIndex]))
	}

	// 用于存储每组解密后的结果
	var decryptedGroups [][]byte

	for _, group := range cipherGroups {
		println("开始初始置换")

		// 3. 填充明文 初始置换
		//paddedGroup := PadPlaintext(group)
		permutedText := InitialPermutation(group)
		println("初始置换完毕")

		// 4. 拆分L0和R0
		//println("开始拆分L0和R0")
		L, R := SplitLR(permutedText)
		println("拆分L0和R0完毕")

		// 5. 进行16轮加密
		for i := 0; i < 16; i++ {
			// 扩展R
			expandedR := Expand32To48(R)
			//println("扩展完毕")
			// 生成子密钥
			subkey := subkeys[15-i]
			// 异或
			xored := xorBytes(expandedR, subkey)
			//println("异或完毕")
			fmt.Printf("异或结果：%v\n", xored)
			// S盒变换
			sboxed := Sbox48To32(xored)
			//println("S盒完毕")
			// P盒变换
			pboxed := PboxExchange(sboxed)
			//println("P盒完毕")
			// 与L异或
			newL := xorBytes(L, pboxed)
			//println("二次异或完毕")
			L = R
			R = newL
		}

		// 6. 合并L16和R16
		cipherrtext := MergeLR(L, R)

		// 7. 逆置换
		finalCiphertext := ReversePermutation(cipherrtext)

		decryptedGroups = append(decryptedGroups, finalCiphertext)
	}

	// 将所有组的解密结果组合起来
	finalDecryptedText := []byte{}
	for _, decryptedGroup := range decryptedGroups {
		finalDecryptedText = append(finalDecryptedText, decryptedGroup...)
	}

	return finalDecryptedText
}

func main() {

	println("请输入明文：")

	reader := bufio.NewReader(os.Stdin)
	plaintextStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("读取输入时出错：", err)
		return
	}

	// 去除字符串末尾的换行符
	plaintextStr = strings.TrimSpace(plaintextStr)

	// 转换成字节切片组，8个字节一组
	var plainGroups [][]byte
	for i := 0; i < len(plaintextStr); i += 8 {
		endIndex := i + 8
		if endIndex > len(plaintextStr) {
			endIndex = len(plaintextStr)
		}
		plainGroups = append(plainGroups, []byte(plaintextStr[i:endIndex]))
	}

	// 假设主密钥为8字节（64位）
	println("请输入密钥：")
	reader = bufio.NewReader(os.Stdin)
	keyyy, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("读取输入时出错：", err)
		return
	}
	// 去除字符串末尾的换行符
	keyStr := strings.TrimSpace(keyyy)
	key := []byte(keyStr)
	//key := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}

	println("开始填充密钥")

	// 1. 填充密钥（如果需要）
	newKey := PadKeyWithRandom(key)

	//println("填充结果：", newKey)
	println("密钥填充结果：")
	for _, b := range newKey {
		fmt.Printf("%02x ", b)
	}

	println("\n开始生成子密钥……")

	// 2. 生成子密钥
	subkeys := GenerateSubkey(newKey)

	// 用于存储每组加密后的结果
	var encryptedGroups [][]byte

	fmt.Printf("明文字节组数：%d\n", len(plainGroups))
	for _, group := range plainGroups {
		//println(len(group)) 不出意外是一个8一个3 因为This is DES
		println("开始初始置换")

		// 3. 明文填充 + 初始置换
		paddedGroup := PadPlaintext(group)
		permutedText := InitialPermutation(paddedGroup)
		println("初始置换完毕")

		// 4. 拆分L0和R0
		//println("开始拆分L0和R0")
		L, R := SplitLR(permutedText)
		println("拆分L0和R0完毕")

		// 5. 进行16轮加密
		for i := 0; i < 16; i++ {
			// 扩展R
			expandedR := Expand32To48(R)
			//println("扩展完毕")
			// 生成子密钥
			subkey := subkeys[i]
			// 异或
			xored := xorBytes(expandedR, subkey)
			//println("异或完毕")
			fmt.Printf("异或结果：%v\n", xored)
			// S盒变换
			sboxed := Sbox48To32(xored)
			//println("S盒完毕")
			// P盒变换
			pboxed := PboxExchange(sboxed)
			//println("P盒完毕")
			// 与L异或
			newL := xorBytes(L, pboxed)
			//println("二次异或完毕")
			L = R
			R = newL
		}

		// 6. 合并L16和R16
		ciphertext := MergeLR(L, R)

		// 7. 逆置换
		finalCiphertext := ReversePermutation(ciphertext)

		encryptedGroups = append(encryptedGroups, finalCiphertext)
	}

	// 将所有组的加密结果组合起来
	finalEncryptedText := []byte{}
	for _, encryptedGroup := range encryptedGroups {
		finalEncryptedText = append(finalEncryptedText, encryptedGroup...)
	}

	// 调用解密函数进行解密验证
	decryptedText := Decrypt(finalEncryptedText, subkeys)
	fmt.Printf("明文解析字节内容：%d\n", plainGroups)
	fmt.Printf("加密后的密文: %d\n", finalEncryptedText)
	fmt.Printf("解密后的明文: %d\n", decryptedText)

	/*
		// 示例用法
		data := []byte{0x12, 0x34, 0x56, 0x78}
		index := 3
		result := CircularLeftShift(data, index)
		fmt.Printf("原始数据: %x\n", data)
		fmt.Printf("循环左移后的结果: %x\n", result)
	*/
}
