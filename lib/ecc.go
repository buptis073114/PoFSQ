package lib
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"hash"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"strconv"
)

/*
 * 生成椭圆曲线非对称加密的私钥和公钥
 * elliptic.Curve:elliptic.P521()/elliptic.P384()/elliptic.P256()
 */
func GenerateECCKey(c elliptic.Curve, privatePath,publicPath string){
	// 生成密钥
	privateKey, _ := ecdsa.GenerateKey(c, rand.Reader)
	// 保存密钥
	// x509编码
	x509PrivateKey, _ := x509.MarshalECPrivateKey(privateKey)

	//pem编码编码
	block := pem.Block{
		Type:"ecc private key",
		Bytes:x509PrivateKey,
	}

	//保存到文件中
	privateFile, _ := os.Create(privatePath)
	pem.Encode(privateFile,&block)

	defer privateFile.Close()

	////////////////////保存公钥//////////////////////
	// x509编码
	x509PublicKey, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	// pem编码
	publicBlock := pem.Block{
		Type:"ecc public key",
		Bytes:x509PublicKey,
	}

	publicFile, _ := os.Create(publicPath)
	defer publicFile.Close()

	pem.Encode(publicFile,&publicBlock)
}

func TestGenECC()  {
	GenerateECCKey(elliptic.P521(), "eccPri.pem","eccpub.pem")
}


func getKey() (*ecdsa.PrivateKey, error) {
	//prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return prk, err
	}
	return prk, nil
}

func calculateHashcode(data string) string {
	nonce := 0
	var str string
	var check string
	pass := false
	var dif int = 4
	for nonce = 0; ; nonce++ {
		str = ""
		check = ""
		check = data + strconv.Itoa(nonce)
		h := sha256.New()
		h.Write([]byte(check))
		hashed := h.Sum(nil)
		str = hex.EncodeToString(hashed)
		for i := 0; i < dif; i++ {
			if str[i] != '0' {
				break
			}
			if i == dif-1 {
				pass = true
			}
		}
		if pass == true {
			return str
		}
	}
}

// 生成Ecc曲线的秘钥对儿
func GenerateEccKeyPair(fileDirectory string, curve elliptic.Curve) (err error) {

	var (
		privateKey     *ecdsa.PrivateKey
		privDerText    []byte
		privBlock      pem.Block
		privFileHandle *os.File
		pubDerText     []byte
		pubBlock       pem.Block
		pubFileHandle  *os.File
	)

	// 1. 使用指定的曲线生成私钥
	if privateKey, err = ecdsa.GenerateKey(curve, rand.Reader); err != nil {
		return
	}

	// 2. 使用x509编码
	if privDerText, err = x509.MarshalECPrivateKey(privateKey); err != nil {
		return
	}
	// 3. 生成私钥的block
	privBlock = pem.Block{
		Type:    "ECDSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDerText,
	}
	// 4. 创建私钥存储的文件,并写入文件
	if privFileHandle, err = os.Create(path.Join(fileDirectory, fmt.Sprintf("ecdsa_private_key_%s.pem", curve.Params().Name))); err != nil {
		return
	}
	// 5. 写入
	if err = pem.Encode(privFileHandle, &privBlock); err != nil {
		return
	}

	// 6. 使用x509编码
	if pubDerText, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey); err != nil {
		return
	}

	// 7. 生成公钥的block
	pubBlock = pem.Block{
		Type:    "ECDSA PUBLIC KEY",
		Headers: nil,
		Bytes:   pubDerText,
	}
	// 8. 创建公钥存储的文件,并写入文件
	if pubFileHandle, err = os.Create(path.Join(fileDirectory, fmt.Sprintf("ecdsa_public_key_%s.pem", curve.Params().Name))); err != nil {
		return
	}

	// 9.写入
	if err = pem.Encode(pubFileHandle, &pubBlock); err != nil {
		return
	}

	return
}

// 加密,只支持P256
func ECCEncript(pubPemFilePath string, src []byte) (dst []byte, err error) {
	var (
		pubKeyPemContent []byte
		pubKeyBlock      *pem.Block
		pubKey           interface{}
		eccPubKey        *ecdsa.PublicKey
		eciesPubKey      *ecies.PublicKey
		ok               bool
	)
	// 1. 读取公钥pem内容
	if pubKeyPemContent, err = ioutil.ReadFile(pubPemFilePath); err != nil {
		return
	}

	// 2. 使用pem解码
	pubKeyBlock, _ = pem.Decode(pubKeyPemContent)

	// 3. 使用x509解码
	if pubKey, err = x509.ParsePKIXPublicKey(pubKeyBlock.Bytes); err != nil {
		return
	}

	// 4. 转化为ecdsa的pubkey
	if eccPubKey, ok = pubKey.(*ecdsa.PublicKey); !ok {
		err = errors.New("获取ecdsa公钥失败")
		return
	}

	// 5. 转化为ecies的pubkey
	eciesPubKey = ecies.ImportECDSAPublic(eccPubKey)

	// 6. 加密
	dst, err = ecies.Encrypt(rand.Reader, eciesPubKey, src, nil, nil)

	return
}

// 解密,只支持P256
func ECCDecrypt(privPemFilePath string, src []byte) (dst []byte, err error) {

	var (
		privKeyPemContent []byte
		privKeyBlock      *pem.Block
		privKey           interface{}
		eccPrivKey        *ecdsa.PrivateKey
		eciesPrivKey      *ecies.PrivateKey
		ok                bool
	)

	// 1. 获取私钥文件的内容
	if privKeyPemContent, err = ioutil.ReadFile(privPemFilePath); err != nil {
		log.Println(err)
		return
	}

	// 2. 获取pem格式的block
	privKeyBlock, _ = pem.Decode(privKeyPemContent)

	// 3. x509解码
	if privKey, err = x509.ParseECPrivateKey(privKeyBlock.Bytes); err != nil {
		log.Println(err)
		return
	}

	// 4. 转化为ecdsa格式的priKey
	if eccPrivKey, ok = privKey.(*ecdsa.PrivateKey); !ok {
		err = errors.New("获取ecc私钥失败")
		return
	}

	// 5. 转化为ecies格式的私钥
	eciesPrivKey = ecies.ImportECDSA(eccPrivKey)

	// 6. 使用私钥解密
	dst, err = eciesPrivKey.Decrypt(src, nil, nil)
	return
}
// 数字签名
func ECCSign(privPemFilePath string, src []byte, hashType crypto.Hash) (dst []byte, err error) {

	var (
		privKeyPemContent []byte
		privKeyBlock      *pem.Block
		eccPrivKey        *ecdsa.PrivateKey
		hasher            hash.Hash
		srcHash           []byte
		r                 *big.Int
		s                 *big.Int
	)

	// 1. 获取私钥文件的内容
	if privKeyPemContent, err = ioutil.ReadFile(privPemFilePath); err != nil {
		log.Println(err)
		return
	}

	// 2. 获取pem格式的block
	privKeyBlock, _ = pem.Decode(privKeyPemContent)

	// 3. x509解码
	if eccPrivKey, err = x509.ParseECPrivateKey(privKeyBlock.Bytes); err != nil {
		log.Println(err)
		return
	}

	// 4. 生成原文的hash
	hasher = hashType.New()
	if _, err = hasher.Write(src); err != nil {
		return
	}
	srcHash = hasher.Sum(nil)

	// 5.签名获取r和s
	if r, s, err = ecdsa.Sign(rand.Reader, eccPrivKey, srcHash); err != nil {
		return
	}
	dst = append(r.Bytes(), s.Bytes()...)
	return
}

// 数字签名验证
func ECCVerify(pubPemFilePath string, src []byte, hashType crypto.Hash, sig []byte) (err error) {

	var (
		pubKeyPemContent []byte
		pubKeyBlock      *pem.Block
		pubKey           interface{}
		eccPubKey        *ecdsa.PublicKey
		ok               bool
		hasher           hash.Hash
		srcHash          []byte
		isVerified       bool
		r                big.Int
		s                big.Int
	)

	// 1. 读取公钥pem内容
	if pubKeyPemContent, err = ioutil.ReadFile(pubPemFilePath); err != nil {
		return
	}

	// 2. 使用pem解码
	pubKeyBlock, _ = pem.Decode(pubKeyPemContent)

	// 3. 使用x509解码
	if pubKey, err = x509.ParsePKIXPublicKey(pubKeyBlock.Bytes); err != nil {
		return
	}

	// 4. 转化为ecdsa的pubkey
	if eccPubKey, ok = pubKey.(*ecdsa.PublicKey); !ok {
		err = errors.New("获取ecdsa公钥失败")
		return
	}

	// 5. 生成原文的hash
	hasher = hashType.New()
	if _, err = hasher.Write(src); err != nil {
		return
	}
	srcHash = hasher.Sum(nil)

	// 6. 验证签名
	r.SetBytes(sig[:len(sig)/2])
	s.SetBytes(sig[len(sig)/2:])
	isVerified = ecdsa.Verify(eccPubKey, srcHash, &r, &s)
	if !isVerified {
		err = errors.New("验证签名失败")
	}
	return
}

//生成ECC椭圆曲线密钥对，保存到文件
func GenerateECCKey1() {
	//生成密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	//privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	//保存私钥
	//生成文件
	privatefile, err := os.Create("eccprivate.pem")
	if err != nil {
		panic(err)
	}
	//x509编码
	eccPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	//pem编码
	privateBlock := pem.Block{
		Type:  "ecc private key",
		Bytes: eccPrivateKey,
	}
	pem.Encode(privatefile, &privateBlock)
	//保存公钥
	publicKey := privateKey.PublicKey
	//创建文件
	publicfile, err := os.Create("eccpublic.pem")
	//x509编码
	eccPublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	//pem编码
	block := pem.Block{Type: "ecc public key", Bytes: eccPublicKey}
	pem.Encode(publicfile, &block)
}

//取得ECC私钥
func GetECCPrivateKey(path string) *ecdsa.PrivateKey {
	//读取私钥
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//x509解码
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return privateKey
}

//取得ECC公钥
func GetECCPublicKey(path string) *ecdsa.PublicKey {
	//读取公钥
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解密
	block, _ := pem.Decode(buf)
	//x509解密
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		panic(err)
	}
	publicKey := publicInterface.(*ecdsa.PublicKey)
	return publicKey
}

//取得ECC公钥
func GetECCPublicKeyByte(path string) ([]byte) {
	//读取公钥
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解密
	block, _ := pem.Decode(buf)
	//x509解密
	//x509.ParsePKIXPublicKey(block.Bytes)
	return block.Bytes
}
//对消息的散列值生成数字签名
func SignECC(msg []byte, path string)([]byte,[]byte) {
	//取得私钥
	privateKey := GetECCPrivateKey(path)
	//计算哈希值
	hash := sha256.New()
	//填入数据
	hash.Write(msg)
	bytes := hash.Sum(nil)
	//对哈希值生成数字签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, bytes)
	if err != nil {
		panic(err)
	}
	rtext, _ := r.MarshalText()
	stext, _ := s.MarshalText()
	return rtext, stext
}

//验证数字签名
func VerifySignECC(msg []byte,rtext,stext []byte,path string) bool{
	//读取公钥
	publicKey:=GetECCPublicKey(path)
	//计算哈希值
	hash := sha256.New()
	hash.Write(msg)
	bytes := hash.Sum(nil)
	//验证数字签名
	var r,s big.Int
	r.UnmarshalText(rtext)
	s.UnmarshalText(stext)
	verify := ecdsa.Verify(publicKey, bytes, &r, &s)
	return verify
}

func ECCEncrypttest(pt []byte, pubPemFilePath string) (dst []byte, err error) {
	var (
		pubKeyPemContent []byte
		pubKeyBlock      *pem.Block
		pubKey           interface{}
		eccPubKey        *ecdsa.PublicKey
		eciesPubKey      *ecies.PublicKey
		ok               bool
	)
	// 1. 读取公钥pem内容
	if pubKeyPemContent, err = ioutil.ReadFile(pubPemFilePath); err != nil {
		return
	}

	// 2. 使用pem解码
	pubKeyBlock, _ = pem.Decode(pubKeyPemContent)

	// 3. 使用x509解码
	if pubKey, err = x509.ParsePKIXPublicKey(pubKeyBlock.Bytes); err != nil {
		return
	}

	// 4. 转化为ecdsa的pubkey
	if eccPubKey, ok = pubKey.(*ecdsa.PublicKey); !ok {
		err = errors.New("获取ecdsa公钥失败")
		return
	}
	fmt.Println("eccPubKey：",eccPubKey)
	// 5. 转化为ecies的pubkey
	eciesPubKey = ecies.ImportECDSAPublic(eccPubKey)

	// 5. 转化为ecies的pubkey
	//eciesPubKey = ecies.ImportECDSAPublic(publicKey)
	//fmt.Println("eciesPubKey：",eciesPubKey)
	ct, err := ecies.Encrypt(rand.Reader, eciesPubKey, pt, nil, nil)
	return ct, err
}

func ECCDecrypttest(ct []byte, privPemFilePath string) (dst []byte, err error) {
	var (
		privKeyPemContent []byte
		privKeyBlock      *pem.Block
		privKey           interface{}
		eccPrivKey        *ecdsa.PrivateKey
		eciesPrivKey      *ecies.PrivateKey
		ok                bool
	)

	// 1. 获取私钥文件的内容
	if privKeyPemContent, err = ioutil.ReadFile(privPemFilePath); err != nil {
		log.Println(err)
		return
	}
	// 2. 获取pem格式的block
	privKeyBlock, _ = pem.Decode(privKeyPemContent)

	// 3. x509解码
	if privKey, err = x509.ParseECPrivateKey(privKeyBlock.Bytes); err != nil {
		log.Println(err)
		return
	}
	// 4. 转化为ecdsa格式的priKey
	if eccPrivKey, ok = privKey.(*ecdsa.PrivateKey); !ok {
		err = errors.New("获取ecc私钥失败")
		return
	}
	//取得私钥
	//eccPrivKey = GetECCPrivateKey(privPemFilePath)

	fmt.Println("eccPrivKey：",eccPrivKey)
	// 5. 转化为ecies格式的私钥
	eciesPrivKey = ecies.ImportECDSA(eccPrivKey)
	pt, err := eciesPrivKey.Decrypt(ct, nil, nil)
	return pt, err
}



func ECCEncrypt2(pt []byte, puk ecies.PublicKey) ([]byte, error) {
	ct, err := ecies.Encrypt(rand.Reader, &puk, pt, nil, nil)
	return ct, err
}

func ECCDecrypt2(ct []byte, prk ecies.PrivateKey) ([]byte, error) {
	pt, err := prk.Decrypt(ct, nil, nil)
	return pt, err
}




func TestEncAndDec() {

	var mt = "20181111"
	var pn = "18811881188"
	var ln = "001"
	var mn = "importantmeeting"
	var rn = "216"
	data := mt + pn + ln + mn + rn
	hdata := calculateHashcode(data)
	fmt.Println("信息串：", data)
	fmt.Println("sha256加密后：", hdata)
	////bdata := []byte(hdata)
	////prk, err := getKey()
	////GenerateEccKeyPair("./",elliptic.P521())
	//var bytedata []byte = []byte(hdata)
	//
	//ECCEncript("./ecdsa_public_key_P-521.pem",bytedata)


	//生成ECC密钥对文件
	GenerateECCKey1()
	//模拟发送者
	//要发送的消息
	msg:=[]byte(data)
	//生成数字签名
	rtext,stext:=SignECC(msg,"eccprivate.pem")

	//模拟接受者
	//接受到的消息
	acceptmsg:=[]byte(data)
	//接收到的签名
	acceptrtext:=rtext
	acceptstext:=stext
	//验证签名
	verifySignECC := VerifySignECC(acceptmsg, acceptrtext, acceptstext, "eccpublic.pem")
	fmt.Println("验证结果：",verifySignECC)

	//endata, err := ECCEncrypttest([]byte(msg), "eccpublic.pem")
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("ecc公钥加密后：", hex.EncodeToString(endata))
	//dedata, err := ECCDecrypttest(endata, "eccprivate.pem")
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("私钥解密：", string(dedata))


	//prk, err := getKey()
	//prk2 := ecies.ImportECDSA(prk)
	//puk2 := prk2.PublicKey
	//
	//fmt.Println("puk2：", puk2)
	//fmt.Println("prk2：", prk2)
	//
	//
	//endata, err := ECCEncrypt2([]byte(data), puk2)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("ecc公钥加密后：", hex.EncodeToString(endata))
	//dedata, err := ECCDecrypt2(endata, *prk2)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("私钥解密：", string(dedata))
}