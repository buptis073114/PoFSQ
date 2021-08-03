package main

import (
	"./lib"
	"./proverInitPhase"
	"./proverProofPhase"
	"./verifierProofPhase"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"unsafe"
)

const (
	readbitlen int64 = 10
)

func ComputeHmacSha256(message string, secret string) string {		
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	//	fmt.Println(h.Sum(nil))
	sha := hex.EncodeToString(h.Sum(nil))
	//	fmt.Println(sha)
	//	hex.EncodeToString(h.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(sha))

}
func file2Bytes(filename string) ([]byte, error) {

	// File
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// FileInfo:
	stats, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// []byte
	data := make([]byte, stats.Size())
	count, err := file.Read(data)
	if err != nil {
		return nil, err
	}
	fmt.Printf("read file %s len: %d \n", filename, count)
	return data, nil
}





var (
	size int64
	path string
	identity string
)

func generateIndentity(){
	publicKey := lib.GetECCPublicKeyByte("eccpublic.pem")
	identity = lib.GetSHA256HashCode(publicKey)
	fmt.Println("user identity is ", identity)
}

func TestSha256Time(){
	var identity string="c472b3aeaf26ef4ceed0c3b2403b530c7a57962ee2bda1d6edafdc0ef04afc12345678901234567890123456789012";
	var tyrnum int64= 1023
	var trys string
	trys += identity
	trys += strconv.FormatInt(tyrnum, 10)
	lib.GetSHA256HashCode([]byte(trys))
}

func usage(){
	fmt.Println("./main.exe proverinit")
	fmt.Println("./main.exe proverproof")
	fmt.Println("./main.exe proververify")
}


func main() {

	proverInitPhase.TestGenerateBlock()
	generateIndentity()
	proverInitPhase.GenerateEvidenceFile(identity)

	publicKey := lib.GetECCPublicKeyByte("eccpublic.pem")
	identity := lib.GetSHA256HashCode(publicKey)
	fmt.Println("user identity is ", identity)

	var ch string = "12345678901234567890123456789014"

	filename:="5K"
	var readbitlen int64=10
	node := proverProofPhase.GenerateMerkleTree(filename,readbitlen,identity,ch)
	fmt.Println("Information transmitted is ", node)
	fmt.Println("Size of information transmitted is ", unsafe.Sizeof(node))
	verifierProofPhase.Verify(node,filename,identity,readbitlen,ch)
}

