package proverInitPhase

import (
	"../lib"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

var (
	size int64
	path string
	identity string
)

const (
	message = "hello world!"
	secret  = "0933e54e76b24731a2d84b6b463ec04c"
	//fileName = "C:\\Users\\Yuan Fy\\OneDrive\\Documents\\ITFSS\\ITFSS\\bianyi.png"
	//fileName = "1K"
	readbitlen int64 = 10
)


func genreateBlock(){
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Fatalln(err)
	}
	err = os.Truncate(path, size)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("file create succeed, path: %s, size: %d Byte\n", path, size)
	file.Close()
}

func calculatesha256(){
	// 对文件加密
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("The sha256 value of the block is %x\n", h.Sum(nil))
}

func TestGenerateBlock(){
	size=4*1024*1024
	path="Block"
	genreateBlock()
	start := time.Now()
	calculatesha256()
	elapsed := time.Since(start)
	fmt.Println("consumed time of sha256 is ", elapsed)
	generateBlockFile()
}
func generateBlockFile(){
	size=1*1024
	path="1K"
	genreateBlock()
	fmt.Println("1K blockfile generate success")

	size=5*1024
	path="5K"
	genreateBlock()
	fmt.Println("5K blockfile generate success")

	size=50*1024
	path="50K"
	genreateBlock()
	fmt.Println("50K blockfile generate success")


	size=500*1024
	path="500K"
	genreateBlock()
	fmt.Println("500K blockfile generate success")

	size=1024*1024
	path="1024K"

	genreateBlock()
	fmt.Println("1024K blockfile generate success")

	size=2048*1024
	path="2048K"
	genreateBlock()
	fmt.Println("2048K blockfile generate success")



	size=3*1024*1024
	path="3072K"
	genreateBlock()
	fmt.Println("3072K blockfile generate success")

	size=4*1024*1024
	path="4096K"
	genreateBlock()
	fmt.Println("4096K blockfile generate success")

	size=5*1024*1024
	path="5120K"
	genreateBlock()
	fmt.Println("5120K blockfile generate success")
}






//According to the shared file, the proof file is generated, which includes two parts: one is to generate the leaf node of Merkel tree, which is stored in the. Block file; the other is random number, which is stored in the. nounce file
func testevidencefile(fileName string , identity string) {
	//
	var evidencefilepath = fileName + ".blocks"
	var evidencenouncefile = fileName + ".nounce"
	lib.GenerateEvidenceFile(identity, fileName, evidencefilepath, evidencenouncefile, readbitlen)
	evidencefilesize := lib.CalcEvidenceFileSize(fileName, readbitlen, 256)
	//获取文件大小
	filesize := lib.GetFileSize(evidencefilepath)
	if evidencefilesize == filesize {
		fmt.Println("yes")
		fmt.Println("size of file .blocks is ",filesize)
		fmt.Println("size of file .nounce is ",lib.GetFileSize(evidencenouncefile))
	}
}

func GenerateEvidenceFile(identity string){

	////test generate evidence file
	t1:=time.Now() //get current time
	fileName:="1K"
	testevidencefile( fileName, identity)
	elapsed := time.Since(t1)
	fmt.Println("the time of generating 1K's evidence file is ", elapsed)


	t1=time.Now() //get current time
	fileName="5K"
	testevidencefile( fileName, identity)
	elapsed = time.Since(t1)
	fmt.Println("the time of generating 5K's evidence file is ", elapsed)

	t1=time.Now() //get current time
	fileName="50K"
	testevidencefile( fileName, identity)
	elapsed = time.Since(t1)
	fmt.Println("the time of generating 5K's evidence file is ", elapsed)

	t1=time.Now() //get current time
	fileName="500K"
	testevidencefile( fileName, identity)
	elapsed = time.Since(t1)
	fmt.Println("the time of generating 50K's evidence file is ", elapsed)


	t1=time.Now() //get current time
	fileName="1024K"
	testevidencefile( fileName, identity)
	elapsed = time.Since(t1)
	fmt.Println("the time of generating 1024K's evidence file is ", elapsed)

	t1=time.Now() //get current time
	fileName="2048K"
	testevidencefile( fileName, identity)
	elapsed = time.Since(t1)
	fmt.Println("the time of generating 2048K's evidence file is ", elapsed)




}
