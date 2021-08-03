package lib

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/imroc/biu"
	"io"

	//"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

type PathNode struct {
	Row    int64
	Column int64
	Data   []byte
}

func min(a int64, b int64) int64 {
	if a > b {
		return b
	}
	return a
}

type MerkleTree struct {
	RootNode *MerkleNode
}

type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

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

func NewMerkleNode(left, right *MerkleNode, key []byte, data []byte) *MerkleNode {
	mnode := MerkleNode{}
	if nil == left && nil == right {
		mnode.Data = data
		//fmt.Println("mnode.Data is ",mnode.Data)
	} else {
		prevhashes := append(left.Data, right.Data...)

		h := hmac.New(sha256.New, key)
		h.Write(prevhashes)
		//sha := hex.EncodeToString(h.Sum(nil))

		//firsthash := sha256.Sum256(prevhashes)
		//fmt.Println("firsthash[:] is ",firsthash[:])
		mnode.Data = h.Sum(nil)
	}
	mnode.Left = left
	mnode.Right = right
	return &mnode
}

func NewMerkleTree(data [][]byte) *MerkleTree {
	var nodes []MerkleNode
	var key []byte
	//构建叶子节点
	for _, dataum := range data {
		node := NewMerkleNode(nil, nil, key, dataum)
		nodes = append(nodes, *node)
	}
	var i int64 = 0
	var j int64 = 0
	var nSize int64
	for nSize = int64(len(data)); nSize > 1; nSize = (nSize + 1) / 2 {
		for i = 0; i < nSize; i += 2 {
			i2 := min(i+1, nSize-1)
			node := NewMerkleNode(&nodes[j+i], &nodes[j+i2], key, nil)
			nodes = append(nodes, *node)
		}
		j += nSize
	}
	mTree := MerkleTree{&(nodes[len(nodes)-1])}

	fmt.Println("len is ", len(nodes))

	return &mTree
}


func GetSHA256HashCodeFile(path string) (hash string) {
	file, err := os.Open(path)
	if err == nil {
		h_ob := sha256.New()
		_, err := io.Copy(h_ob, file)
		if err == nil {
			hash := h_ob.Sum(nil)
			hashvalue := hex.EncodeToString(hash)
			return hashvalue
		} else {
			return "something wrong when use sha256 interface..."
		}
	} else {
		fmt.Printf("failed to open %s\n", path)
	}
	defer file.Close()
	return
}


func GetSHA256HashCode(message []byte) string {
	hash := sha256.New()
	hash.Write(message)
	bytes := hash.Sum(nil)
	hashCode := hex.EncodeToString(bytes)
	return hashCode

}

func GetSHA256HashCodeString(s string) string {

	hash := sha256.New()
	io.WriteString(hash,s)
	bytes := hash.Sum(nil)
	hashCode := hex.EncodeToString(bytes)
	return hashCode


}

/**
*Bit comparison, this function will compare whether the first bit of two byte arrays is consistent
*Origin byte array 1
*Target byte array 1
*Bit length of bitlen comparison
*If it is the same, it returns true; otherwise, it returns false
 */
func bitcompare(origin []byte, target []byte, bitlen int64) (bool, error) {
	var merchant int64 = bitlen / 8
	var remainder int64 = bitlen % 8
	//fmt.Println("merchant is ",merchant)
	//fmt.Println("remainder is ",remainder)
	if merchant > 0 {
		var iter int64
		for iter = 0; iter < merchant; iter++ {
			//fmt.Println("origin[",iter,"] is ",origin[iter])
			//fmt.Println("target[",iter,"] is ",target[iter])
			if origin[iter] != target[iter] {
				return false, fmt.Errorf("not equal")
			}
		}
	}
	if remainder > 0 {
		//fmt.Println("origin[",merchant,"] is ",biu.ByteToBinaryString(origin[merchant]))
		//fmt.Println("target[",merchant,"] is ",biu.ByteToBinaryString(target[merchant]))
		var aaa byte = origin[merchant] >> (8 - remainder)
		var bbb byte = target[merchant] >> (8 - remainder)
		//fmt.Println("aaa is ",biu.ByteToBinaryString(aaa))
		//fmt.Println("bbb is ",biu.ByteToBinaryString(bbb))
		if aaa != bbb {
			return false, fmt.Errorf("not equal")
		}
	}
	return true, fmt.Errorf("equal")
}

func ReadAllFileIntoMemmory(filePth string) ([][]byte, error) {
	datalen := GetFileSize(filePth)
	file, err := os.Open(filePth)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data := make([]byte, datalen)
	_, err = file.Read(data)
	nodenumber := datalen / 32
	//int_num := *(*int)(unsafe.Pointer(&nodenumber))
	var dataarray [][]byte
	var readiter int64 = 0
	for readiter = 0; readiter < nodenumber; readiter++ {
		var byteiter int64 = 0
		tmpdata := make([]byte, 32)
		for byteiter = 0; byteiter < 32; byteiter++ {
			tmpdata[byteiter] = data[readiter*32+byteiter]
		}
		dataarray = append(dataarray, tmpdata)
	}
	//var dataarray [][]byte =  bytes.SplitN(data,nil,int_num)
	return dataarray, fmt.Errorf("")
}

func ReadAllNouceIntoMemmory(filePth string) ([]string, error) {

	file,err := os.Open(filePth)
	if err != nil {
		return nil, err
	}

	defer file.Close()
	fileinfo,err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := fileinfo.Size()
	buffer := make([]byte,fileSize)

	bytesread,err := file.Read(buffer)
	if err != nil {
		return nil, err
	}

	fmt.Println("bytes read:",bytesread)
	//fmt.Println("bytestream to string:",string(buffer))
	dataarray := strings.Split(string(buffer), ",")
	//fmt.Println("bytestream to string:",dataarray)

	return dataarray, fmt.Errorf("")


	//datalen := GetFileSize(filePth)
	//file, err := os.Open(filePth)
	//if err != nil {
	//	return nil, err
	//}
	//defer file.Close()
	//data := make([]byte, datalen)
	//fmt.Println("data to string:",string(data))
	//_, err = file.Read(data)
	////noucenumber := bytes.IndexByte(data, ',')
	//nodenumber := datalen / 32
	////int_num := *(*int)(unsafe.Pointer(&nodenumber))
	//
	//var dataarray [][]byte
	//var readiter int64 = 0
	//for readiter = 0; readiter < nodenumber; readiter++ {
	//	var byteiter int64 = 0
	//	tmpdata := make([]byte, 32)
	//	for byteiter = 0; byteiter < 32; byteiter++ {
	//		tmpdata[byteiter] = data[readiter*32+byteiter]
	//	}
	//	dataarray = append(dataarray, tmpdata)
	//}
	////var dataarray [][]byte =  bytes.SplitN(data,nil,int_num)
	//return dataarray, fmt.Errorf("")
}

/**
*This function skips skipbittlen bits from the filepth file, reads bufsize bits, and returns a byte array
*Filepth file path
*Bufsize to read bit size
*Skipbitlen skip bit size
*Returns the read byte array. A byte is equal to 8 bits. The returned byte array contains all the bits to be read
 */
func ReadBlock(filePth string, bufSize int64, skipbitlen int64) ([]byte, error) {
	var merchant int64 = skipbitlen / 8
	var remainder int64 = skipbitlen % 8
	var blockbitsize int64
	var iter int64
	if (bufSize % 8) > 0 {
		blockbitsize = (bufSize/8 + 1)
	} else {
		blockbitsize = (bufSize / 8)
	}
	var datalen = blockbitsize + 1
	// File
	file, err := os.Open(filePth)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data := make([]byte, datalen)
	for iter = 0; iter < datalen; iter++ {
		data[iter] = 0
	}
	retdata := make([]byte, blockbitsize)
	for iter = 0; iter < blockbitsize; iter++ {
		retdata[iter] = 0
	}
	_, err = file.ReadAt(data, merchant)
	//fmt.Println("count is ",count)
	//datasignStr := fmt.Sprintf("%x", data)
	//fmt.Println("data is ", datasignStr)

	if remainder > 0 {
		for iter = 0; iter < blockbitsize; iter++ {
			retdata[iter] = (data[iter] << remainder) ^ (data[iter+1] >> (8 - remainder))
		}
	} else {
		for iter = 0; iter < blockbitsize; iter++ {
			retdata[iter] = data[iter]
		}
	}
	return retdata, fmt.Errorf("")
}

//exists Whether the path exists
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

//getFileSize get file size by path(B)
func GetFileSize(path string) int64 {
	if !exists(path) {
		return 0
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fileInfo.Size()
}

func getFileName(path string) string {
	if !exists(path) {
		return ""
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fileInfo.Name()
}

func WriteBlock(path string, comparebyte []byte) {

	outputFile, outputError := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if outputError != nil {
		fmt.Println(outputError)
		return
	}
	defer outputFile.Close()
	outputWriter := bufio.NewWriter(outputFile)
	outputWriter.Write(comparebyte)
	outputWriter.Flush()
}

func WriteNounce(path string, content string) {

	outputFile, outputError := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if outputError != nil {
		fmt.Println(outputError)
		return
	}
	defer outputFile.Close()
	outputWriter := bufio.NewWriter(outputFile)
	outputWriter.WriteString(content)

	outputWriter.Flush()
}

func CalcEvidenceFileSize(filepath string, readbitlen int64, hashlen int64) int64 {
	var blocknum int64 = 0
	filesize := GetFileSize(filepath)
	if (filesize * 8 / readbitlen) > 0 {
		blocknum = (filesize*8/readbitlen + 1)
	} else {
		blocknum = (filesize * 8 / readbitlen)
	}
	return blocknum * hashlen / 8
}

//According to the data path to be shared, the certification file is generated
//The first parameter is the personal unique ID, the second parameter is the source file path, and the third parameter is the bit length of each read
//This function generates a certificate file with suffix. Blocks and a file with suffix. Nounce
func  GenerateEvidenceFile(
	identity string,
	fileName string,
	evidencefilepath string,
	evidencenouncefile string,
	readbitlen int64) {
	var readiter int64 = 0
	var previoushash string
	var tyrnum int64 = 0
	//fmt.Println("filesize is ", filesize)
	var blocknum int64

	var blockbytebuffer bytes.Buffer
	//var blockbyte []byte
	var noncestring string
	if exists(evidencefilepath) {

		del := os.Remove(evidencefilepath)
		if del != nil {
			fmt.Println(del)
		}
	}

	if exists(evidencenouncefile) {

		del := os.Remove(evidencenouncefile)
		if del != nil {
			fmt.Println(del)
		}
	}

	filesize := GetFileSize(fileName)
	if (filesize * 8 / readbitlen) > 0 {
		blocknum = (filesize*8/readbitlen + 1)
	} else {
		blocknum = (filesize * 8 / readbitlen)
	}
	fmt.Println("blocknum is ", blocknum)
	//filename := getFileName(fileName)
	for readiter = 0; readiter < blocknum; readiter++ {
		//fmt.Println("readiter is ", readiter)
		retdata, _ := ReadBlock(fileName, readbitlen, readiter*readbitlen)
		//fmt.Println("retdata is ", retdata)
		if 0 == readiter {
			for tyrnum = 0; ; tyrnum++ {
				var trys string
				trys += identity
				trys += strconv.FormatInt(tyrnum, 10)
				//fmt.Println("trys is ",trys)
				//t1:=time.Now()
				calc_hash := GetSHA256HashCode([]byte(trys))
				//t2:=time.Now()
				//d:=t2.Sub(t1)
				//fmt.Println("calc_hash is ",calc_hash)
				var comparebyte []byte
				comparebyte, _ = hex.DecodeString(calc_hash)
				ret, _ := bitcompare(retdata, comparebyte, readbitlen)
				if ret {
					//fmt.Println("calc_hash is ", calc_hash)
					//fmt.Println("retdata is ", retdata)
					//fmt.Println("comparebyte is ", comparebyte)
					//fmt.Println("tyrnum is ", tyrnum)

					previoushash = calc_hash
					//blockbyte = blockbyte + comparebyte
					blockbytebuffer.Write(comparebyte)
					noncestring += strconv.FormatInt(tyrnum, 10)

					//WriteBlock(evidencefilepath, comparebyte)
					//WriteNounce(evidencenouncefile, strconv.FormatInt(tyrnum, 10))
					break
				}
			}
		} else {
			for tyrnum = 0; ; tyrnum++ {
				var trys string
				trys += identity
				trys += previoushash
				trys += strconv.FormatInt(tyrnum, 10)
				//fmt.Println("trys is ",trys)
				calc_hash := GetSHA256HashCode([]byte(trys))
				//fmt.Println("calc_hash is ",calc_hash)
				var comparebyte []byte
				comparebyte, _ = hex.DecodeString(calc_hash)
				ret, _ := bitcompare(retdata, comparebyte, readbitlen)
				if ret {
					//fmt.Println("trys is ",trys)
					//fmt.Println("tyrnum is ", tyrnum)
					//fmt.Println("retdata is ", retdata)
					//fmt.Println("comparebyte is ", comparebyte)
					previoushash = calc_hash
					blockbytebuffer.Write(comparebyte)
					noncestring += ","+strconv.FormatInt(tyrnum, 10)

					//WriteBlock(evidencefilepath, comparebyte)
					//WriteNounce(evidencenouncefile, ","+strconv.FormatInt(tyrnum, 10))
					break
				}
			}
		}
	}
	WriteBlock(evidencefilepath, blockbytebuffer.Bytes() )
	WriteNounce(evidencenouncefile, noncestring)


}

func NewMerkleTreeContainAllNodes(evidencepath string, ch string, evdencecachpath string) []MerkleNode {
	var nodes []MerkleNode
	//get evidencefile size
	evidencefilesize := GetFileSize(evidencepath)
	//calculate leaf nodes number
	nodenumber := evidencefilesize / 32
	//j stands for the first element of every level
	var i int64 = 0
	var j int64 = 0
	var k int64 = 0
	var keybyte []byte = []byte(ch)
	//nSize stands for the leaf number of every level. Half every cycle
	for nSize := nodenumber; nSize > 1; nSize = (nSize + 1) / 2 {
		//The second loop i+=2 represents pairwise splicing, and i2 is to copy the last element when the number is odd.
		for i = 0; i < nSize; i += 2 {
			i2 := min(i+1, nSize-1)
			if k <= 0 {
				readdata1, _ := ReadBlock(evidencepath, 256, i*256)
				readdata2, _ := ReadBlock(evidencepath, 256, i2*256)
				var node1 MerkleNode
				var node2 MerkleNode
				node1.Data = readdata1
				node2.Data = readdata2
				node := NewMerkleNode(&node1, &node2, keybyte, nil)
				WriteBlock(evdencecachpath, node.Data)
				k += 1
			} else {
				readdata1, _ := ReadBlock(evdencecachpath, 256, (j+i)*256)
				readdata2, _ := ReadBlock(evdencecachpath, 256, (j+i2)*256)
				var node1 MerkleNode
				var node2 MerkleNode
				node1.Data = readdata1
				node2.Data = readdata2
				node := NewMerkleNode(&node1, &node2, keybyte, nil)
				WriteBlock(evdencecachpath, node.Data)
				j += nSize
			}
		}
	}
	//mTree:=MerkleTree{&(nodes[len(nodes)-1])}

	//fmt.Println("len is ", len(nodes))

	return nodes
}

//Generate Merkel tree in memory
func NewMerkleTreeMemory(evidencepath string, ch string) *MerkleTree {
	var nodes []MerkleNode
	var key []byte = []byte(ch)
	var data [][]byte

	data, _ = ReadAllFileIntoMemmory(evidencepath)
	//fmt.Println("len(data) is ", len(data))
	//var nodenum int64 =int64( len(data))

	//Building leaf nodes
	for _, dataum := range data {
		node := NewMerkleNode(nil, nil, key, dataum)
		nodes = append(nodes, *node)
	}

	//j represents the first element of a layer
	var i int64 = 0
	var j int64 = 0
	var nSize int64

	//nSize represents the number of a certain layer, and each cycle is halved
	for nSize = int64(len(data)); nSize > 1; nSize = (nSize + 1) / 2 {
		for i = 0; i < nSize; i += 2 {
			i2 := min(i+1, nSize-1)
			node := NewMerkleNode(&nodes[j+i], &nodes[j+i2], key, nil)
			nodes = append(nodes, *node)
			//WriteBlock(evidencecachpath, node.Data)
		}
		//j represents the first element of a layer
		j += nSize
	}
	mTree := MerkleTree{&(nodes[len(nodes)-1])}
	fmt.Println("len is ", len(nodes))
	//GetNodePath(&mTree,nodenum)
	return &mTree
}

func ChunkString(s string, chunkSize int) []string {
	var chunks []string
	runes := []rune(s)

	if len(runes) == 0 {
		return []string{s}
	}

	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}

//Array de duplication
func RemoveRepeatedElement(arr []int64) (newArr []int64) {
	newArr = make([]int64, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return
}

func GetNodePath(filename string,evidencepath string,evidencenoucepath string, ch string,readbitlen int64) map[int64][]byte {
	var nodes []MerkleNode
	var key []byte = []byte(ch)
	var evidencedata [][]byte
	var evidencenouncedata []string
	//var filedigestbyte []byte

	//convert hashstring to byte[]
	//filedigestbyte, _ = hex.DecodeString(filedigest)
	//fmt.Println("filedigestbyte is ", filedigestbyte)

	//Read the. blocks file into memory and cut it into an array of 32byte
	evidencedata, _ = ReadAllFileIntoMemmory(evidencepath)
	fmt.Println("len(data) is ", len(evidencedata))
	//Read the .nouce file into memory and read it into an array
	evidencenouncedata,_ = ReadAllNouceIntoMemmory(evidencenoucepath)
	//fmt.Println("evidencenouncedata is ", evidencenouncedata)
	fmt.Println("len(evidencenouncedata) is ", len(evidencenouncedata))
	t1:=time.Now() //Get local current time


	//The number of leaf nodes in Merkel tree
	var nodenum int64 = int64(len(evidencedata))

	var filenodehashbyte []byte = filenodehash(filename,ch,nodenum,readbitlen)

	//Building leaf nodes
	var nodenumiter int64 = 0
	fmt.Println("nodenum: ",nodenum)
	for _, dataum := range evidencedata {
		//Convert random number to eight byte []
		nouceint,err := strconv.ParseInt(evidencenouncedata[nodenumiter], 10, 64)
		if err != nil {
			fmt.Println("err: ",err)
		}
		//fmt.Println("nouceint: ",nouceint)
		var buf = make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(nouceint))
		//fmt.Println("buf is ", buf)
		//fmt.Println("dataum is ", dataum)
		//The leaf node is head||tail||nounce||filedigest
		for _,nounceum := range buf{
			dataum=append(dataum,nounceum)
			//dataum = append(dataum,filedigestbyte)
		}
		for _,filenodehashbytenum := range filenodehashbyte{
			dataum=append(dataum,filenodehashbytenum)
			//dataum = append(dataum,filedigestbyte)
		}


		//for _,filedigestum := range filedigestbyte{
		//	dataum=append(dataum,filedigestum)
		//}
		//fmt.Println("leaf nodes are ", nodenumiter)
		//fmt.Println("dataum is ", dataum)
		node := NewMerkleNode(nil, nil, key, dataum)
		nodes = append(nodes, *node)
		nodenumiter++
	}

	//Build nodes other than leaf nodes. j represents the first element of a layer
	var i int64 = 0
	var j int64 = 0
	var nSize int64
	//The first layer represents the cycle, nSize represents the number of a certain layer, and each cycle is halved
	for nSize = int64(len(evidencedata)); nSize > 1; nSize = (nSize + 1) / 2 {

		//The second loop i+=2 represents pairwise splicing, and i2 is to copy the last element when the number is odd
		for i = 0; i < nSize; i += 2 {
			i2 := min(i+1, nSize-1)
			node := NewMerkleNode(&nodes[j+i], &nodes[j+i2], key, nil)
			nodes = append(nodes, *node)
			//WriteBlock(evidencecachpath, node.Data)
		}

		//j represents the first element of a layer
		j += nSize
	}
	mTree := MerkleTree{&(nodes[len(nodes)-1])}
	fmt.Println("len nodes is ", len(nodes))
	fmt.Println("Time to generate Merkle tree: ", time.Since(t1))
	//var data [][]byte
	var rootnode MerkleNode = *mTree.RootNode
	//Convert the root node of Merkel tree to 01 string
	var rootnodestring string = biu.ToBinaryString(rootnode.Data)
	//Remove all "["
	rootnodestring = strings.Replace(rootnodestring, "[", "", -1)
	//Remove all "]"
	rootnodestring = strings.Replace(rootnodestring, "]", "", -1)
	//Remove all space
	rootnodestring = strings.Replace(rootnodestring, " ", "", -1)

	//fmt.Println("rootnodestring is ", rootnodestring)
	var bittosting string = biu.ToBinaryString(nodenum)

	bittosting = strings.Replace(bittosting, "[", "", -1)
	bittosting = strings.Replace(bittosting, "]", "", -1)
	bittosting = strings.Replace(bittosting, " ", "", -1)
	var stringlen = len(bittosting)
	fmt.Println("nodenum is ", bittosting)
	fmt.Println("stringlen is ", stringlen)
	var stringiter int = 0
	//Zerolen is the zerolen bit when calculating the number of leaf nodes in binary representation
	var zerolen int = 0
	for stringiter = 0; stringiter < stringlen; stringiter++ {
		if '0' != bittosting[stringiter] {
			//zerolen = stringiter + 1
			zerolen = stringiter
			break
		}
	}

	//fmt.Println("zerolen is ", zerolen)

	var eachlen uintptr = ((unsafe.Sizeof(nodenum) * 8) - uintptr(zerolen))
	//fmt.Println("eachlen is ", eachlen)

	var nodeposition []int64
	var chunkarray []string = ChunkString(rootnodestring, int(eachlen))
	//fmt.Println("chunkarray is ", chunkarray)
	var bititer int = 0
	for bititer = 0; bititer < len(chunkarray); bititer++ {
		var tmpint int64 = 0
		var partiter int = 0
		for partiter = 0; partiter < len(chunkarray[bititer]); partiter++ {
			tmpint = (tmpint << 1)
			if '1' == chunkarray[bititer][partiter] {
				tmpint = (tmpint) ^ 1
			}
			if tmpint >= nodenum {
				tmpint = tmpint % nodenum
			}

		}
		nodeposition = append(nodeposition, tmpint)
	}

	//fmt.Println("nodeposition is ", nodeposition)
	nodeposition = RemoveRepeatedElement(nodeposition)
	fmt.Println("nodeposition is ", nodeposition)


	var routenodenum [][]int64
	var firstrownodenum []int64
	var nodeiter int64 = 0
	for nodeiter = 0; nodeiter < int64(len(nodeposition)); nodeiter++ {
		var value int64 = nodeposition[nodeiter]
		if 0 == value%2 {
			firstrownodenum = append(firstrownodenum, value)
			if value < nodenum {
				if value == nodenum - 1{
					firstrownodenum = append(firstrownodenum, value)
				}else{
					firstrownodenum = append(firstrownodenum, value+1)
				}
				if 0 != value {
					firstrownodenum = append(firstrownodenum, value-1)
					firstrownodenum = append(firstrownodenum, value-2)
				}
			}

		} else {
			firstrownodenum = append(firstrownodenum, value)
			firstrownodenum = append(firstrownodenum, value-1)
		}
	}
	routenodenum = append(routenodenum, RemoveRepeatedElement(firstrownodenum))

	var routenSize int64 = 0
	var routej int64 = 0
	var mapiter int64 = 0
	for routenSize = int64(len(evidencedata)); routenSize > 1; routenSize = (routenSize + 1) / 2 {
		var previousarray []int64 = routenodenum[mapiter]
		var previousarrayiter int64 = 0
		var tmproutenum []int64

		for previousarrayiter = 0; previousarrayiter < int64(len(previousarray)); previousarrayiter++ {
			var rowvalue int64 = previousarray[previousarrayiter] / 2
			if 0 == rowvalue%2 {
				//fmt.Println("routenSize is ",routenSize,",rowvalue is", rowvalue,",(routenSize+1)/2-1 is",(routenSize+1)/2-1)
				if rowvalue >= (routenSize+1)/2-1 {
					tmproutenum = append(tmproutenum, rowvalue)
				}else {
					tmproutenum = append(tmproutenum, rowvalue+1)
				}
			} else {
				tmproutenum = append(tmproutenum, rowvalue-1)
			}
		}

		mapiter++
		routej += routenSize
		routenodenum = append(routenodenum, RemoveRepeatedElement(tmproutenum))
	}
	//fmt.Println("routenodenum len is ", len(routenodenum), " routenodenum is ", routenodenum)
	var routeniter int64 = 0
	var arraynum int64 = 0
	var accumulatednumber int64 = 0
	for routeniter = int64(len(evidencedata)); routeniter > 1; routeniter = (routeniter + 1) / 2 {
		var arrayiter int64 = 0
		for arrayiter = 0; arrayiter < int64(len(routenodenum[arraynum])); arrayiter++ {
			routenodenum[arraynum][arrayiter] = routenodenum[arraynum][arrayiter]+accumulatednumber
		}
		arraynum++
		accumulatednumber = accumulatednumber + routeniter
	}
	routenodenum[arraynum][0] = routenodenum[arraynum][0]+accumulatednumber
	//fmt.Println("routenodenum len is ", len(routenodenum), " routenodenum is ", routenodenum)

	var node map[int64][]byte
	node = make(map[int64][]byte)

	var nodelayiter int = 0
	var nodeeiter int = 0
	for nodelayiter = 0; nodelayiter < len(routenodenum); nodelayiter++{
		for nodeeiter = 0; nodeeiter < len(routenodenum[nodelayiter]); nodeeiter++{
			var num = routenodenum[nodelayiter][nodeeiter]
			node [num] = nodes[num].Data
		}
	}
	//fmt.Println("node is ",node)
	fmt.Println("Time to generate the path of the selected leaf node ", time.Since(t1))
	return node
}


//According to ch and the number of  leaf nodes to select the file hash value of some nodes
func filenodehash(filename string,ch string,nodenum int64,readbitlen int64) []byte{
	//H(ch)is parsed into k indexes.
	//Calculate the hash value HCH of ch
	var Hch string = GetSHA256HashCodeString(ch)
	var Hchbyte, _ = hex.DecodeString(Hch)
	//Hch,_ := hex.DecodeString(ch)
	fmt.Println("Hch is ", Hch)
	fmt.Println("Hchbyte is ", Hchbyte)
	//Convert Hch to 01 string
	var Hchstring string = biu.ToBinaryString(Hchbyte)
	//remove all "["
	Hchstring = strings.Replace(Hchstring, "[", "", -1)
	//remove all "]"
	Hchstring = strings.Replace(Hchstring, "]", "", -1)
	//remove all space
	Hchstring = strings.Replace(Hchstring, " ", "", -1)
	fmt.Println("Hchstring is ", Hchstring)
	//convert nodenum to 01
	var bittosting string = biu.ToBinaryString(nodenum)

	bittosting = strings.Replace(bittosting, "[", "", -1)
	bittosting = strings.Replace(bittosting, "]", "", -1)
	bittosting = strings.Replace(bittosting, " ", "", -1)
	var stringlen = len(bittosting)

	fmt.Println("nodenum is ", bittosting)
	fmt.Println("stringlen is ", stringlen)

	var stringiter int = 0
	var zerolen int = 0
	for stringiter = 0; stringiter < stringlen; stringiter++ {
		if '0' != bittosting[stringiter] {
			//zerolen = stringiter + 1
			zerolen = stringiter
			break
		}
	}

	fmt.Println("zerolen is ", zerolen)



	//The calculation requires eachlen bits to represent the total number of leaf nodes.
	//For example, if the number of leaf nodes is 245441, 17 bits are needed to represent it
	var eachlen uintptr = ((unsafe.Sizeof(nodenum) * 8) - uintptr(zerolen))
	fmt.Println("eachlen is ", eachlen)



	//由Hchstring切割得到原文件序号
	var fileposition []int64
	//将Hchstring的bit字符串按每eachlen一份进行切割，生成[]string
	var Hcharray []string = ChunkString(Hchstring, int(eachlen))
	//fmt.Println("chunkarray is ", chunkarray)
	var filebititer int = 0
	for filebititer = 0; filebititer < len(Hcharray); filebititer++ {
		var tmpint int64 = 0
		var partiter int = 0
		for partiter = 0; partiter < len(Hcharray[filebititer]); partiter++ {
			tmpint = (tmpint << 1)
			if '1' == Hcharray[filebititer][partiter] {
				tmpint = (tmpint) ^ 1
			}
			if tmpint >= nodenum {
				tmpint = tmpint % nodenum
			}

		}
		fileposition = append(fileposition, tmpint)
	}

	fmt.Println("fileposition is ", fileposition)
	fileposition = RemoveRepeatedElement(fileposition)
	fmt.Println("fileposition is ", fileposition)
	var fileretdata []byte
	//retdata, _ := ReadBlock(filename, readbitlen, 0*readbitlen)
	//fmt.Println("000000000000retdata is ", retdata)
	var readiter int
	for readiter = 0; readiter < len(fileposition); readiter++ {
		//fmt.Println("readiter is ", readiter)
		//fmt.Println("now fileposition is ", fileposition[readiter])
		retdata, _ := ReadBlock(filename, readbitlen, (fileposition[readiter])*readbitlen)
		//fmt.Println("retdata is ", retdata)
		for _,nounceum := range retdata{
			fileretdata=append(fileretdata,nounceum)
		}

	}
	fmt.Println("fileretdata is ", fileretdata)
	fileretdata_hash := GetSHA256HashCode([]byte(fileretdata))

	var filebyte_hash []byte
	filebyte_hash, _ = hex.DecodeString(fileretdata_hash)
	fmt.Println("filebyte_hash is ", filebyte_hash)
	return filebyte_hash

}
//Verify according to the value of the received node
//The first parameter is the serial number and value of the node sent by the prover, the second parameter is the local file path, the third parameter is the personal ID, the fourth parameter is the bit length of each read, and the fifth parameter is the sending time
//This function returns the validation result
func Verify(node map[int64][]byte, filename string,identity string, readbitlen int64,ch string) string {
	fmt.Println("Start validation")
	t1:=time.Now()


	var leafnodenum int64
	var nodenum int64
	filesize := GetFileSize(filename)
	if (filesize * 8 / readbitlen) > 0 {
		leafnodenum = (filesize*8/readbitlen + 1)
	} else {
		leafnodenum = (filesize * 8 / readbitlen)
	}
	fmt.Println("leafnodenum is ", leafnodenum)
	nodenum = Calcnodenumber(leafnodenum)
	fmt.Println("nodenum is ", nodenum)

	rootnodevalue, ok := node [ nodenum-1 ]
	if (ok) {
		fmt.Println("rootnodevalue is ", rootnodevalue)
	} else {
		fmt.Println("rootnodevalue not exist")
		var result = "Root node does not exist, validation failed"
		return result
	}
	var rootnodestring string = biu.ToBinaryString(rootnodevalue)

	rootnodestring = strings.Replace(rootnodestring, "[", "", -1)

	rootnodestring = strings.Replace(rootnodestring, "]", "", -1)

	rootnodestring = strings.Replace(rootnodestring, " ", "", -1)
	//fmt.Println("rootnodestring is ", rootnodestring)

	var bittosting string = biu.ToBinaryString(leafnodenum)

	bittosting = strings.Replace(bittosting, "[", "", -1)
	bittosting = strings.Replace(bittosting, "]", "", -1)
	bittosting = strings.Replace(bittosting, " ", "", -1)
	var stringlen = len(bittosting)
	//fmt.Println("leafnodenum is ", bittosting)
	//fmt.Println("stringlen is ", stringlen)
	var stringiter int = 0
	var zerolen int = 0
	for stringiter = 0; stringiter < stringlen; stringiter++ {
		if '0' != bittosting[stringiter] {
			//zerolen = stringiter + 1
			zerolen = stringiter
			break
		}
	}
	var eachlen uintptr = ((unsafe.Sizeof(leafnodenum) * 8) - uintptr(zerolen))
	//fmt.Println("eachlen is ", eachlen)

	var nodeposition []int64

	var chunkarray []string = ChunkString(rootnodestring, int(eachlen))
	//fmt.Println("chunkarray is ", chunkarray)
	var bititer int = 0
	for bititer = 0; bititer < len(chunkarray); bititer++ {
		var tmpint int64 = 0
		var partiter int = 0
		for partiter = 0; partiter < len(chunkarray[bititer]); partiter++ {
			tmpint = (tmpint << 1)
			if '1' == chunkarray[bititer][partiter] {
				tmpint = (tmpint) ^ 1
			}
			if tmpint >= leafnodenum {
				tmpint = tmpint % leafnodenum
			}

		}
		nodeposition = append(nodeposition, tmpint)
	}
	//fmt.Println("nodeposition is ", nodeposition)
	nodeposition = RemoveRepeatedElement(nodeposition)
	fmt.Println("Leaf node to be verified is ", nodeposition)


	//1. Verify that the head value of the leaf node is consistent with the head value of the file stored locally

	var headiter int
	fmt.Println("len(nodeposition) is ", len(nodeposition))

	//fmt.Println("verifyfile is ", verifyfile)
	for headiter = 0; headiter < len(nodeposition); headiter++ {

		//var nodenumber int64
		//nodenumber = nodeposition[headiter]
		//fmt.Println(nodenumber,"验证与本地文件是否相同的节点 ", nodeposition[headiter])
		//fmt.Println("node[nodeposition[headiter]] is ", node[nodeposition[headiter]])
		var verifyfile []byte
		verifyfile,_ = ReadBlock(filename,readbitlen,readbitlen*nodeposition[headiter])
		//fmt.Println("verifyfile is ", verifyfile)
		if(verifyfile != nil){
			//fmt.Println("verifyfile is ", verifyfile)
		}else {
			fmt.Println("verifyfile is nil")
			return "fail"
		}
		if(node[nodeposition[headiter]] != nil){
			//fmt.Println("node[nodeposition[headiter]] is ", node[nodeposition[headiter]])
		}else {
			return "fail"
		}
		ret, _ := bitcompare(verifyfile, node[nodeposition[headiter]], readbitlen)
		if(ret){

			//fmt.Println("与本地文件相同节点：", nodeposition[headiter])
		}else {
			fmt.Println("Verification failed node:",nodeposition[headiter])
			return "The node is incorrect and the verification is unsuccessful"
		}
	}
	fmt.Println("1.The head value of the node is the same as that of the local file")



	//2，Verify whether hash(id||previoushash||nonce) is consistent with head||tail

	var nodeiter int
	//var nodevalue []byte
	//var previousnode []byte
	for nodeiter = 0; nodeiter < len(nodeposition); nodeiter++{

		nodevalue, ok := node [ nodeposition[nodeiter] ]
		if (ok) {
			//fmt.Println("nodevalue is ", nodevalue)
		} else {
			fmt.Println("not exist node:",nodeposition[nodeiter])
			var result = "Node does not exist, validation failed"
			return result
		}
		if(nodeposition[nodeiter] ==0){
			var trys string
			var noucevalue int64
			trys += identity

			noucevalue = calnoucevalue(nodevalue)
			//identity||nouce
			trys += strconv.FormatInt(noucevalue, 10)
			//计算hash
			calc_hash := GetSHA256HashCode([]byte(trys))

			var comparebyte []byte
			comparebyte, _ = hex.DecodeString(calc_hash)
			ret, _ := bitcompare(nodevalue, comparebyte, 32*8)
			if ret {
				//fmt.Println("nodevalue is ", nodevalue)
				//fmt.Println("comparebyte is ", comparebyte)
				//fmt.Println("Verification success node ", nodeposition[nodeiter])

			}else{
				fmt.Println("Verification failed node:",nodeposition[nodeiter])
				var result = "The node is incorrect and the verification is unsuccessful"
				return result
			}
		}else{
			//fmt.Println("previousnode is ", nodeposition[nodeiter]-1)
			previousnode, ok := node [ nodeposition[nodeiter]-1 ]
			if (ok) {
				//fmt.Println("previousnode is ", nodeposition[nodeiter]-1)
				//fmt.Println("previousnodevalue is ", previousnode)
				var trys string
				var previoushash string
				var noucevalue int64
				var previousnodehead []byte
				previousnodehead = make([]byte,32)
				copy(previousnodehead,previousnode)
				//fmt.Println("previousnodehead is ", previousnodehead)
				trys += identity
				previoushash = hex.EncodeToString(previousnodehead)
				trys += previoushash
				noucevalue = calnoucevalue(nodevalue)
				//identity||previouse||nonce
				trys += strconv.FormatInt(noucevalue, 10)
				//计算hash
				calc_hash := GetSHA256HashCode([]byte(trys))

				var comparebyte []byte
				comparebyte, _ = hex.DecodeString(calc_hash)
				//fmt.Println("comparebyte is ", comparebyte)
				ret, _ := bitcompare(nodevalue, comparebyte, 32)
				if ret {
					//fmt.Println("nodevalue is ", nodevalue)
					//fmt.Println("comparebyte is ", comparebyte)


				}else{
					fmt.Println("previousnode:",nodeposition[nodeiter])
					var result = "The node is incorrect and the verification is unsuccessful"
					return result
				}

			} else {
				fmt.Println("not exist previousnode:",nodeposition[nodeiter])
				var result = "The node is incorrect and the verification is unsuccessful"
				return result
			}
		}
	}
	fmt.Println("2.hash（id||previoushash||nonce) head||tail is same")



	var rownum []int64
	var nSize int64
	var allnodenum int64 = 0
	var key []byte = []byte(ch)
	for nSize = leafnodenum; nSize > 1; nSize = (nSize + 1) / 2 {
		allnodenum = nSize + allnodenum
		rownum = append(rownum, allnodenum)
	}
	rownum = append(rownum,allnodenum+1)
	fmt.Println("Layers of Merkel tree:",len(rownum))

	var nodenumiter int64 = 0
	for nodenumiter = 0; nodenumiter < int64(len(nodeposition)); nodenumiter++ {

		var nodepath []int64
		nodepath = append(nodepath, nodeposition[nodenumiter])
		var i int
		var childnode int64
		var nodenumber int64 = nodeposition[nodenumiter]
		var nodevalue []byte
		for i=1; i<len(rownum);i++{
			if(i == 1){
				childnode = nodeposition[nodenumiter]
			}else{
				childnode = childnode/2
			}

			var verifynodevalue []byte
			if(i == 1){
				if Oddornot(childnode) {
					leftnodevalue, ok := node[nodenumber-1]
					if (!ok) {
						return "The node does not exist"
					}
					rightnodevalue, ok := node[nodenumber]
					if (!ok) {
						return "The node does not exist"
					}

					verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)

				} else{
					if(nodenumber == rownum[0]-1){
						leftnodevalue, ok := node[nodenumber]
						if (!ok) {
							return "The node does not exist"
						}
						rightnodevalue:= node[nodenumber]
						verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)
					}else{
						leftnodevalue, ok := node[nodenumber]
						if (!ok) {
							return "The node does not exist"
						}
						rightnodevalue, ok := node[nodenumber+1]
						if (!ok) {
							return "The node does not exist"
						}
						verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)
					}
				}
			}else{
				if Oddornot(childnode) {
					leftnodevalue, ok := node[nodenumber-1]
					if (!ok) {
						return "The node does not exist"
					}
					rightnodevalue := nodevalue
					verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)
				} else{
					if(nodenumber == rownum[i-1]-1){
						leftnodevalue := nodevalue;
						rightnodevalue := nodevalue
						verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)
					}else{
						leftnodevalue := nodevalue;
						rightnodevalue, ok := node[nodenumber+1]
						if (!ok) {
							return "The node does not exist"
						}
						verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)
					}
				}

			}
			nodevalue = verifynodevalue
			if(i == len(rownum)-1) {
				//Calculate to root node
				//fmt.Println("root node:",node[rownum[i]-1])
				//fmt.Println("nodevalue",nodevalue)
				ret, _ := bitcompare(nodevalue, node[rownum[i]-1], 32*8)
				if (ret) {
				} else {
					return "Verification failed, wrong path"
				}
			}
			//j represents the number of the node in the layer
			var j int64
			j = childnode / 2
			//nodenumber is the number of the node in the Merkel tree
			nodenumber = rownum[i-1]+j
			nodepath = append(nodepath, nodenumber)
		}
	}
	fmt.Println("3.Node path validation successful")

	elapsed := time.Since(t1)
	fmt.Println("verification consumption time =", elapsed)
	var result = "verify success"
	return result
}

func CalMerkleNodeValue(leftnodevalue []byte,rightnodevalue []byte,key []byte) []byte{
	var nodevalue []byte
	prevhashes := append(leftnodevalue,rightnodevalue...)
	//calculate hmac_sha256
	h := hmac.New(sha256.New, key)
	h.Write(prevhashes)
	nodevalue = h.Sum(nil)
	return nodevalue
}

func calnoucevalue(nodevalue []byte) int64 {
	var nouncestring string
	var nouncebyte []byte
	var i int
	for i=32;i<40;i++{
		nouncebyte = append(nouncebyte, nodevalue[i])
	}
	//fmt.Println("nouncebyte:",nouncebyte)
	nouncestring = hex.EncodeToString(nouncebyte)
	//fmt.Println("nouncestring:",nouncestring)
	s, err := strconv.ParseInt(nouncestring, 16, 64)
	if err != nil {
		panic(err)
	}
	//fmt.Println("nouncestring:",s)


	return s
}

func calcparentroutenodenum(routenSize int64, nodearray []int64) []int64 {
	var tmpint []int64
	for _, value := range nodearray {
		var parentnodenum int64 = value / 2
		tmpint = append(tmpint, parentnodenum)
	}
	return tmpint
}

//Oddornot
func Oddornot(input int64) bool {
	if 1 == (input & 1) {
		return true
	} else {
		return false
	}
}

func Calcnodenumber(n int64) int64 {
	var m int64 = 0
	//n is the number of leaf nodes, m is the number of Merkel tree nodes
	m = m + n
	for ; n > 1; {
		if Oddornot(n) {
			n = (n + 1) / 2
			m = m + n
		} else {
			n = n / 2
			m = m + n
		}
	}
	return m
}


//The first parameter is the serial number of the lowest leaf node selected
//the second parameter is the number of the lowest leaf nodes
//the third parameter is the path of the generated certificate file
//the fourth parameter is the path of the certificate cache file generated according to Ch
func CalcRoute(m []int64, nodenum int64,
	evidencepath string, evidencecachpath string) map[int64]string {

	//Given the leaf node serial number, return the path from leaf node to heel node
	scene := make(map[int64]string)
	for _, data := range m {
		var number int64
		if data > nodenum {
			number := data % nodenum
			fmt.Println("remainder is ", number)
		} else {
			number = data
		}
		for ; number > 1; {
			if Oddornot(number) {
				//(number+1)/2

			} else {

			}
		}
		//scene[data] = "route"
	}
	return scene
}
