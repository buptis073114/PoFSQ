package proverProofPhase

import (
	"../lib"
	"fmt"
)

func testevidencecachfile(evidencefile string, evidencecachfile string, ch string) {
	lib.NewMerkleTreeContainAllNodes(evidencefile, ch, evidencecachfile)
	//NewMerkleTreeMemory(evidencefileName, ch)
}

func generateProofResponce(evidencefile string, ch string) {

	lib.NewMerkleTreeMemory(evidencefile, ch)
}


func GenerateMerkleTree(fileName string,readbitlen int64,identity string, ch string)(map[int64][]byte){
	// When receiving challenge ch, generate Merkle tree.
	evidencefileName := fileName + ".blocks"
	//node needs nouce
	evidencenouncefile := fileName + ".nounce"
	//node needs filedigest
	var filedigest string
	filedigest = lib.GetSHA256HashCodeFile(fileName)
	fmt.Println(fileName+"file hash is ", filedigest)
	//node is [head||tail||nouce||filedigest]

	generateProofResponce(evidencefileName, ch)
	var node map[int64][]byte
	node = lib.GetNodePath(fileName, evidencefileName, evidencenouncefile, ch, readbitlen)
	//fmt.Println("Information transmitted is ", node)

	//unsafe.Sizeof(hmap) + (len(theMap) * 8) + (len(theMap) * 8 * unsafe.Sizeof(x)) + (len(theMap) * 8 * unsafe.Sizeof(y))
	//fmt.Println("Size of information transmitted is ", unsafe.Sizeof(node))

	return node

}