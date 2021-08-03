package verifierProofPhase

import "fmt"
import "../lib"

func Verify(node map[int64][]byte,fileName string,identity string,readbitlen int64,ch string)(string){
	var verifyresult string
	verifyresult = lib.Verify(node,fileName,identity,readbitlen,ch)
	fmt.Println("verifyresult is ", verifyresult)
	return verifyresult
}