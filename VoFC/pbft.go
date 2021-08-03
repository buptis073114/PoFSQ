package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
	"../lib"
	"../proverProofPhase"
	"../verifierProofPhase"
)


var  nodepath map[int64][]byte
var identity string
var ch string = "12345678901234567890123456789014"
var filename string ="5K"
var readbitlen int64=10


//Local message pool (simulating persistence layer), which will be saved only after the successful submission is confirmed
var localMessagePool = []Message{}

type node struct {
	//node ID
	nodeID string
	//listenning address
	addr string
	//RSA private key
	rsaPrivKey []byte
	//RSA public key
	rsaPubKey []byte
}

type pbft struct {
	//nodes information
	node node
	//The serial number of each request
	sequenceID int
	//lock
	lock sync.Mutex
	//Temporary message pool
	messagePool map[string]Request
	//Store the number of received prepare message (at least 2f must be received and confirmed)
	prePareConfirmCount map[string]map[string]bool
	//Store the number of received commits message(at least 2f + 1 must be received and confirmed)
	commitConfirmCount map[string]map[string]bool
	//Whether the Commit message has been broadcast
	isCommitBordcast map[string]bool
	//Whether the reply message been send to client
	isReply map[string]bool
}

func NewPBFT(nodeID, addr string) *pbft {
	p := new(pbft)
	p.node.nodeID = nodeID
	p.node.addr = addr
	p.node.rsaPrivKey = p.getPivKey(nodeID) //Read from generated private key file
	p.node.rsaPubKey = p.getPubKey(nodeID)  //Read from generated public key file
	p.sequenceID = 0
	p.messagePool = make(map[string]Request)
	p.prePareConfirmCount = make(map[string]map[string]bool)
	p.commitConfirmCount = make(map[string]map[string]bool)
	p.isCommitBordcast = make(map[string]bool)
	p.isReply = make(map[string]bool)
	return p
}

func (p *pbft) handleRequest(data []byte) {
	//Cut the message and call different functions according to the message command
	cmd, content := splitMessage(data)
	switch command(cmd) {
	case cRequest:
		p.handleClientRequest(content)
	case cPrePrepare:
		p.handlePrePrepare(content)
	case cPrepare:
		p.handlePrepare(content)
	case cCommit:
		p.handleCommit(content)
	}
}

//Processing requests from clients
func (p *pbft) handleClientRequest(content []byte) {
	fmt.Println("The node has received the request from the client...")
	//Parsing the request structure using JSON
	var ch string = "12345678901234567890123456789014"
	r := new(Request)
	err := json.Unmarshal(content, r)
	if err != nil {
		log.Panic(err)
	}
	//Add information serial number
	p.sequenceIDAdd()
	//Get message digest
	digest := getDigest(*r)
	fmt.Println("The request has been saved to the temporary message pool")
	//saved to the temporary message pool
	p.messagePool[digest] = *r
	//node sign the message digest
	digestByte, _ := hex.DecodeString(digest)
	signInfo := p.RsaSignWithSha256(digestByte, p.node.rsaPrivKey)
	//Splice it into prepare and send it to the follower node
	pp := PrePrepare{*r, digest,
		ch,p.sequenceID, signInfo}
	b, err := json.Marshal(pp)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("Preparing PrePrepare broadcast to other nodes...")
	//Preparing PrePrepare broadcast
	p.broadcast(cPrePrepare, b)
	fmt.Println("PrePrepare broadcast over")
}

//Processing pre-prepared messages
func (p *pbft) handlePrePrepare(content []byte) {
	fmt.Println("This node has received the PrePrepare message from the master node...")
	//Parse the PrePrepare structure with JSON

	pp := new(PrePrepare)
	err := json.Unmarshal(content, pp)
	if err != nil {
		log.Panic(err)
	}
	//Obtain the public key of the master node for digital signature verification
	primaryNodePubKey := p.getPubKey("N0")
	digestByte, _ := hex.DecodeString(pp.Digest)
	if digest := getDigest(pp.RequestMessage); digest != pp.Digest {
		fmt.Println("Message digest is not correct. Prepare broadcast is rejected")
	} else if p.sequenceID+1 != pp.SequenceID {
		fmt.Println("The message sequence number is not matched, and the prepare broadcast is rejected")
	} else if !p.RsaVerySignWithSha256(digestByte, pp.Sign, primaryNodePubKey) {
		fmt.Println("The signature verification of the master node failed. Prepare broadcast is rejected")
	} else {
		//ch:= pp.ch
		publicKey := lib.GetECCPublicKeyByte("eccpublic.pem")
		identity = lib.GetSHA256HashCode(publicKey)
		fmt.Println("user identity is ", identity)
		//var ch string = "12345678901234567890123456789014"
		filename:="5K"
		var readbitlen int64=10
		nodepath := proverProofPhase.GenerateMerkleTree(filename,readbitlen,identity,ch)
		fmt.Println(nodepath)
		//Serial number assignment
		p.sequenceID = pp.SequenceID
		//Storing information in temporary message pool
		fmt.Println("Message saved to temporary node pool")
		p.messagePool[pp.Digest] = pp.RequestMessage
		//Nodes sign message with private keys
		sign := p.RsaSignWithSha256(digestByte, p.node.rsaPrivKey)
		//Splicing into Prepare
		//ch1:="45678901234567890141234567890123"
		pre := Prepare{pp.Digest, pp.SequenceID,
			p.node.nodeID, ch,sign}
		fmt.Println("pre is ",pre)

		bPre, err := json.Marshal(pre)
		if err != nil {
			log.Panic(err)
		}
		//Broadcast in the preparation stage
		fmt.Println("Prepare broadcast in progress...")
		fmt.Println("bPre is "+string(bPre))
		p.broadcast(cPrepare, bPre)
		fmt.Println("Prepare broadcast complete")
	}
}

//Processing Prepare message
func (p *pbft) handlePrepare(content []byte) {
	//Parse the prepare structure with JSON
	pre := new(Prepare)
	err := json.Unmarshal(content, pre)
	if err != nil {
		log.Panic(err)
	}
	fmt.Printf("This node has received the Prepare from %s node... \n", pre.NodeID)

	//fmt.Println("pre is ",pre)
	publicKey := lib.GetECCPublicKeyByte("eccpublic.pem")
	identity = lib.GetSHA256HashCode(publicKey)
	fmt.Println("user identity is ", identity)
	//var ch string = "12345678901234567890123456789014"
	filename:="5K"
	var readbitlen int64=10

	//ch1:=pre.ch1
	//nodepath = pre.nodepath
	fmt.Println("nodepath length is ", len(nodepath))
	var ch string = "12345678901234567890123456789014"
	var result string= verifierProofPhase.Verify(nodepath,filename,identity,readbitlen,ch)

	//Obtain the public key of the message source node for digital signature verification
	MessageNodePubKey := p.getPubKey(pre.NodeID)
	digestByte, _ := hex.DecodeString(pre.Digest)
	if (!strings.EqualFold(result,"verify success")){
		fmt.Println("prepare phase, nodepath verify failed. Commit broadcast is rejected")
	}else if _, ok := p.messagePool[pre.Digest]; !ok {
		fmt.Println("The current temporary message pool does not have this digest. Commit broadcast is rejected")
	} else if p.sequenceID != pre.SequenceID {
		fmt.Println("The serial number of the message does not match. The commit broadcast is refused")
	} else if !p.RsaVerySignWithSha256(digestByte, pre.Sign, MessageNodePubKey) {
		fmt.Println("Node signature verification failed, refuse to execute commit broadcast")
	} else {
		nodepath := proverProofPhase.GenerateMerkleTree(filename,readbitlen,identity,ch)
		p.setPrePareConfirmMap(pre.Digest, pre.NodeID, true)
		count := 0
		for range p.prePareConfirmCount[pre.Digest] {
			count++
		}
		//Because the master node does not send prepare message, it does not include itself
		specifiedCount := 0
		if p.node.nodeID == "N0" {
			specifiedCount = nodeCount / 3 * 2
		} else {
			specifiedCount = (nodeCount / 3 * 2) - 1
		}
		//If the node has received at least 2f prepare messages (including its own)
		//and has not carried out a commit broadcast
		//it will carry out a commit broadcast
		p.lock.Lock()
		//Obtain the public key of the message source node for digital signature verification
		if count >= specifiedCount && !p.isCommitBordcast[pre.Digest] {
			fmt.Println("The node has received prepare information from at least 2f nodes (including local nodes) ...")
			//The node signs it with a private key
			sign := p.RsaSignWithSha256(digestByte, p.node.rsaPrivKey)
			c := Commit{pre.Digest, pre.SequenceID,
				p.node.nodeID, nodepath,result,sign}
			bc, err := json.Marshal(c)
			if err != nil {
				log.Panic(err)
			}
			//Broadcast information submitted
			fmt.Println("Commit broadcast in progress")
			p.broadcast(cCommit, bc)
			p.isCommitBordcast[pre.Digest] = true
			fmt.Println("commit broadcast complete")
		}
		p.lock.Unlock()
	}
}

//Process submit confirmation message
func (p *pbft) handleCommit(content []byte) {

	//Using JSON to parse the commit structure
	c := new(Commit)
	err := json.Unmarshal(content, c)
	if err != nil {
		log.Panic(err)
	}
	fmt.Printf("This node has received the commit from %s nodes... \n", c.NodeID)
	//Obtain the public key of the message source node for digital signature verification
	MessageNodePubKey := p.getPubKey(c.NodeID)
	digestByte, _ := hex.DecodeString(c.Digest)

	//ch1:="45678901234567890141234567890123"
	nodepath:=c.nodepath
	var result string = verifierProofPhase.Verify(nodepath,filename,identity,readbitlen,ch)


	if (!strings.EqualFold(result,"verify success")){
		fmt.Println("commit phase, nodepath verify failed. Commit broadcast is rejected")
	}else if _, ok := p.prePareConfirmCount[c.Digest]; !ok {
		fmt.Println("The current prepare pool does not have this digest and refuses to persist information to the local message pool")
	} else if p.sequenceID != c.SequenceID {
		fmt.Println("Message number cannot be matched, message persistence to local message pool is refused")
	} else if !p.RsaVerySignWithSha256(digestByte, c.Sign, MessageNodePubKey) {
		fmt.Println("Node signature verification failed, refusing to persist information to the local message pool")
	} else {
		p.setCommitConfirmMap(c.Digest, c.NodeID, true)
		count := 0
		for range p.commitConfirmCount[c.Digest] {
			count++
		}
		//If the node receives at least 2f + 1 commit messages (including its own)
		//and the node has not replied and has been committed broadcast,
		//submit the information to the local message pool and reply successfully flag to the client！
		p.lock.Lock()
		if count >= nodeCount/3*2 && !p.isReply[c.Digest] && p.isCommitBordcast[c.Digest] {
			fmt.Println("This node has received the commit message from at least 2f + 1 nodes (including local nodes) ...")
			//Submit message information to local message pool
			localMessagePool = append(localMessagePool, p.messagePool[c.Digest].Message)
			info := p.node.nodeID + "node has stored msgid:" + strconv.Itoa(p.messagePool[c.Digest].ID) + " into message pool, the content of this message is " + p.messagePool[c.Digest].Content
			fmt.Println(info)
			fmt.Println("Replying client ...")
			tcpDial([]byte(info), p.messagePool[c.Digest].ClientAddr)
			p.isReply[c.Digest] = true
			fmt.Println("reply over")

			t2:=time.Now()
			fmt.Println(t2)

		}
		p.lock.Unlock()
	}
}

//Serial number accumulation
func (p *pbft) sequenceIDAdd() {
	p.lock.Lock()
	p.sequenceID++
	p.lock.Unlock()
}

//Broadcast to other nodes except oneself
func (p *pbft) broadcast(cmd command, content []byte) {
	for i := range nodeTable {
		if i == p.node.nodeID {
			continue
		}
		message := jointMessage(cmd, content)
		go tcpDial(message, nodeTable[i])
	}
}

//Assign values to multiple maps
func (p *pbft) setPrePareConfirmMap(val, val2 string, b bool) {
	if _, ok := p.prePareConfirmCount[val]; !ok {
		p.prePareConfirmCount[val] = make(map[string]bool)
	}
	p.prePareConfirmCount[val][val2] = b
}

//Assign values to multiple maps
func (p *pbft) setCommitConfirmMap(val, val2 string, b bool) {
	if _, ok := p.commitConfirmCount[val]; !ok {
		p.commitConfirmCount[val] = make(map[string]bool)
	}
	p.commitConfirmCount[val][val2] = b
}

//Pass in the node number to get the corresponding public key
func (p *pbft) getPubKey(nodeID string) []byte {
	key, err := ioutil.ReadFile("Keys/" + nodeID + "/" + nodeID + "_RSA_PUB")
	if err != nil {
		log.Panic(err)
	}
	return key
}

//Pass in the node number to get the corresponding private key
func (p *pbft) getPivKey(nodeID string) []byte {
	key, err := ioutil.ReadFile("Keys/" + nodeID + "/" + nodeID + "_RSA_PIV")
	if err != nil {
		log.Panic(err)
	}
	return key
}
