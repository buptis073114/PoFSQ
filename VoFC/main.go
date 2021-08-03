package main

import (
	"log"
	"os"
)

const nodeCount = 4

//Listening address of client
var clientAddr = "127.0.0.1:8888"

//Node pool, mainly used to store listening address
var nodeTable map[string]string

func main() {
	//Generate public and private keys for nodes
	genRsaKeys()
	nodeTable = map[string]string{
		"N0": "127.0.0.1:8000",
		"N1": "127.0.0.1:8001",
		"N2": "127.0.0.1:8002",
		"N3": "127.0.0.1:8003",
		//"N4": "127.0.0.1:8004",
		//"N5": "127.0.0.1:8005",
		//"N6": "127.0.0.1:8006",
		//"N7": "127.0.0.1:8007",
		//"N8": "127.0.0.1:8008",
		//"N9": "127.0.0.1:8009",
		//"N10": "127.0.0.1:8010",
		//"N11": "127.0.0.1:8011",
		//"N12": "127.0.0.1:8012",
		//"N13": "127.0.0.1:8013",
		//"N14": "127.0.0.1:8014",
		//"N15": "127.0.0.1:8015",
		//"N16": "127.0.0.1:8016",
		//"N17": "127.0.0.1:8017",
		//"N18": "127.0.0.1:8018",
		//"N19": "127.0.0.1:8019",
	}
	if len(os.Args) != 2 {
		log.Panic("The input parameter is wrong!")
	}
	nodeID := os.Args[1]
	if nodeID == "client" {
		clientSendMessageAndListen() //Start client program
	} else if addr, ok := nodeTable[nodeID]; ok {
		p := NewPBFT(nodeID, addr)
		go p.tcpListen() //start nodes
	} else {
		log.Fatal("No node number!")
	}
	select {}
}
