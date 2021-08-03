package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)

func clientSendMessageAndListen() {
	//Turn on the local monitoring of the client (mainly used to receive the reply information of the node)
	go clientTcpListen()
	fmt.Printf("Client starts monitoring, address: %s\n", clientAddr)
	fmt.Println(" ---------------------------------------------------------------------------------")
	fmt.Println("|  Pbft test demo client has entered, please start all nodes before sending messages)  |")
	fmt.Println(" ---------------------------------------------------------------------------------")
	fmt.Println("Please enter the information to be saved in the node below:")
	//First, get user input from command line
	stdReader := bufio.NewReader(os.Stdin)
	for {
		data, err := stdReader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from stdin")
			panic(err)
		}
		r := new(Request)
		r.Timestamp = time.Now().UnixNano()
		r.ClientAddr = clientAddr
		r.Message.ID = getRandom()
		//The message content is the user's input
		r.Message.Content = strings.TrimSpace(data)
		br, err := json.Marshal(r)
		if err != nil {
			log.Panic(err)
		}
		fmt.Println(string(br))
		starttime := time.Now()
		fmt.Println(starttime)
		content := jointMessage(cRequest, br)
		//Default N0 is the primary node, and the request information is sent directly to N0
		tcpDial(content, nodeTable["N0"])
	}
}

//Returns a ten digit random number as msgid
func getRandom() int {
	x := big.NewInt(10000000000)
	for {
		result, err := rand.Int(rand.Reader, x)
		if err != nil {
			log.Panic(err)
		}
		if result.Int64() > 1000000000 {
			return int(result.Int64())
		}
	}
}
