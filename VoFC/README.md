# VoFC
Verification of File-Consistency (VoFC) is proposed to ensure that all participants keep consistent files. It can be ensured that the consistent files are really needed by the file-downloaders under the condition where more than two-thirds of participants in the whole network are honest. 
VoFC is composed of Proof of SpaceTime and the PBFT algorithm.

This demo is the code implementation of VoFC consensus algorithm. If you want to learn more about PBFT, please browse the resources yourself.

This demo shows some functions of VoFC (not include master node rotation mechanism), which is not rigorous and is only used for understanding VoFC


![VoFC](https://github.com/buptis073114/VoFSQ/blob/master/img/VoFC.png)

## Function:

There are three roles in VoFC, Client, Primary and replica. Client can be viewed as file downloader. The primary is a special file sharer who is elected by other file-sharers. The replica represents other file-sharers except the primary. There are five phases in file-consistency verification, namely request, pre-prepare, prepare, commit and reply.
  
 1. Client (file downloader) sends file download message to the primary.
 2. After receiving the message from the client, the primary verifies the digital signature. If the verification is passed, the primary constructs the pre-prepare message and send to other nodes.
 3. When the replica receives the message from the primary, the replica verifies the digital signature. If the verification is passed, the replica sends a prepare message to the primary.
 4. If the node receives 2f prepare messages (including itself) and all the signatures are verified, it can proceed to the commit step and broadcast commit to other nodes in the whole network.
 5. If the node receives 2f + 1 commit information (including itself) and all the signatures are verified, it can store the message locally and return the reply message to the client.


## Operation steps:
<br>

##### 1.Download/compile
```shell
 git clone https://github.com/buptis073114/VoFSQ.git
```
```shell
 cd VoFSQ/VoFC
```
```go
 go build -o vofc.exe
```

##### 2.Open five ports (one client, four nodes)
console execute 
```shell script
vofc.exe client
```
The other four nodes execute:
```shell script
vofc.exe N0
```
```shell script
vofc.exe N1
```
```shell script
vofc.exe N2
```
```shell script
vofc.exe N3
```

![startup](https://github.com/buptis073114/VoFSQ/blob/master/img/VoFC1.png)
##### 3.Enter message to see the synchronization process between nodes
![vofc1](https://github.com/buptis073114/VoFSQ/blob/master/img/VoFC2.png)
##### 4.Close a node (representing the evil or fault node) and input the information again to see if it will receive a reply
You can see that the client will still receive a reply, because according to the formula n > = 3f + 1, even if a node is down, the system can still run smoothly
![vofc2](https://github.com/buptis073114/VoFSQ/blob/master/img/VoFC3.png)
##### 5.Close the two nodes (representing the evil and fault nodes) and input the information again to see if the reply will still be received
It can be seen that after the two nodes are shut down, the number of failed nodes has exceeded the allowable number of pbft. When the message goes to the prepare stage, the fixed system will no longer confirm the commit because it can not receive the required number of messages, and the client will not receive the reply
![vofc3](https://github.com/buptis073114/VoFSQ/blob/master/img/VoFC4.png)
