# PoFSQ

PoFSQ: An Efficient File-Sharing Consensus Protocol

Proof of File-Sharing Qualification(PoFSQ). PoFSQ allows file-holders to verify with each other whether the shared-file has been preserved for a period of time. It also ensures that the content of shared-file is indeed what the file-downloader wants under the condition that more than 2/3 of participants are honest. Compared to the consensus protocol of Filecoin, PoFSQ is more efficient in the prover and verifier proof phases, because it uses a simple Proof of SpaceTime (PoST) of shared-file association to complete the qualification verification. Meanwhile, PoFSQ does not disclose the private information of shared-file during the consensus process, and does not rely on trusted third parties. This paper also implements and tests PoFSQ, and experimental results show that consensus can be reached efficiently.


## Build the source:

```shell script
go build main.go
```
```shell script
./main.exe
```

### Prover Initialization Phase

prover runs the parallel limited proof of work (PL-PoW) to generate the evidence file.
Difficulty value can be adjusted dynamically and it determines the difficulty of PL-PoW.
In this project, readbitlen is the difficulty value, as follows:

```
const (
	readbitlen int64 = 10
)
```

The evidence file includes two parts: node file ending in .block and random number file ending in .nonce.
For example, Initialize the "1K" file will generate "1K.block" and "1K.nonce" files.


### Prover Proof Phase
Any verifier can challenge the prover by sending a random string ch. Upon receiving the challenge, prover utilizes the preserved evidence file to generate response message.

In this project, the value of ch is fixed, as follows:
```
var ch string = "12345678901234567890123456789014"
```

This phase will generate the response results, as follows:
```shell script
node := proverProofPhase.GenerateMerkleTree(filename,readbitlen,identity,ch)
```

node is the response result which includes the selected node and the path from the corresponding node to the root node.


### Verifier Proof phase
When verifiers receive the response result, they begin to verify:
```
verifierProofPhase.Verify(node,filename,identity,readbitlen,ch)
```


## Example of program running:

![test](https://github.com/buptis073114/PoFSQ/blob/master/img/run.png)

![test](https://github.com/buptis073114/PoFSQ/blob/master/img/generateBlockFiles.png)

![test](https://github.com/buptis073114/PoFSQ/blob/master/img/verify.png)

# Contract:
sushuai@iie.ac.cn

yuanfangyuan@iie.ac.cn
