// A private or local blockchain example for local proof-of-concept of modified LwRS scheme.
const cryptoJS = require("crypto-js")
const SHA256 = cryptoJS.SHA256
const BigNumber = require("./bignumber")  
const jsSHA = require("./jssha")
const { MerkleTree } = require('merkletreejs')         

class Transaction {
	constructor (fromAddress, toAddress, amount, tData) {
		this.fromAddress = fromAddress;
		this.toAddress = toAddress;
		this.amount = amount;
		this.tData = tData;
	}

	transToSign(){
		if(addressVal(this.fromAddress)===1 && addressVal(this.toAddress)===1){
			if(this.amount >= 1 & this.tData.length >=1){
				return JSON.stringify({From: this.fromAddress, Amount: this.amount, Data: this.tData, To: this.toAddress})
			} else {
				return 0
			}
		} else {
			return 0
		}
	}
}

class Block {
	constructor(index, timestamp, transactionData, previousHash) {
		this.index = index;
        this.previousHash = previousHash;
        this.timestamp = timestamp;
        this.transactionData = transactionData;
        this.hash = this.calculateHash();
        this.nonce = 0;
    }

	calculateHash() {
		return SHA256(this.index + this.previousHash + this.timestamp + JSON.stringify(this.transactionData) + this.nonce).toString();
	}

	mineBlock(difficulty) {
		while (this.hash.substring(0, difficulty) !== Array(difficulty + 1).join("0")) {
			this.nonce++;
			this.hash = this.calculateHash();
		}
		console.log("Hash of block mined: " + this.hash);
	}
}

class Blockchain{
	constructor() {
		this.chain = [this.createGenesisBlock()];
		this.difficulty = 4;
		this.pendingTransactions = []; // To store pending transactions.
		this.miningReward = 50;
	}

	getCurrentDate(){
		var currentTime = new Date()
		var month = currentTime.getMonth() + 1
		var day = currentTime.getDate()
		var year = currentTime.getFullYear()
		var time = currentTime.getHours() + ':'+ currentTime.getUTCMinutes() + ':' + currentTime.getSeconds()
		return day + "/" + month + "/" + year + '::' + time
	}

	createGenesisBlock() {
		return new Block(1, this.getCurrentDate(), "Genesis Block", "0");
	}

	getLatestBlock() {
		return this.chain[this.chain.length -1];
	}

	addTransaction(transaction) {
		// Validation already done hence proceed.
		// Push into onto the "pendingTransactions" array
		this.pendingTransactions.push(transaction);
	}

	minePendingTransactions(miningRewardAddress) {
		if (addressVal(miningRewardAddress)=== 1) {
		// Create new block with all pending transactions and mine it..
		let block = new Block(this.getLatestBlock().index + 1, this.getCurrentDate(), this.pendingTransactions, this.getLatestBlock().hash);
		block.mineBlock(this.difficulty);
		// Add the newly mined block to the chain
		this.chain.push(block);
		// Reset the pending transactions and send the mining reward
		this.pendingTransactions = [new Transaction(null, miningRewardAddress, this.miningReward, null)];
		} else {
			console.log('Invalid miner address.')
		}
	}

	isChainValid() {
		for (let i = 1; i < this.chain.length; i++){
			const currentBlock = this.chain[i];
			const previousBlock = this.chain[i - 1];
			if (currentBlock.hash !== currentBlock.calculateHash()) {
				return false;
			}
			if (currentBlock.previousHash !== previousBlock.hash) {
				return false;
			}
		}
		return true;
	}

	getBalanceOfAddress(address){
		// Perform address validation.
		if(addressVal(address)=== 1) {
			let balance = 0; 
			// Loop over each block and each transaction inside the block
			for(const block of this.chain){
				for(const trans of block.transactionData){
					// If the given address is the sender -> reduce the balance
					if(trans.fromAddress === address){
						balance -= trans.amount;
					}
					// If the given address is the receiver -> increase the balance
					if(trans.toAddress === address){
						balance += trans.amount;
					}
				}
			}
			return balance;
		} else {
			return -1
		}
	}
}

class userKey{
    constructor(p, q){
        this.p = p;
        this.q = q;
        this.N = p * q;
    }
    static randomGenerate(){
    }
}

class signTransaction {
	constructor(user, L, message, IDevent){
		this.user = user;
		this.L = L;
		this.message = message;
		this.IDevent = IDevent;
	}

	genSignature(){
		let j = null
		for(let i = 0; i < this.L.length; i++){
			if(this.L[i] === this.user.N){
				j = i
				break
			}
		}
		if(j === null) throw "j not found."

		// console.log(`found signer j === ${j}`)
		//
		let h = getHashI(buildLmIDeventData(this.L, this.message, this.IDevent), this.L[0])

		// console.log(`get h === ${h}`)

		// Generate random numbers.
		let x = []
		for(let i = 0; i < this.L.length; i++){
			x[i] = getRandomFromN(this.L[i])
		}

		// console.log(`init random xArr === ${x.join()}`)

		// A stronger Key Image computation to withstand double spending tendency.
		let k = '' // Commitment.
		k = (getQRHash((this.user.q + this.user.p),this.user.N)).toString()
		console.log("+++++++++++++++++++++++++++++++++++++++++++++++++++")
		console.log("The commitment value is: ", k)
		let I = Math.sqrt(getQRHash(buildpjNjIDeventData(k, this.user.N, this.IDevent), this.user.N)) % this.user.N
		console.log("********************************")
		console.log(`The Stronger key image I is === ${I}`)
		// console.log("*******************************************************")

		let c = []
		//c Computation.
		let current = j
		let next = (current + 1) % this.L.length //j + 1
		c[next] = getHashI(buildhrjData(h, x[current]), this.L[next])
		for(let i = 1; i < this.L.length; i++){
			current = next
			next = (current + 1) % this.L.length
			c[next] = getHashI(buildhrjData(h, (c[current] * I + x[current] * x[current]) % this.L[current]), this.L[next])
		}

		let ti = getMod(x[j] - c[j] * I, this.L[j])
		while(!checkIfInQR(ti, this.L[j])){
			let pre = (j - 1 + this.L.length) % this.L.length
			x[pre] = getRandomFromN(this.L[pre])
			c[j] = getHashI(buildhrjData(h, (c[pre] * I + x[pre] * x[pre]) % this.L[pre]), this.L[j])
			ti = getMod(x[j] - c[j] * I, this.L[j])
		}

		x[j] = Math.sqrt(ti)
		// console.log(`get cArr === ${c.join()}`)
		// console.log(`get xArr === ${x.join()}`)
		// console.log(c[0])
		return {I, c1: c[0], x: x}
	}
}

class verifySig {
	constructor(sign, L, message, IDevent){
		this.sign = sign;
		this.L = L;
		this.message = message;
		this.IDevent = IDevent;
	}

	verify(){
		//h = H1(L||m||IDevent)
		let h = getHashI(buildLmIDeventData(this.L, this.message, this.IDevent), this.L[0])
		// console.log(`get h === ${h}`)
	
		let x = this.sign.x
		let c1 = this.sign.c1
		let I = this.sign.I
		// console.log(`get xArr === ${x.join()}`)
		// console.log(c1)
	
		let r = []
		let c = []
		c[0] = c1
		r[0] = getMod(c[0] * I + x[0] * x[0], this.L[0])
		for(let i = 1; i < this.L.length; i++){
			c[i] = getHashI(buildhrjData(h, r[i - 1]), this.L[i])
			r[i] = getMod(c[i] * I + x[i] * x[i], this.L[i])
		}
		// console.log(`get cArr === ${c.join()}`)
		// console.log(`get rArr === ${r.join()}`)
		c1 = getHashI(buildhrjData(h, r[this.L.length - 1]), this.L[0])
		// console.log(`c1 : ${c1} <===>  c[0]: ${c[0]}`)
		if(c1 === c[0]){
			return 1
		} else {
			return 0
		}
	}
}

// Helper functions begin.
function getMod(num, N){
    if(num < 0){
        num = num + (1 - Math.floor(num / N)) * N
    }
    return num % N
}

function getQRHash(data, Ni){
    let Niq2 = Math.floor(Math.sqrt(Ni)) 
    let shaObj = new jsSHA("SHA-256", "TEXT"); // Instantiating of cryptographic hashing function. 
    shaObj.update(data); // Stream in input.
    hash = shaObj.getHash("HEX")  // Get digest with specified output type. In this case HEX not TEXT.
    return new BigNumber(hash, 16).mod(Niq2).pow(2).toNumber()
}

function getHashI(data, Ni){
    let shaObj = new jsSHA("SHA-256", "TEXT");
    shaObj.update(data);
    hash = shaObj.getHash("HEX")
    return new BigNumber(hash, 16).mod(Ni).toNumber()
}

function buildLmIDeventData(L, m, IDevent){
    let str = ""
    str += L.join("-")
    str += "||"
    str += m
    str += "||"
    str += IDevent
    return str
}

function buildhrjData(h, rj){
    let str = ""
    str += h
    str += "||"
    str += rj
    return str
}

function buildpjNjIDeventData(pj, Nj, IDevent){
    let str = ""
    str += pj
    str += "||"
    str += Nj
    str += "||"
    str += IDevent
    return str
}

function getRandomFromN(N){
    return Math.floor(Math.random() * N)
}

function checkIfInQR(num, Nj){
    num = Math.sqrt(num % Nj)
    if(num > 0 && Math.floor(num) === num){
        return true
    } else {
        return false
    }
}

function addressVal(address){
	let regTest = /^0x[0-9A-F]{5}$/i
	if (regTest.test(address)=== true){
		return 1
	} else {
		return 0
	}
}
// Helper functions end.

// Main execution begins. 
let prvBC = new Blockchain();
// console.log('Block inspection on instantiation:', prvBC.chain)
// Needed params.
let ring = []
// Value 1 as Identity value for multiplication.
ring.push(new userKey(0xd2525ad879ead3282695cf2f9d22ab96e9fb84d56e21e3e749145e0883c6db9b, 
					0x8267a554802a6dc9413de6cc7b2facd13c3b076a1d85ad678115aaeac29da6b8))
ring.push(new userKey(0xbf630b2686a85baf74142941e8fc1c4de0ea296f2adbe397259ea73124173623,1))
ring.push(new userKey(0x74eac5db9bac04bdeffbedeb842813b2179893d6985b8ab14efecdc592873659,1))
ring.push(new userKey(0x935228b20bdc2349389ade14548ad5542bb16a2df7f3f2e4c293c03319a87125,1))
// Public key computation and Public Key list for Ring members.
L = ring.map(user => user.N)
let IDevent = 1

let uRawTransactions = []
let userTransDataToSign = []
let uTransactionOne = new Transaction('0x1234a', '0x2345a', 10, 'LabTest1')
let uTransactionTwo = new Transaction('0x1234a', '0x2345b', 15, 'LabTest2')
// let uTransactionThree = new Transaction('0x1234a', '0x2345c', 25, 'LabTest3')

uRawTransactions.push(uTransactionOne, uTransactionTwo)

for(i=0; i<uRawTransactions.length; i++){
	userTransDataToSign[i] = uRawTransactions[i].transToSign()
}
// Build merkle tree of the two transactions. Validate. 
const leaves = userTransDataToSign.map(x => SHA256(x))
const mTree = new MerkleTree(leaves, SHA256)
const mRoot = mTree.getRoot().toString('hex')
console.log('Total user transactions:', userTransDataToSign.length)
let counter = 1;
let tempObj = []
for(var i=0; i<userTransDataToSign.length; i++){
	if (userTransDataToSign[i] != 0){
		// Sign transaction.
		console.log('Signing transaction No.:', i+1)
		let signInstance = new signTransaction(ring[0], L, userTransDataToSign[i], IDevent)
		let mLwRS = signInstance.genSignature()
		// console.log("**********************************************************************")
		// console.log("Ring Signature generated for modified scheme is: ", mLwRS)
		// console.log("**********************************************************************")
		// Verify signature is valid.
		// console.log("verifying signature ===================")
		let verifyInstance  = new verifySig(mLwRS, L, userTransDataToSign[i], IDevent)
		let verifySigResult = verifyInstance.verify()
		// console.log('Verification result: ', verifySigResult)
		if (verifySigResult === 1){
			// Display verification success message.
			console.log("Signature verification successful.")
			console.log("********************************")
			// Create temporary object for this transaction. 
			tempObj[i] = [userTransDataToSign[i], mLwRS]
			// Add transactions to pending transactions if they are two.
			if((counter % 2) === 0 && tempObj.length === 2 && typeof tempObj[tempObj.length-2] !=="undefined"){
				// Build the Block body.
				let transObject = {
									MerkleRoot: mRoot, 
									BlockBody: {
												Tx1: tempObj[tempObj.length-2],
												Tx2: tempObj[i]
											}
								}
				prvBC.addTransaction(transObject)
				// Reset transObj
				tempObj.length = 0
			}
			// Check number of pending transactions and mine them.
			// console.log("Total pending transactions: ", prvBC.pendingTransactions.length)
			// console.log('Starting mining');
			// console.log('Pending transactions object: ', prvBC.pendingTransactions)
			if (prvBC.pendingTransactions.length > 0){
				// There exist pending transactions hence mine them.
				console.log('Pending transactions found. Mining them now...')
				for(var x = 0; x < prvBC.pendingTransactions.length; x++){
					prvBC.minePendingTransactions('0x34567') // Transactions mined. Block reward would be in next mined block.
				}
				// prvBC.minePendingTransactions('0x34567') // Mine again to claim reward.
			} else {
				console.log('No pending transaction(s) found.')
			}
		} else {
				console.log("Failed Signature verification. Rejecting transaction.")
			}
			// Main execution ends.
	} else {
			console.log('Sorry! Invalid transaction. Transaction aborted.')
		}
	counter++
}
// Check balance.
// let userAccBal = prvBC.getBalanceOfAddress('0x34567')
// if (userAccBal >= 0) {
	// console.log('Balance check of miner address is', prvBC.getBalanceOfAddress('0x34567'));
// } else {
	// console.log('Sorry! Invalid miner address format.');
// }
// Testing tamper proof nature begins.
// Check if chain is valid.
console.log('Is the Blockchain valid? ' + prvBC.isChainValid());

// Let's now manipulate the data
// prvBC.chain[0].transactionData = '0x12345' + 10 + 'LabTest' + '0x23456'
// prvBC.chain[0].hash = SHA256(0 + '23/7/2020' + JSON.stringify('0x12345' + 10 + 'LabTest' + '0x23456') + 0).toString()
// Check our chain again (will now return false)
// console.log("Is the Blockchain valid after tampering attempt? " + prvBC.isChainValid()); // Yes hence outputs false.
console.log('Last Block Info =>: Block index:', prvBC.chain[prvBC.chain.length - 1].index + ' Previous hash: ', prvBC.chain[prvBC.chain.length - 1].previousHash + ' Timestamp:', prvBC.chain[prvBC.chain.length - 1].timestamp)
console.log('Entire block:', prvBC.chain[prvBC.chain.length - 1].transactionData)
if(prvBC.chain[prvBC.chain.length - 1].transactionData !== 'Genesis Block') {
	// console.log('Merkle root: ',prvBC.chain[prvBC.chain.length - 1].transactionData[0].MerkleRoot)
	console.log('Tx1: ',prvBC.chain[prvBC.chain.length - 1].transactionData[0].BlockBody.Tx1)
}
// Testing tamper proof nature ends.
