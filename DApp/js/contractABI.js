// This file holds contracts ABI, Address and Default Gas for contract execution.

var ABI = [
	{
		"constant": false,
		"inputs": [
			{
				"name": "_UserpubKeyP",
				"type": "uint256"
			},
			{
				"name": "_RandomR",
				"type": "uint256"
			},
			{
				"name": "_oracleValueE",
				"type": "uint256"
			},
			{
				"name": "_responseS",
				"type": "uint256"
			}
		],
		"name": "PartakeInPubKeyPool",
		"outputs": [
			{
				"name": "status",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_UserpubKeyP",
				"type": "uint256"
			}
		],
		"name": "AwaitResponse",
		"outputs": [
			{
				"name": "status",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "state",
		"outputs": [
			{
				"name": "",
				"type": "uint8"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"name": "msg",
				"type": "string"
			}
		],
		"name": "message",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"name": "msg",
				"type": "string"
			}
		],
		"name": "failed",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"name": "pubKeyOne",
				"type": "bytes32"
			}
		],
		"name": "publishAwait",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"name": "pubKeyOne",
				"type": "bytes32"
			},
			{
				"indexed": false,
				"name": "pubKeyTwo",
				"type": "bytes32"
			},
			{
				"indexed": false,
				"name": "pubKeyThree",
				"type": "bytes32"
			},
			{
				"indexed": false,
				"name": "pubKeyFour",
				"type": "bytes32"
			}
		],
		"name": "pubKeys",
		"type": "event"
	}
]

var contractAddress = '0x8BF093c72A1c86F5fD5d6d084470CcB983759691';


var suppliedGas = 3000000;
