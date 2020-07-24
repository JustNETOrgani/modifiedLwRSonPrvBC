pragma solidity ^0.5.7;
import "github.com/provable-things/ethereum-api/provableAPI.sol";
// Libray to aid computations.
library ZKPComputations {
    // Function containing In-line Assembly Language for Arbitrary Pricision Arithmetic. 
    function VerifyProof(uint256 P,uint256 R,uint256 e,uint256 s) internal pure returns (uint8 verifyCalc){
        uint256 G = 0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817; // Compressed form.
        uint256 ecOrder = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        uint256 rightSG;
        uint256 leftEP;
        uint256 rightside;
        assembly{
                rightSG :=mulmod(s,G,ecOrder)
                leftEP :=mulmod(e,P,ecOrder)
                rightside := addmod(R,leftEP,ecOrder)
        }
        bytes32 leftsideResult = keccak256(abi.encodePacked(rightSG));
        bytes32 rightsideResult = keccak256(abi.encodePacked(rightside));
        if (leftsideResult==rightsideResult){
            return 1;
        }
        else{
            return 0;
        }
    }
}
// Main contract begins. 
contract NIZkProofs is usingProvable  {
    using ZKPComputations for *;
    enum userState {New, GrantedPubKeys, Awaiting}// New for fresh users, GrantedPubKeys for those already given keys and Awaiting proved users but awaiting public keys due key availability.
    struct pkPool{
        bytes32 KeyPool; // Public Key Pool for users. Is this really needed?
        userState stateOfUser;
    }
    bytes32[] internal PubKeyPool;
    uint256 public randomNumber; // Random number to be supplied by Provable oraclize.
    mapping (bytes32 => pkPool) internal publicKeyMap; //Mapping for usage in array checks.
    // Events for DApp frontend begin.
    event message(string msg);
    event failed(string msg);
    event genRNDnum(uint256 rndNumProvable); // For testing.
    event pubKeys(bytes32 pubKeyOne, bytes32 pubKeyTwo, bytes32 pubKeyThree, bytes32 pubKeyFour);
    // Events for DApp frontend end.
    userState public state;
    // Constructor for the contract.
    constructor() payable public {
        state = userState.New;
        provable_setProof(proofType_Ledger);
        getRandomNumFromProvable(); // Get random number from Provable at Contract deployment.
    }
    // Function to be called by Provable Oraclize.
    function __callback(bytes32 queryId, string memory result, bytes memory proof) public {
        require(msg.sender == provable_cbAddress());
        if(provable_randomDS_proofVerify__returnCode(queryId, result, proof) == 0){
            uint MaxRange = 2 ** (8 * 7);
            randomNumber = uint(keccak256(abi.encodePacked(result))) % MaxRange;
            emit genRNDnum(randomNumber);
        }
        else{
            // Handle failed proof verification.
            emit failed("Failed Provable verification.");
        }
    }
    // Function to get the random number from Provable oraclize.
    function getRandomNumFromProvable() payable public {
        uint numberOfBytes = 7;
        uint delay = 0;
        uint callbackGas = 200000;
        provable_newRandomDSQuery(delay, numberOfBytes, callbackGas);
        emit message("Provable query sent, awaiting response...");
    }
    // Function for verification of proof.
    function PartakeInPubKeyPool (uint256 _UserpubKeyP,uint256 _RandomR,uint256 _oracleValueE,uint256 _responseS) 
                public returns (bool status) {
        if(ZKPComputations.VerifyProof(_UserpubKeyP,_RandomR,_oracleValueE,_responseS)==1){
            // ranNum0 to 2 can be obtained via oraclize using Random Generator Service.
            bytes32 hashPubKey = keccak256(abi.encodePacked(_UserpubKeyP));
            if(memberCheck(hashPubKey)==0){
                PubKeyPool.push(hashPubKey);
                if(getPubKeyPoolLength()>=4){
                    emit message("Successful proof. Retrieving public keys.");
                    pkPool storage pool = publicKeyMap[hashPubKey];
                    pool.KeyPool = hashPubKey;
                    (uint256 posOne, uint256 posTwo, uint256 posThree) = PubKeyPoolPos(_UserpubKeyP,_responseS);
                    emit pubKeys(hashPubKey,PubKeyPool[posOne],PubKeyPool[posTwo],PubKeyPool[posThree]);
                    pool.stateOfUser = userState.GrantedPubKeys;
                    return true;
                }
                else{
                        emit message("Successful proof but less public keys available. Call awaiting someday.");
                        pkPool storage pool = publicKeyMap[hashPubKey];
                        pool.KeyPool = hashPubKey;
                        pool.stateOfUser = userState.Awaiting;
                        return false; 
                    }
                     
                }
                else
                    {
                        emit failed("User can only call this contract method once.");
                        return false; 
                    }
        }
        else{
                emit failed("Sorry! Verfication failed");
                return false;
        }
    }
    // Function for existing proved users to get public keys.
    function AwaitResponse(uint256 _UserpubKeyP) public returns (bool status){
        bytes32 hashPubKey = keccak256(abi.encodePacked(_UserpubKeyP));
        if(memberCheck(hashPubKey)==2){
            if(getPubKeyPoolLength()>=4){
                pkPool storage pool = publicKeyMap[hashPubKey];
                (uint256 posOne, uint256 posTwo, uint256 posThree) = PubKeyPoolPos(_UserpubKeyP,getPubKeyPoolLength());
                emit pubKeys(hashPubKey,PubKeyPool[posOne],PubKeyPool[posTwo],PubKeyPool[posThree]);
                pool.stateOfUser = userState.GrantedPubKeys;
                return true; 
            }
            else{
                    emit message("Still less public keys available. Call awaiting another time.");
                    return false; 
                }
        }
        else{
                emit failed("Sorry! You're not on awaiting list.");
                return false; 
            }
    }
    // Function to get the length of PubKeyPool. 
    function getPubKeyPoolLength() internal view returns (uint256 length){
        return PubKeyPool.length;
    }
    // Function to perform array/mapping member check for user input of Public key. 
    function memberCheck(bytes32 _userPublicKey) internal view returns (uint8){
        pkPool memory pool = publicKeyMap[_userPublicKey];
        if(pool.stateOfUser==userState.New){
            return 0;
        }
        else if(pool.stateOfUser==userState.Awaiting){
                return 2;
        }
        else{
                return 1;
        }
    }
    // Function to determine index values of 'PubKeyPool' to be used to retrieve the hashed public keys.
    function PubKeyPoolPos(uint256 _UserpubKeyP,uint256 _responseS ) public payable returns (uint256, uint256, uint256){
        uint256 MaxNum      = PubKeyPool.length;
        uint256 posOne      = uint256(randomNumber % MaxNum);
        uint256 posTwo      = uint256((randomNumber + _UserpubKeyP) % MaxNum);
        uint256 posThree    = uint256((randomNumber + _responseS) % MaxNum);
        if(posOne!=posTwo && posTwo!=posThree && posOne!=posThree){
            return (posOne,posTwo,posThree);
        }
        else return (1,2,3);
    } 
}