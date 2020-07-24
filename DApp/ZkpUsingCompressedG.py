from hashlib import sha256
import os
# Public parameters: Can be changed based on the desired specifications in the SEC document.
# Based on secp256k1, http://www.oid-info.com/get/1.3.132.0.10

_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
generator = 0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817 # Compresssed form.
#generator = 0x0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 # Uncompressed form. Also works. 

ec_order = _r
byte_array=''


def random_secret():        #   Method to generate private key. 
    byte_array = os.urandom(32)
    joinArray = "".join([str(i) for i in byte_array])
    convert_to_int = int(joinArray)
    encode_int = int(hex(convert_to_int), 16)
    return (encode_int % ec_order)
 

def getKeyPair():
    #   Now going to generate a new private key.
    secret = random_secret()    #Generate a new private key.
    print("Private key is: ", secret)
    print("Hex form is:", hex(secret))
    P = (secret*generator)% ec_order
    #PublicKeyP = int((sha256(str(P).encode())).hexdigest(),16) # Displaying Public key in hex format. 
    print("The Public key is:", hex(P))
    print("Integer form is :", int(P))
    return secret, P


def getRvalue(r):
    #R = cv.mul_point(r,generator) 
    R = (r*generator)% ec_order 
    return R


def ProverComputations():
    x, P = getKeyPair()  # (x,P) for Prover.

    r = random_secret()     # Prover choses random nonce value r. 

    R  = getRvalue(r)
    print("R value is: ", hex(R))

    # Challenge e using H(R)
    e = int((sha256(str(R).encode())).hexdigest(),16)
    print("Value of e is: ", hex(e))
    #x = int(x,16)
    s = hex((r + (e*x)) % ec_order) # Check this area for ecmul usage.
    s = int(s,16)
    print("The response s value is: ", hex(s))
    return P,R,e,s


def VerifierComputations(P,R,e,s):
    leftSidePoint = (s*generator)% ec_order
    leftSide = (sha256(str(leftSidePoint).encode())).hexdigest()# In hex format.
    print("Left side value is: ", leftSide)

    #eP = (e*P)% ec_order  #cv.mul_point(e,P) also works fine. //These two commented lines also work.
    #addends = (R+eP)% ec_order
    rightCompute = (R + e*P) % ec_order
    rightSide = (sha256(str(rightCompute).encode())).hexdigest() # In hex format.
    print("Right side value is: ", rightSide)
    return leftSide, rightSide

def verificationCheck(rightSide, leftSide):
    if(rightSide==leftSide):
        print("Successful proof.")
    else:
        print("Failed proof")
    return


#   Main method for ZKP.
def main():
    print('')

    print("***********************Zero-Knowledge Proof using Schnorr***********")

    print('')

    print ("++++++++++ Prover's computations begins.+++++++++++++++")

    print('')
    # Call Prover to perform computations.
    P,R,e,s =  ProverComputations()
    print ("++++++++++ Prover's computations ends.+++++++++++++++")

    print('')
    print ("++++++++++ Verifier's computations begins.+++++++++++++++")
    print('')
    rightSide, leftSide = VerifierComputations(P,R,e,s)
    print ("++++++++++ Verifier's computations ends.+++++++++++++++")

    print('')
    print ("***************** Fetching Verifier's result.*************")
    verificationCheck(rightSide, leftSide)
    print('')
    print ("*************Verifier's result ends.***********************")
    print('')
    print ("++++++++++++++++++++++ End of program.++++++++++++++++++++++++++++++")
    #   Main method ends here. 

#   Program execution time. 
main()


    

