import ecdsa
#import sha3
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.curves import SECP256k1
from ecpy.curves import Curve, Point
#from ecdsa import  SECP256k1   # This is useful to avoid manual curve key computations.#SECP256k1 
# can be changed based on the desired specifications in the SEC document.
# Refer to downloaded document in Block_chain_stuff ---- Recommended EC domain parameters.
#
import os
import sys
import numpy as np
from hashlib import sha256
import binascii
import re


from ecdsa.util import string_to_number, number_to_string

# Based on secp256k1, http://www.oid-info.com/get/1.3.132.0.10

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

curve_secp256k1 = ecdsa.ellipticcurve.CurveFp(_p, _a, _b)
generator_secp256k1 = ecdsa.ellipticcurve.Point(curve_secp256k1, _Gx, _Gy, _r)
oid_secp256k1 = (1, 3, 132, 0, 10)
SECP256k1 = ecdsa.curves.Curve("SECP256k1", curve_secp256k1, generator_secp256k1, oid_secp256k1)
ec_order = _r
curve = curve_secp256k1
cv = Curve.get_curve('secp256k1')
#generator = generator_secp256k1
generator = Point(_Gx, _Gy, cv) # Another way to get the G
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
    P = (secret*generator)
    #PublicKeyP = get_point_pubkey(P)
    PublicKeyP = (sha256(str(P).encode())).hexdigest() # Displaying Public key in hex format.
    print("The Public key is:", PublicKeyP)
    return secret, P


def getRvalue(r):
    R = cv.mul_point(r,generator) 
    return R


def get_point_pubkey(point):
    '''
    Converts point to hex format.
    '''
    if point.y & 1:
        key = '03' + '%064x' % point.x
    else:
        key = '02' + '%064x' % point.x
    return key


def ProverComputations():
    x, P = getKeyPair()  # (x,P) for Prover.

    r = random_secret()     # Prover choses random nonce value r. 

    R  = getRvalue(r)
    print("R value is: ", R)

    # Challenge e using H(R)
    e = int((sha256(str(R).encode())).hexdigest(),16)
    print("Value of e is: ", e)
    #x = int(x,16)
    s = hex((r + (e*x)) % ec_order) # Check this area for ecmul usage.
    s = int(s,16)
    print("The response s value is: ", s)
    return P,R,e,s


def VerifierComputations(P,R,e,s):
    leftSidePoint = (s*generator)
    leftSide = (sha256(str(leftSidePoint).encode())).hexdigest()# In hex format.
    print("Left side value is: ", leftSide)

    #px =P.x
    #py =P.y 
    #P = Point(px,py,cv)
    eP = e*P  #cv.mul_point(e,P) also works fine. 
    addends = cv.add_point(R, eP)
    rightSide = (sha256(str(addends).encode())).hexdigest() # In hex format.
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
    print('')
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


    

