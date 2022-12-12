const BigNumber = require("./bignumber")    // https://github.com/MikeMcl/bignumber.js
const jsSHA = require("./jssha")            //https://github.com/Caligatio/jsSHA.

class userKey{
    constructor(p, q){
        this.p = p
        this.q = q
        this.N = p * q
    }

    static randomGenerate(){

    }
}

// Execution begins here. Timing starts.
var execStartTime = process.hrtime()

// Generate user's private/secret keys.
let users = []
users.push(new userKey(0xd2525ad879ead3282695cf2f9d22ab96e9fb84d56e21e3e749145e0883c6db9b, 0x8267a554802a6dc9413de6cc7b2facd13c3b076a1d85ad678115aaeac29da6b8))
users.push(new userKey(0xbf630b2686a85baf74142941e8fc1c4de0ea296f2adbe397259ea73124173623,1))
users.push(new userKey(0x74eac5db9bac04bdeffbedeb842813b2179893d6985b8ab14efecdc592873659,1))
users.push(new userKey(0x935228b20bdc2349389ade14548ad5542bb16a2df7f3f2e4c293c03319a87125,1))

// Public key computation and Public Key list for Ring members.
L = users.map(user => user.N)

let IDevent = 1
let message = "Hello world"
console.log("sign ===================")
let sign = signature(users[0], L, message, IDevent)
console.log("**********************************************************************")
console.log("Ring Signature generated is: ", sign)
console.log("**********************************************************************")

console.log("verify ===================")
verify(sign, L, message, IDevent)

execEndTime = process.hrtime(execStartTime)
console.info('Execution time (hr): %ds %dms', execEndTime[0], execEndTime[1] / 1000000)
// Execution ends. Timing ends.

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

function signature(user, L, message, IDevent){
    let j = null
    for(let i = 0; i < L.length; i++){
        if(L[i] === user.N){
            j = i
            break
        }
    }
    if(j === null) throw "j not found"

    console.log(`found signer j === ${j}`)
    //
    let h = getHashI(buildLmIDeventData(L, message, IDevent), L[0])

    console.log(`get h === ${h}`)

    // Generate random numbers.
    let x = []
    for(let i = 0; i < L.length; i++){
        x[i] = getRandomFromN(L[i])
    }

    console.log(`init random xArr === ${x.join()}`)

    // Key Image computation.
    let I = Math.sqrt(getQRHash(buildpjNjIDeventData(user.p, user.N, IDevent), user.N)) % user.N
    console.log("********************************")
    console.log(`The key image I_A is === ${I}`)
    console.log("********************************")
    console.log('Simulating malicious user by key swapping')
    let I_B = Math.sqrt(getQRHash(buildpjNjIDeventData(user.q, user.N, IDevent), user.N)) % user.N
    console.log("********************************")
    console.log(`The key image I_B is === ${I_B}`)
    console.log("********************************")



    let c = []
    //c Computation.
    let current = j
    let next = (current + 1) % L.length //j + 1
    c[next] = getHashI(buildhrjData(h, x[current]), L[next])
    for(let i = 1; i < L.length; i++){
        current = next
        next = (current + 1) % L.length
        c[next] = getHashI(buildhrjData(h, (c[current] * I + x[current] * x[current]) % L[current]), L[next])
    }

    let ti = getMod(x[j] - c[j] * I, L[j])
    while(!checkIfInQR(ti, L[j])){
        let pre = (j - 1 + L.length) % L.length
        x[pre] = getRandomFromN(L[pre])
        c[j] = getHashI(buildhrjData(h, (c[pre] * I + x[pre] * x[pre]) % L[pre]), L[j])
        ti = getMod(x[j] - c[j] * I, L[j])
    }

    x[j] = Math.sqrt(ti)
    console.log(`get cArr === ${c.join()}`)
    console.log(`get xArr === ${x.join()}`)
    console.log(c[0])
    return {
        I,
        c1: c[0],
        x: x
    }
}

function verify(sign, L, message, IDevent){
    //h = H1(L||m||IDevent)
    let h = getHashI(buildLmIDeventData(L, message, IDevent), L[0])
    console.log(`get h === ${h}`)

    let x = sign.x
    let c1 = sign.c1
    let I = sign.I
    console.log(`get xArr === ${x.join()}`)
    console.log(c1)

    let r = []
    let c = []
    c[0] = c1
    r[0] = getMod(c[0] * I + x[0] * x[0], L[0])
    for(let i = 1; i < L.length; i++){
        c[i] = getHashI(buildhrjData(h, r[i - 1]), L[i])
        r[i] = getMod(c[i] * I + x[i] * x[i], L[i])
    }
    console.log(`get cArr === ${c.join()}`)
    console.log(`get rArr === ${r.join()}`)
    c1 = getHashI(buildhrjData(h, r[L.length - 1]), L[0])

    console.log(`c1 : ${c1} <===>  c[0]: ${c[0]}`)

    if(c1 === c[0]){
        console.log("**************************************")
        console.log("1: Signature verification successful.")
        console.log("**************************************")
    } else {
        console.log("**************************************")
        console.log("0: Failed Signature verification.")
        console.log("**************************************")
    }
}