'''
Information sending protocol between Voter, Official, and Machine.
Currently a work-in-progress

LEGEND:
    V: Voter
    O: Official
    M: Machine
    I: Voter information (Unique identifiers)
    B: Voter ballot

    E_x(y): Message y encrypted with x's public key
    S_x(y): Message y signed by x
    SHA256(y): Message y hash by SHA256 

V -----> O
    E_O {
        I + S_v(I) + E_m(S_v(SHA256(B))) + E_m(SHA256(B))
    }

O -----> M
    E_M {
        S_o(E_m(S_v(SHA256(B)))) + E_m(S_v(SHA256(B)))
    }
V -----> M
    E_m(B)

M:
    E_m(B) + S_o(E_m(S_v(SHA256(B))))

    |
    V

    B + S_o(S_v(SHA256(B))) check if 

'''
import rsa
import hashlib

#generate voter, official, and machine keys
(Vpubkey, Vprivkey) = rsa.newkeys(512)
(Opubkey, Oprivkey) = rsa.newkeys(512)
(Mpubkey, Mprivkey) = rsa.newkeys(512)

def voterSendToOfficial(UID, vote, vPrivKey, mPubKey, oPubKey):
    '''
    Generates an encrypted message to send to an official containing:
        -The Voter's unique identifying information
        -The Voter's ballot, encrypted with mPubKey

    Returns a list of the following items encrypted with the official's public
    key:
        -Unique Identifiers
        -Signed identifiers, broken into 2 parts to get around encryption size limits
        -Hashed ballot, split into 4 parts
        -Signed hashed ballot
    '''
    #hash ballot, sign info and ballot, encrypt ballot with machine key, send msg
    hashballot = hashlib.sha512(vote).hexdigest()
    siginfo = rsa.sign(UID, vPrivKey, 'MD5')
    sigballot = rsa.sign(hashballot, vPrivKey, 'MD5')

    #split the ballot up because it's too damn big to encrypt
    machineballot1 = rsa.encrypt(sigballot[0:len(sigballot)/2], mPubKey)
    machineballot2 = rsa.encrypt(sigballot[len(sigballot)/2:], mPubKey)

    #now this has to be split and sent in smaller packets to the official
    #I + S_v(I) + E_m(S_v(SHA256(B)))
    sigi1, sigi2 = siginfo[0:len(siginfo)/2], siginfo[len(siginfo)/2:]
    mb11, mb12 = machineballot1[:len(machineballot1)/2], machineballot1[len(machineballot1)/2:]
    mb21, mb22 = machineballot2[:len(machineballot2)/2], machineballot2[len(machineballot2)/2:]

    #list of items to encrypt and send to official
    toOfficial = [UID, sigi1, sigi2, mb11, mb12, mb21, mb22]

    #encrypt each item individually and send to official
    officialInbox = []
    for msg in toOfficial:
        enc = rsa.encrypt(msg, oPubKey)
        officialInbox.append(enc)
    return officialInbox

OIB = voterSendToOfficial("Marty McFly", "Candidate A", Vprivkey, Mpubkey, Opubkey)
print "official inbox:",OIB

