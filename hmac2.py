megaBlockSize=128
def strToNum(inp):
    """Takes a sequence of bytes and makes a number"""
    out=0
    for i in inp:
        out=out<<8
        out^=ord(i)
    return out
def numToStr(inp):
    """Take a number and make a sequence of bytes in a string"""
    out=""
    while inp!=0:
        out=chr(inp & 255)+out
        inp=inp>>8
    return out

def cueh_hash_2(inp, blockSize):
    """ CUEH Hash Function v 2.0 
    Returns given-length hash of any string input or stringable input
    Uses given number of bits, must be multiple of 8
    """
    if blockSize%8!=0 or blockSize<=0:
        raise Exception("Block size must be a multiple of 8")
    inp=str(inp) #Make sure we have a string
    while (len(inp)%(blockSize/8)!=0):
        inp=" "+inp #Pad it if we need to
    val=0<<blockSize #Our accumulator
    for pos in range(0,len(inp),blockSize/8): #Now in blocks of the rigth size...
        for pos2 in range(blockSize/8):
            tval=ord(inp[pos2+pos])
            tval=tval<<(blockSize-pos2*8)
            val=val^tval
    return val

def cueh_hmac_2(key, message, blockSize):
    """Outputs a hash-based digest of the message and secret key combo"""
    key=str(key)
    message=str(message)
    if len(key)>blockSize/8:
        key=numToStr(cueh_hash_2(key,blockSize)) #Keys are shortened to blocksize
    while len(key)<blockSize/8:
        key+="#" #Keys are padded with spaces if they're too short
    return cueh_hash_2(key+message,blockSize)


def main():
    print "Testing hash: %06x"%cueh_hash_2("ABC\0\0\0",megaBlockSize)

    #Examples of flipping between numbers and strings of bytes
    #Just makes it easier to have "password" style keys
    print "%x"%strToNum("ABC")
    print numToStr((65<<16) + (66<<8) + 67)

    #Now to see it in practice
    secretKey="sswrodfishez"  #This is known by both parties
    authedMessage="ssdsdsdsdsd"

    
    out=cueh_hmac_2(secretKey,authedMessage, megaBlockSize)
    #Now we have the special verification code that can be used to
    #prove we were the aithor of the message. Anyone else who knows
    #the secret can do the same and compare the values
    dispString="0x%%0%dx|%%s"%(megaBlockSize/16)
    print dispString%(out, authedMessage)


 
    
if __name__ == '__main__':
    main()