hmac_blocksize=16
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
def cueh_hash_1(inp):
    """ CUEH Hash Function v 1.0 
    Returns 16 bit hash of any string input or stringable input
    """
    inp=str(inp) #Make sure we have a string
    if len(inp)%2!=0: inp+=" " #Pad it if we need to
    val=0 #Our accumulator
    for pos in range(0,len(inp),2): #Now in twos...
        i=inp[pos]
        j=inp[pos+1]
        # print "\tEncoding",i,j
        val^=ord(i)  #XOR first char onto lowest 8 bits
        val^=(ord(j)<<8)  #and second char onto highest 8 bits
    #     print "\t\t",val
    # print "\t",val
    return val

def cueh_hmac_1(key, message):
    """Outputs a hash-based digest of the message and secret key combo"""
    key=str(key)
    message=str(message)
    if len(key)>hmac_blocksize/8:
        key=numToStr(cueh_hash_1(key)) #Keys are shortened to blocksize
    while len(key)<hmac_blocksize/8:
        key+=" " #Keys are padded with spaces if they're too short
    # print "0x%x"%cueh_hash_1(key+message) 
    return cueh_hash_1(key+message)
    
if __name__=="__main__":
    print "-"*20
    #Examples of flipping between numbers and strings of bytes
    #Just makes it easier to have "password" style keys
    print "%x"%strToNum("ABC")
    print numToStr((65<<16) + (66<<8) + 67)

    #Now to see it in practice
    secretKey="cCAA"  #This is known by both parties
    authedMessage="This is a test of the emergency broadcast system."

    
    out=cueh_hmac_1(secretKey,authedMessage)
    #Now we have the special verification code that can be used to
    #prove we were the aithor of the message. Anyone else who knows
    #the secret can do the same and compare the values    
    print "%d|%s"%(out, authedMessage)