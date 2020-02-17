import hmac

def cueh_brute_1(num, msg):
    """
    Input the final key and message
    This function returns a key which generates the same number
    Brute force
    """
    num = int(num)  # make sure we have an int as the digest
    msg = str(msg)  # make sure we have a str as the message
    for i in range(0, 65537):   # there's a total of 65536 possible keys
        testKey  = hmac.numToStr(i) # turn i (loop iterator) into a "test key"
        testSign = hmac.cueh_hmac_1(testKey, msg) # sign message using "test key"
        if testSign == num: # if the newly signed message has the same digest as the original
            return testKey  # return the key which can be used to sign a new message

def cueh_haxxor_1(num, msg):
    """
    Input the final key and message
    This function returns a key which generates the same number
    Reverse XOR
    """
    num = int(num)  # make sure we have an int as the digest
    msg = str(msg)  # make sure we have a str as the message
    if len(msg)%2 != 0: msg+=" "    # if message isn't even, pad it with a space
    msg = msg[::-1] # reverse the message
    for pos in range(0, len(msg), 2):   # almost exact same XOR process as in cueh_hash_1(), the reverse of XOR is still XOR
        i = msg[pos]
        j = msg[pos + 1]
        num ^= ord(j)   # only difference in the loop, switched i and j, since we're reversing the XOR
        num ^= (ord(i) << 8)
    return hmac.numToStr(num)[::-1] # since the endresult is reversed, flip it again
