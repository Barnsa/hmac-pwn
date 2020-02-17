import hmac

def cueh_brute_1(num, msg):
    """
    Input the final key and message
    This function returns a key which generates the same number
    Brute force
    """
    num = int(num)
    msg = str(msg)
    for i in range(0, 65537):
        testKey  = hmac.numToStr(i)
        testSign = hmac.cueh_hmac_1(testKey, msg)
        if testSign == num:
            return testKey

def cueh_haxxor_1(num, msg):
    """
    Input the final key and message
    This function returns a key which generates the same number
    Reverse XOR
    """
    msg = str(msg)
    if len(msg)%2 != 0: msg+=" "
    msg = msg[::-1]
    for pos in range(0, len(msg), 2):
        i = msg[pos]
        j = msg[pos + 1]
        num ^= ord(j)
        num ^= (ord(i) << 8)
    return hmac.numToStr(num)[::-1]
