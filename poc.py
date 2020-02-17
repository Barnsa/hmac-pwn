import hmac
import pwn

dmessage = str(raw_input("Enter a digest|message to grab the key:\n"))

digest  = int(dmessage.split("|")[0])
message = str(dmessage.split("|")[1]).strip()

bruted  = hmac.strToNum(pwn.cueh_brute_1(digest, message))
print("Key according to cueh_brute_1: " + str(bruted))

haxxord  = hmac.strToNum(pwn.cueh_haxxor_1(digest, message))
print("Key according to cueh_haxxor_1: " + str(haxxord))

if bruted == haxxord:
    print("Keys match")
else:
    print("Keys don't match, quitting")
    quit()

nmessage = str(raw_input("Enter a new message to sign using the key:\n"))

out = hmac.cueh_hmac_1(hmac.numToStr(haxxord), nmessage)

print("%d|%s"%(out, nmessage))

raw_input()
