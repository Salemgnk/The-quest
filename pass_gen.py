import string
import random

specials = "~#{([_-@]*!£$;,:/?)}"

def pass_gen():
    lenght = random.randint(8, 12)
    char = string.ascii_letters + string.digits + specials
    mdp = ''.join(random.sample(char, lenght))
    print(mdp)
    return mdp

