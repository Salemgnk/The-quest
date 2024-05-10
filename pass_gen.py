import string
import random

specials = "~#{([_-@]*!£$;,:/?)}"

def pass_gen():
    lenght = random.randint(8, 12)
    char = string.ascii_letters + string.digits + specials
    mdp = ''.join(random.sample(char, lenght))
    return mdp

def pass_checker(input):
    special = False
    upper = False
    lenght = False

    if len(input) < 8:
        print("Your password is too short")
    else:
        lenght = True
    for i in input:
        for j in specials:
            if i == j:
                special = True
        if i.isupper():
            upper = True
    if special == True and upper == True and lenght == True:
        return 1
    else:
        return 1
