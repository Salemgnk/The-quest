import os
import time


def password(input):
    file_path = "./password"

    with open(file_path, "w") as file:
        file.write(input)
    time.sleep(60)
    os.remove(file_path)
    
