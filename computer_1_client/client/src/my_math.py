
# math.ceil and math.floor don't work for large integers

def floor(a, b):
    return a // b

def ceil(a, b):
    return a // b + (a % b > 0)

def str_hex_to_int(s):
    return int(s, 16)