from random import randint, choice


def make_code():
    charset = '123456789'
    code = ''
    for i in range(randint(4, 6)):
        code += choice(charset)
    return code
