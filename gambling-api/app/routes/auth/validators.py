import re


def valiate_username(username: str):
    regex = r"^[a-zA-Z\d_\$]*$"
    return bool(re.match(regex, username))
