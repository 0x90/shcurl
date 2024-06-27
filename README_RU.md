# SHCurl

SHCurl - это небольшая утилита для организации обратного шелла с сервера/ноутбука/устройства.

Полезна при эксплуатации уязвимостей вида внедрения команд на устройствах блокирующих исходящий трафик отличный от DNS/HTTP(S).

Требования: 
- установлена команда curl
- установлена команда base64 (опционально)


## Установка 

Установка зависимостей:

```
git clone https://github.com/0x90/shcurl
cd shcurl
pip install -r requirements.txt
```

Установка пакета

```
pip install https://github.com/0x90/shcurl#egg=shcurl
```

Установка пакета в режиме для разработчика

```
pip install https://github.com/0x90/shcurl#egg=shcurl
```

## Использование


Генерация ключа для HTTPS сервера:
```
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

Примеры использования

```
python shcurl.py -i <SERVER_IP> -p [SERVER_IP] -c [CERIFICICATE_PATH]
```
