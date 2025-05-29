from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
from flask_cors import CORS
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)
CORS(app)  # Habilita CORS

def load_tokens(server_name):
    try:
        print(f"Carregando tokens para o servidor: {server_name}")
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        print(f"Tokens carregados: {len(tokens)}")
        return tokens
    except Exception as e:
        print(f"Erro ao carregar tokens: {e}")
        return None

def encrypt_message(plaintext):
    try:
        print("Criptografando mensagem...")
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        hexed = binascii.hexlify(encrypted_message).decode('utf-8')
        print(f"Mensagem criptografada (hex): {hexed}")
        return hexed
    except Exception as e:
        print(f"Erro na criptografia: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        print(f"Criando Protobuf para Like - UID: {user_id}, Região: {region}")
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        serialized = message.SerializeToString()
        print(f"Protobuf serializado (like): {binascii.hexlify(serialized)}")
        return serialized
    except Exception as e:
        print(f"Erro ao criar protobuf de like: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        print(f"Enviando requisição para {url} com token: {token[:10]}...")  # parcial para segurança
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                print(f"Resposta HTTP status: {response.status}")
                if response.status != 200:
                    return response.status
                return await response.text()
    except Exception as e:
        print(f"Erro em send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        print(f"Iniciando múltiplos envios de like para UID: {uid}")
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            print("Falha ao criar mensagem protobuf.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            print("Falha na criptografia do protobuf.")
            return None
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None:
            print("Falha ao carregar tokens.")
            return None
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        print("Requisições concluídas.")
        return results
    except Exception as e:
        print(f"Erro geral em send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        print(f"Criando protobuf para UID Generator: {uid}")
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        serialized = message.SerializeToString()
        print(f"Protobuf UID Generator serializado: {binascii.hexlify(serialized)}")
        return serialized
    except Exception as e:
        print(f"Erro ao criar protobuf do UID: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)

def make_request(encrypt, server_name, token):
    try:
        print(f"Fazendo requisição para obter dados do jogador...")
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        print(f"Resposta recebida com tamanho: {len(response.content)} bytes")
        binary = response.content
        return decode_protobuf(binary)
    except Exception as e:
        print(f"Erro em make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        print("Decodificando dados do protobuf...")
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        print(f"Erro ao decodificar Protobuf: {e}")
        return None
    except Exception as e:
        print(f"Erro inesperado ao decodificar: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        def process_request():
            print(f"Processando request para UID: {uid} no servidor: {server_name}")
            tokens = load_tokens(server_name)
            if tokens is None:
                raise Exception("Erro ao carregar tokens")
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Erro ao criptografar UID")

            before = make_request(encrypted_uid, server_name, token)
            if before is None:
                raise Exception("Erro ao obter dados do jogador antes dos likes")
            data_before = json.loads(MessageToJson(before))
            before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0))
            print(f"Likes antes: {before_like}")

            # Determina URL de like
            if server_name == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            asyncio.run(send_multiple_requests(uid, server_name, url))

            after = make_request(encrypted_uid, server_name, token)
            if after is None:
                raise Exception("Erro ao obter dados do jogador depois dos likes")
            data_after = json.loads(MessageToJson(after))
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            print(f"Likes depois: {after_like}, Likes dados: {like_given}")

            return {
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": 1 if like_given != 0 else 2
            }

        result = process_request()
        return jsonify(result)
    except Exception as e:
        print(f"Erro no endpoint /like: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("Servidor iniciado em http://0.0.0.0:10000")
    app.run(host="0.0.0.0", port=10000)
