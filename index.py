from flask import Flask, request, jsonify
import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from protobuf_decoder.protobuf_decoder import Parser
import codecs
import time
from datetime import datetime
import urllib3
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th", 
    "BD": "bn", "PK": "ur", "TW": "zh", "EU": "en", "CIS": "ru", 
    "NA": "en", "SAC": "es", "BR": "pt", "SG": "en"
}

def get_server_repo_info(server_name):
    server_name = server_name.upper()
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/"
    else:
        return "https://clientbp.ggblueshark.com/"

hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
encryption_key = bytes.fromhex(hex_key)

class AccountGenerator:
    @staticmethod
    def encode_varint(value):
        if value < 0:
            return b''
        encoded_bytes = []
        while True:
            byte_val = value & 0x7F
            value >>= 7
            if value:
                byte_val |= 0x80
            encoded_bytes.append(byte_val)
            if not value:
                break
        return bytes(encoded_bytes)

    @staticmethod
    def decode_varint(hex_string):
        value = shift = 0
        for byte_val in bytes.fromhex(hex_string):
            value |= (byte_val & 0x7F) << shift
            if not byte_val & 0x80:
                break
            shift += 7
        return value

    @staticmethod
    def create_variant_field(field_number, value):
        field_header = (field_number << 3) | 0
        return AccountGenerator.encode_varint(field_header) + AccountGenerator.encode_varint(value)

    @staticmethod
    def create_length_field(field_number, value):
        field_header = (field_number << 3) | 2
        encoded_value = value.encode() if isinstance(value, str) else value
        return AccountGenerator.encode_varint(field_header) + AccountGenerator.encode_varint(len(encoded_value)) + encoded_value

    @staticmethod
    def create_protobuf_message(fields):
        packet = bytearray()
        for field_num, field_value in fields.items():
            if isinstance(field_value, dict):
                nested_packet = AccountGenerator.create_protobuf_message(field_value)
                packet.extend(AccountGenerator.create_length_field(field_num, nested_packet))
            elif isinstance(field_value, int):
                packet.extend(AccountGenerator.create_variant_field(field_num, field_value))
            elif isinstance(field_value, (str, bytes)):
                packet.extend(AccountGenerator.create_length_field(field_num, field_value))
        return packet

    @staticmethod
    def aes_encrypt(plaintext_hex):
        plaintext_bytes = bytes.fromhex(plaintext_hex)
        aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        aes_iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        encrypted_data = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        return bytes.fromhex(encrypted_data.hex())

    @staticmethod
    def generate_random_username():
        characters = string.ascii_uppercase + string.digits
        return ''.join(random.choice(characters) for _ in range(12))

    @staticmethod
    def generate_secure_password():
        characters = string.ascii_uppercase + string.digits
        return ''.join(random.choice(characters) for _ in range(64))

    @staticmethod
    def get_random_region():
        regions = list(REGION_LANG.keys())
        return random.choice(regions)

class FreeFireAPI:
    def __init__(self):
        self.account_generator = AccountGenerator()

    def get_region_language(self, region_code):
        return REGION_LANG.get(region_code.upper())

    def create_guest_account(self, region=None, custom_name=None, custom_password=None):
        try:
            # Handle null values
            if region == "null" or not region:
                region = self.account_generator.get_random_region()
            
            if custom_name == "null" or not custom_name:
                custom_name = self.account_generator.generate_random_username()
            
            if custom_password == "null" or not custom_password:
                custom_password = self.account_generator.generate_secure_password()
            
            password = custom_password
            
            registration_data = f"password={password}&client_type=2&source=2&app_id=100067"
            message = registration_data.encode('utf-8')
            signature = hmac.new(encryption_key, message, hashlib.sha256).hexdigest()

            registration_headers = {
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
                "Authorization": "Signature " + signature,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive"
            }

            registration_response = requests.post(
                "https://ffmconnect.live.gop.garenanow.com/oauth/guest/register",
                headers=registration_headers,
                data=registration_data
            )
            
            user_id = registration_response.json()['uid']
            return self.obtain_access_token(user_id, password, region, custom_name, user_id)
            
        except Exception as error:
            return self.create_guest_account(region, custom_name, custom_password)

    def obtain_access_token(self, user_id, password, region, custom_name, guest_uid):
        token_headers = {
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "ffmconnect.live.gop.garenanow.com",
            "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
        }

        token_payload = {
            "uid": user_id,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": encryption_key,
            "client_id": "100067"
        }

        token_response = requests.post(
            "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant",
            headers=token_headers,
            data=token_payload
        )
        
        open_id = token_response.json()['open_id']
        access_token = token_response.json()["access_token"]
        encoded_field = self.encode_open_id(open_id)
        processed_field = codecs.decode(encoded_field, 'unicode_escape').encode('latin1')
        
        return self.register_account(access_token, open_id, processed_field, user_id, password, region, custom_name, guest_uid)

    def encode_open_id(self, original_string):
        keystream = [
            0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31,
            0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30
        ]
        
        encoded_result = ""
        for index, character in enumerate(original_string):
            original_byte = ord(character)
            key_byte = keystream[index % len(keystream)]
            result_byte = original_byte ^ key_byte
            encoded_result += chr(result_byte)
            
        return self.convert_to_unicode_escape(encoded_result)

    def convert_to_unicode_escape(self, input_string):
        return ''.join(
            char if 32 <= ord(char) <= 126 else f'\\u{ord(char):04x}'
            for char in input_string
        )

    def register_account(self, access_token, open_id, encoded_field, user_id, password, region, custom_name, guest_uid):
        username = custom_name
        
        registration_headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": "loginbp.ggblueshark.com",
            "ReleaseVersion": "OB51",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4."
        }

        registration_payload = {
            1: username,
            2: access_token,
            3: open_id,
            5: 102000007,
            6: 4,
            7: 1,
            13: 1,
            14: encoded_field,
            15: "en",
            16: 1,
            17: 1
        }

        protobuf_data = self.account_generator.create_protobuf_message(registration_payload).hex()
        encrypted_payload = self.account_generator.aes_encrypt(protobuf_data).hex()
        
        registration_response = requests.post(
            "https://loginbp.ggblueshark.com/MajorRegister",
            headers=registration_headers,
            data=bytes.fromhex(encrypted_payload),
            verify=False
        )
        
        return self.authenticate_user(user_id, password, access_token, open_id, registration_response.status_code, username, region, guest_uid)

    def encrypt_payload(self, plaintext_hex):
        plaintext_bytes = bytes.fromhex(plaintext_hex)
        aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        aes_iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        return ciphertext.hex()

    def authenticate_user(self, user_id, password, access_token, open_id, status_code, username, region, guest_uid):
        region_language = self.get_region_language(region)
        language_bytes = region_language.encode("ascii") if region_language else b'en'

        auth_headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": "loginbp.ggblueshark.com",
            "ReleaseVersion": "OB51",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1"
        }

        auth_payload = (
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02' +
            language_bytes +
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        )
        
        processed_payload = auth_payload.replace(
            b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390',
            access_token.encode()
        ).replace(
            b'1d8ec0240ede109973f3321b9354b44d',
            open_id.encode()
        )
        
        encrypted_data = self.encrypt_payload(processed_payload.hex())
        final_payload = bytes.fromhex(encrypted_data)
        
        login_url = (
            "https://loginbp.ggblueshark.com/MajorLogin"
        )
        
        auth_response = requests.post(login_url, headers=auth_headers, data=final_payload, verify=False)
        
        if auth_response.status_code != 200 or len(auth_response.text) < 10:
            return {"success": False, "error": "Authentication failed"}

        if region_language and region_language.lower() not in ["ar", "en"]:
            available_rooms = self.parse_available_rooms(auth_response.content.hex())
            parsed_data = json.loads(available_rooms)
            jwt_token = parsed_data['8']['data']
            
            if region.lower() == "cis":
                region = "RU"
                
            region_fields = {1: region}
            region_payload = bytes.fromhex(self.encrypt_payload(
                self.account_generator.create_protobuf_message(region_fields).hex()
            ))
            
            region_status = self.select_region(region_payload, jwt_token)
            if region_status == 200:
                return self.authenticate_user_secondary(user_id, password, access_token, open_id, status_code, username, region, guest_uid)
        else:
            jwt_token = auth_response.text[auth_response.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]

        second_dot_position = jwt_token.find(".", jwt_token.find(".") + 1)
        time.sleep(0.2)
        jwt_token = jwt_token[:second_dot_position + 44]
        
        return self.process_authentication_data(jwt_token, access_token, user_id, password, username, region, guest_uid)

    def select_region(self, payload_data, jwt_token):
        region_headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'Authorization': f"Bearer {jwt_token}",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB51"
        }
        
        region_response = requests.post(
            "https://loginbp.ggblueshark.com/ChooseRegion",
            data=payload_data,
            headers=region_headers,
            verify=False
        )
        return region_response.status_code

    def authenticate_user_secondary(self, user_id, password, access_token, open_id, status_code, username, region, guest_uid):
        region_language = self.get_region_language(region)
        language_bytes = region_language.encode("ascii") if region_language else b'en'

        auth_headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": "loginbp.ggblueshark.com",
            "ReleaseVersion": "OB51",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1"
        }

        auth_payload = (
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02' +
            language_bytes +
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        )
        
        processed_payload = auth_payload.replace(
            b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390',
            access_token.encode()
        ).replace(
            b'1d8ec0240ede109973f3321b9354b44d',
            open_id.encode()
        )
        
        encrypted_data = self.encrypt_payload(processed_payload.hex())
        final_payload = bytes.fromhex(encrypted_data)
        
        login_url = (
            "https://loginbp.ggblueshark.com/MajorLogin"
        )
        
        auth_response = requests.post(login_url, headers=auth_headers, data=final_payload, verify=False)
        
        if auth_response.status_code != 200 or len(auth_response.text) < 10:
            return {"success": False, "error": "Secondary authentication failed"}

        available_rooms = self.parse_available_rooms(auth_response.content.hex())
        parsed_data = json.loads(available_rooms)
        jwt_token = parsed_data['8']['data']

        second_dot_position = jwt_token.find(".", jwt_token.find(".") + 1)
        time.sleep(0.2)
        jwt_token = jwt_token[:second_dot_position + 44]
        
        return self.process_authentication_data(jwt_token, access_token, user_id, password, username, region, guest_uid)

    def process_authentication_data(self, jwt_token, access_token, user_id, password, username, region, guest_uid):
        try:
            token_parts = jwt_token.split('.')
            token_payload_base64 = token_parts[1]
            token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
            decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
            payload_data = json.loads(decoded_payload)
            
            account_id = payload_data.get('account_id', user_id)
            
            return {
                "success": True,
                "account_region": region,
                "account_token": jwt_token,
                "account_uid": account_id,
                "guest_password": password,
                "guest_uid": guest_uid,  # Yahan registration wala UID use karo
                "nickname": username
            }
        except Exception as error:
            return {"success": False, "error": f"Authentication processing failed: {str(error)}"}

    def parse_protobuf_results(self, parsed_results):
        result_dict = {}
        for result in parsed_results:
            field_info = {'wire_type': result.wire_type}
            if result.wire_type == "varint":
                field_info['data'] = result.data
            elif result.wire_type in ["string", "bytes"]:
                field_info['data'] = result.data
            elif result.wire_type == 'length_delimited':
                field_info["data"] = self.parse_protobuf_results(result.data.results)
            result_dict[result.field] = field_info
        return result_dict

    def parse_available_rooms(self, input_data):
        try:
            parsed_results = Parser().parse(input_data)
            parsed_dict = self.parse_protobuf_results(parsed_results)
            return json.dumps(parsed_dict)
        except Exception as error:
            print(f"Parsing error: {error}")
            return None

freefire_api = FreeFireAPI()

@app.route('/guest/<name>/<region>/<password>')
def create_account_custom(name, region, password):
    # Handle null values by passing them as is
    try:
        account_result = freefire_api.create_guest_account(region, name, password)
        
        if account_result and account_result.get('success', True):
            return jsonify({
                "success": True,
                "account_region": account_result.get('account_region'),
                "account_token": account_result.get('account_token'),
                "account_uid": account_result.get('account_uid'),
                "guest_password": account_result.get('guest_password'),
                "guest_uid": account_result.get('guest_uid'),
                "nickname": account_result.get('nickname')
            })
        else:
            return jsonify({
                "success": False,
                "error": account_result.get('error', 'Account creation failed')
            }), 500
            
    except Exception as error:
        return jsonify({
            "success": False,
            "error": f"Internal server error: {str(error)}"
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860, debug=False)
