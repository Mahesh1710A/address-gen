from flask import Flask, request, jsonify, render_template
import hashlib
import codecs
import ecdsa
import base58
from functools import lru_cache

app = Flask(__name__)

@lru_cache
def to_64_digit_hex(number):
    hex_number = hex(number)[2:]  # Convert the number to hexadecimal, remove '0x'
    return hex_number.zfill(64)  # Pad with leading zeros to ensure it's 64 digits long
#Original

def generate_bitcoin_address(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    public_key_raw = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    public_key_bytes = public_key_raw.to_string()
    public_key_hex = codecs.encode(public_key_bytes, 'hex')
    public_key = (b'04' + public_key_hex).decode("utf-8")

    if (ord(bytearray.fromhex(public_key[-2:])) % 2 == 0):
        public_key_compressed = '02'
    else:
        public_key_compressed = '03'
    
    public_key_compressed += public_key[2:66]
    hex_str = bytearray.fromhex(public_key_compressed)
    sha = hashlib.sha256()
    sha.update(hex_str)
    
    rip = hashlib.new('ripemd160')
    rip.update(sha.digest())
    key_hash = rip.hexdigest()
    modified_key_hash = "00" + key_hash
    
    sha = hashlib.sha256()
    hex_str = bytearray.fromhex(modified_key_hash)
    sha.update(hex_str)
    
    sha_2 = hashlib.sha256()
    sha_2.update(sha.digest())
    checksum = sha_2.hexdigest()[:8]
    
    byte_25_address = modified_key_hash + checksum
    address = base58.b58encode(bytes(bytearray.fromhex(byte_25_address))).decode('utf-8')
    
    return address

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['GET'])
def generate():
    range_value = request.args.get('range', '1:10000')
    start, end = map(lambda x: int(x, 16), range_value.split(':'))
    target_address = request.args.get('targetAddress', '').strip()

    addresses = []
    for number in range(start, end + 1):
        private_key = to_64_digit_hex(number)
        address = generate_bitcoin_address(private_key)
        if target_address and address == target_address:
            return jsonify({"match": {"private_key": private_key, "address": address}})
        addresses.append({'private_key': private_key, 'address': address})
    
    return jsonify(addresses)

if __name__ == '__main__':
    app.run(debug=True)
