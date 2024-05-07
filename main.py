import argparse
import zipfile
import os
import numpy as np
from scipy.ndimage import rotate
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

PUBLIC_KEY_FILE = "public_key.pem"
PRIVATE_KEY_FILE = "private_key.pem"

def generate_penrose_tiling(N, q):
    def point_inside_polygon(x, y, poly):
        n = len(poly)
        inside = False
        p1x, p1y = poly[0]
        for i in range(n + 1):
            p2x, p2y = poly[i % n]
            if y > min(p1y, p2y):
                if y <= max(p1y, p2y):
                    if x <= max(p1x, p2x):
                        if p1y != p2y:
                            xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                        if p1x == p2x or x <= xinters:
                            inside = not inside
            p1x, p1y = p2x, p2y
        return inside

    def draw_line(x1, y1, x2, y2):
        points = []
        num_points = max(abs(x2 - x1), abs(y2 - y1)) + 1
        for i in range(num_points):
            x = int(x1 + (i / num_points) * (x2 - x1))
            y = int(y1 + (i / num_points) * (y2 - y1))
            points.append((x, y))
        return points

    def draw_rhombus(x, y, side_length, angle):
        rhombus_points = []
        for i, j in [(0, 0), (1, 0), (1, 1), (0, 1)]:
            rotated_x = x + i * side_length
            rotated_y = y + j * side_length
            rotated_x, rotated_y = (rotated_x - x) * np.cos(angle) - (rotated_y - y) * np.sin(angle) + x, \
                                   (rotated_x - x) * np.sin(angle) + (rotated_y - y) * np.cos(angle) + y
            rhombus_points.append((rotated_x, rotated_y))
        return rhombus_points

    def is_valid_point(x, y):
        center_x, center_y = N / 2, N / 2
        radius = N / 2
        return (x - center_x) ** 2 + (y - center_y) ** 2 <= radius ** 2

    tiling = np.zeros((N, N), dtype=np.float64)
    indices = np.meshgrid(np.arange(N), np.arange(N))
    tiling[(indices[0] + indices[1]) % 2 == 0] = 1
    rotated_tiling = rotate(tiling, angle=36, reshape=False, mode='reflect')

    phi = (1 + np.sqrt(5)) / 2  # Golden ratio
    side_length = 1
    for i in range(-N, N):
        for j in range(-N, N):
            if point_inside_polygon(i * phi, j * phi, [(0, 0), (-1, -phi), (-phi, -1), (0, -2), (phi, -1), (1, -phi)]):
                line_points = draw_line(int(i * phi), int(j * phi), int((i + 1) * phi), int(j * phi))
                for p1, p2 in zip(line_points[:-1], line_points[1:]):
                    if is_valid_point(p1[0], p1[1]) and is_valid_point(p2[0], p2[1]):
                        rotated_tiling[int(p1[0]), int(p1[1])] = 1
                        rotated_tiling[int(p2[0]), int(p2[1])] = 1
                line_points = draw_line(int((i + 1) * phi), int(j * phi), int(i * phi), int((j + 1) * phi))
                for p1, p2 in zip(line_points[:-1], line_points[1:]):
                    if is_valid_point(p1[0], p1[1]) and is_valid_point(p2[0], p2[1]):
                        rotated_tiling[int(p1[0]), int(p1[1])] = 1
                        rotated_tiling[int(p2[0]), int(p2[1])] = 1
                rhombus_points = draw_rhombus(int(i * phi), int(j * phi), side_length, np.pi / 5)
                for p1, p2, p3, p4 in zip(rhombus_points[:-1], rhombus_points[1:], rhombus_points[2:], rhombus_points[3:] + [rhombus_points[0]]):
                    if is_valid_point(p1[0], p1[1]) and is_valid_point(p2[0], p2[1]) \
                            and is_valid_point(p3[0], p3[1]) and is_valid_point(p4[0], p4[1]):
                        rotated_tiling[int(p1[0]), int(p1[1])] = 1
                        rotated_tiling[int(p2[0]), int(p2[1])] = 1
                        rotated_tiling[int(p3[0]), int(p3[1])] = 1
                        rotated_tiling[int(p4[0]), int(p4[1])] = 1

    min_val, max_val = rotated_tiling.min(), rotated_tiling.max()
    normalized_tiling = (rotated_tiling - min_val) / (max_val - min_val)
    scaled_tiling = np.floor(normalized_tiling * (np.iinfo(np.int64).max / (q - 1)))
    scaled_tiling = scaled_tiling.astype(np.int64) % q
    return scaled_tiling

def matrix_influenced_random_bytes(tiling_matrix):
    # Buffer a large amount of random bytes and use these in the custom random function.
    def random_bytes(k):
        # Buffer size could be larger depending on performance needs
        random_buffer = get_random_bytes(k * 10)
        bytes_out = bytearray(k)
        for i in range(k):
            buffer_index = i % len(random_buffer)
            random_index = np.random.randint(0, tiling_matrix.size)
            matrix_value = tiling_matrix.flat[random_index] % 256
            # Mixing buffered random byte and matrix value
            bytes_out[i] = (random_buffer[buffer_index] + matrix_value) & 0xFF
        return bytes(bytes_out)
    return random_bytes

def generate_rsa_keys(N, tiling_matrix):
    # Use a custom random function influenced by the matrix
    custom_random = matrix_influenced_random_bytes(tiling_matrix)
    key = RSA.generate(N, randfunc=custom_random)
    return key

def generate_and_save_keys(N, tiling_matrix):
    """Generate RSA keys and save them to files if they don't exist."""
    if not os.path.exists(PUBLIC_KEY_FILE) or not os.path.exists(PRIVATE_KEY_FILE):
        print("Generating new RSA key pair...")
        key_pair = generate_rsa_keys(N, tiling_matrix)
        with open(PUBLIC_KEY_FILE, 'wb') as pub_file:
            pub_file.write(key_pair.publickey().export_key())
        with open(PRIVATE_KEY_FILE, 'wb') as priv_file:
            priv_file.write(key_pair.export_key())
        print(f"Keys saved: {PUBLIC_KEY_FILE}, {PRIVATE_KEY_FILE}")

def load_keys():
    """Load RSA keys from the files."""
    with open(PUBLIC_KEY_FILE, 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())
    with open(PRIVATE_KEY_FILE, 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())
    return public_key, private_key

def encrypt_message(message_bytes, public_key):
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message_bytes)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    return enc_session_key, cipher_aes.nonce, tag, ciphertext

def compress_encrypt_file(file_path, public_key, compression_level=9):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    enc_session_key, nonce, tag, encrypted_data = encrypt_message(file_data, public_key)
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as file:
        file.write(enc_session_key)
        file.write(nonce)
        file.write(tag)
        file.write(encrypted_data)
    zip_file_path = file_path + '.zip'
    with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=compression_level) as zipf:
        zipf.write(encrypted_file_path, os.path.basename(encrypted_file_path))
    os.remove(encrypted_file_path)
    print(f"Encrypted and compressed file saved as {zip_file_path}")

def decrypt_message(encrypted_data, private_key):
    enc_session_key, nonce, tag, ciphertext = encrypted_data
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext

def decrypt_uncompress_file(zip_file_path, private_key):
    with zipfile.ZipFile(zip_file_path, 'r') as zipf:
        encrypted_files = zipf.namelist()
        if not encrypted_files:
            raise ValueError("No files found in the provided archive.")
        encrypted_file_name = encrypted_files[0]
        zipf.extract(encrypted_file_name)
    with open(encrypted_file_name, 'rb') as file:
        enc_session_key = file.read(private_key.size_in_bytes())
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()
    os.remove(encrypted_file_name)
    encrypted_data = (enc_session_key, nonce, tag, ciphertext)
    decrypted_data = decrypt_message(encrypted_data, private_key)
    output_file_path = zip_file_path.replace('.zip', '')
    with open(output_file_path, 'wb') as output_file:
        output_file.write(decrypted_data)
    print(f"Decrypted file saved as {output_file_path}")

def main():
    parser = argparse.ArgumentParser(description="Encrypt and compress a file, or decrypt and decompress a file")
    parser.add_argument("file_path", help="The path of the file to be processed")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt and compress the file")
    group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt and decompress the file")
    args = parser.parse_args()

    N = 2048
    q = 10
    tiling_matrix = generate_penrose_tiling(64, q)

    # Generate keys if they don't exist
    generate_and_save_keys(N, tiling_matrix)

    # Load public and private keys
    public_key, private_key = load_keys()

    if args.encrypt:
        compress_encrypt_file(args.file_path, public_key)
    elif args.decrypt:
        decrypt_uncompress_file(args.file_path, private_key)

if __name__ == "__main__":
    main()
