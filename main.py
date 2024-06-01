# Import necessary libraries
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import numpy as np

# Penrose tiling and seed generation functions
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

def matrix_influenced_seed(tiling_matrix):
    # Flatten the matrix and convert it to a seed value
    flat_matrix = tiling_matrix.flatten()
    seed = int(hashlib.sha256(flat_matrix.tobytes()).hexdigest(), 16) % (2**32)
    return seed

# Function to hash the PIN using SHA-3 256
def hash_pin(pin):
    return hashlib.sha3_256(pin.encode()).digest()

# Function to combine entropy from PIN hash and matrix seed
def combine_entropy(pin_hash, matrix_seed):
    matrix_seed_bytes = matrix_seed.to_bytes(8, 'big')  # Convert seed to bytes
    combined_entropy = hmac.new(pin_hash, matrix_seed_bytes, hashlib.sha3_256).digest()
    return combined_entropy

# Function to generate a cryptographic key
def generate_key(pin, matrix_seed):
    pin_hash = hash_pin(pin)
    combined_entropy = combine_entropy(pin_hash, matrix_seed)
    return combined_entropy[:32]  # Use the first 256 bits for AES-256

# Encryption and decryption functions remain unchanged
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(ct, key):
    iv = ct[:AES.block_size]
    ct = ct[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# Polynomial and vector operations for Kyber
def add_poly(a, b, q):
    result = [0] * max(len(a), len(b))
    for i in range(max(len(a), len(b))):
        if i < len(a):
            result[i] += a[i]
        if i < len(b):
            result[i] += b[i]
        result[i] %= q
    return result

def inv_poly(a, q):
    return list(map(lambda x: -x % q, a))

def sub_poly(a, b, q):
    return add_poly(a, inv_poly(b, q), q)

def mul_poly_simple(a, b, f, q):
    tmp = [0] * (len(a) * 2 - 1)
    for i in range(len(a)):
        for j in range(len(b)):
            tmp[i + j] += a[i] * b[j]
    degree_f = len(f) - 1
    for i in range(degree_f, len(tmp)):
        tmp[i - degree_f] -= tmp[i]
        tmp[i] = 0
    tmp = list(map(lambda x: x % q, tmp))
    return tmp[:degree_f]

def add_vec(v0, v1, q):
    assert(len(v0) == len(v1))
    result = []
    for i in range(len(v0)):
        result.append(add_poly(v0[i], v1[i], q))
    return result

def mul_vec_simple(v0, v1, f, q):
    assert(len(v0) == len(v1))
    degree_f = len(f) - 1
    result = [0 for i in range(degree_f - 1)]
    for i in range(len(v0)):
        result = add_poly(result, mul_poly_simple(v0[i], v1[i], f, q), q)
    return result

def mul_mat_vec_simple(m, a, f, q):
    result = []
    for i in range(len(m)):
        result.append(mul_vec_simple(m[i], a, f, q))
    return result

def transpose(m):
    result = [[None for i in range(len(m))] for j in range(len(m[0]))]
    for i in range(len(m)):
        for j in range(len(m[0])):
            result[j][i] = m[i][j]
    return result

def kyber_encrypt(A, t, m_b, f, q, r, e_1, e_2):
    half_q = int(q / 2 + 0.5)
    m = list(map(lambda x: x * half_q, m_b))
    u = add_vec(mul_mat_vec_simple(transpose(A), r, f, q), e_1, q)
    v = sub_poly(add_poly(mul_vec_simple(t, r, f, q), e_2, q), m, q)
    return u, v

def kyber_decrypt(s, u, v, f, q):
    m_n = sub_poly(v, mul_vec_simple(s, u, f, q), q)
    half_q = int(q / 2 + 0.5)
    def round(val, center, bound):
        dist_center = np.abs(center - val)
        dist_bound = min(val, bound - val)
        return center if dist_center < dist_bound else 0
    m_n = list(map(lambda x: round(x, half_q, q), m_n))
    m_b = list(map(lambda x: x // half_q, m_n))
    return m_b

# Kyber key generation function
def kyber_keygen(k, f, q):
    np.random.seed(42)  # Set seed for reproducibility
    A = (np.random.random([k, k, len(f) - 1]) * q).astype(int)
    s = (np.random.random([k, len(f) - 1]) * 3).astype(int) - 1
    e = (np.random.random([k, len(f) - 1]) * 3).astype(int) - 1
    t = add_vec(mul_mat_vec_simple(A, s, f, q), e, q)
    return (A, t), s

# Kyber encapsulation function
def kyber_encapsulate(pk, f, q):
    k = len(pk[0])
    np.random.seed(42)  # Set seed for reproducibility
    r = (np.random.random([k, len(f) - 1]) * 3).astype(int) - 1
    e_1 = (np.random.random([k, len(f) - 1]) * 3).astype(int) - 1
    e_2 = (np.random.random([len(f) - 1]) * 3).astype(int) - 1
    m_b = (np.random.random(len(f) - 1) * 2).astype(int)
    u, v = kyber_encrypt(pk[0], pk[1], m_b, f, q, r, e_1, e_2)
    return (u, v), m_b

# Kyber decapsulation function
def kyber_decapsulate(sk, ct, f, q):
    return kyber_decrypt(sk, ct[0], ct[1], f, q)

# Generate Penrose tiling based seed
N = 100  # Dimension of the tiling matrix
q = 257  # Modulus used in Penrose tiling
tiling_matrix = generate_penrose_tiling(N, q)
matrix_seed = matrix_influenced_seed(tiling_matrix)

# Generate a key using PIN and matrix seed
pin = "1234"
key = generate_key(pin, matrix_seed)

# Encrypt and decrypt data example using AES
data = "Sensitive data"
encrypted_data = aes_encrypt(data, key)
decrypted_data = aes_decrypt(encrypted_data, key)

print("Original data:", data)
print("Encrypted data:", encrypted_data)
print("Decrypted data:", decrypted_data)

# Example Kyber key encapsulation and decapsulation
k = 2  # Example parameter
q = 17  # Plain modulus
f = [1, 0, 0, 0, 1]  # Polynomial modulus, x^4 + 1

# Generate Kyber key pair
pk, sk = kyber_keygen(k, f, q)

# Encapsulate to generate a shared secret and ciphertext
ct, shared_secret_sender = kyber_encapsulate(pk, f, q)

# Decapsulate to recover the shared secret
shared_secret_receiver = kyber_decapsulate(sk, ct, f, q)

# Ensure shared secrets match
assert np.array_equal(shared_secret_sender, shared_secret_receiver), "Shared secrets do not match!"

# Use the shared secret as a key for symmetric encryption
post_quantum_key = hashlib.sha3_256(bytes(shared_secret_sender)).digest()[:32]

# Encrypt and decrypt data using the post-quantum key with AES
encrypted_data_pq = aes_encrypt(data, post_quantum_key)
decrypted_data_pq = aes_decrypt(encrypted_data_pq, post_quantum_key)

print("Encrypted data with PQ key:", encrypted_data_pq)
print("Decrypted data with PQ key:", decrypted_data_pq)