# Penrose Tiling Encryption

This Python script allows you to encrypt and compress files using a Penrose tiling-based encryption method. It also provides functionality to decrypt and decompress encrypted files.

## Installation

1. Clone this repository or download the `penrose_tiling_encryption.py` script.
2. Install the required dependencies using pip:

```bash
pip install -r requirements.txt
```

## Usage
### Encrypt and Compress a File
To encrypt and compress a file, run the script with the -e or --encrypt flag followed by the path of the file to be processed:

```bash
python penrose_tiling_encryption.py /path/to/file -e
```

This will generate encrypted and compressed versions of the file.

### Decrypt and Decompress a File
To decrypt and decompress a file, run the script with the -d or --decrypt flag followed by the path of the encrypted file to be processed:

```bash
python penrose_tiling_encryption.py /path/to/encrypted/file -d
```

This will generate the decrypted file.

## Notes
- Ensure you have the necessary permissions to read, write, and execute files in the specified locations.
- The script uses RSA encryption with a 2048-bit key size.
- The encryption method is influenced by a Penrose tiling matrix.
- Compressed files are saved with the .zip extension appended to the original file name.
- Encrypted files are saved with the .enc extension appended to the original file name.

## License
This project is licensed under the MIT License. See the LICENSE file for details.