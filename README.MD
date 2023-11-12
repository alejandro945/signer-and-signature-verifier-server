# Signer and Signature Verifier Server 🥷🏿

This system provides a Django API interface for generating RSA key pairs, signing files, and verifying digital signatures. Below is a detailed explanation of how to use each option.

## Description

Signer and signature verifier. The program should have three options: 

1. **RSA key pair generation:** You must generate the public and private key in two separate files. The private key file must be password protected. 
2. **Sign file:** This option receives as inputs any file, and the private key file. Once the private key lock password has been verified, the program must generate the digital signature of the file, and save it in a separate file. 
3. **Signature verification:** This option should receive as inputs the original file, the file containing the signature, and the public key file. With these three entries, it must be verified that the signature is correct.

## Prerequisites

Make sure to have the following libraries installed:

```
pip install django
pip install cryptography
pip install djangorestframework 
```

## RSA Signature Operations

### 1. `generate_rsa_key_pair`

This function generates an RSA key pair (public and private keys) with a specified key size (default is 2048 bits). The private key is then encrypted with a provided password and stored in PEM format. The public key is also returned.

#### Parameters:
- `password`: Password used for encrypting the private key.
- `key_size`: Size of the RSA key (default is 2048 bits).

### 2. `sign_file`

This function signs the content of a file using an RSA private key, provided as PEM format and protected with a password.

#### Parameters:
- `file_to_sign`: Content of the file to be signed.
- `private_key_pem`: Encrypted RSA private key in PEM format.
- `password`: Password to decrypt the private key.

#### Returns:
- Digital signature of the file content in base64-encoded format.

### 3. `verify_signature`

This function verifies if a digital signature corresponds to the original content of a file using an RSA public key.

#### Parameters:
- `original_file_content`: Content of the original file.
- `signature_content`: Digital signature to be verified in base64-encoded format.
- `public_key_content`: RSA public key in PEM format.

#### Raises:
- `InvalidKey`: Exception raised if the signature is invalid.

## Usage

1. Generate RSA Key Pairs

Endpoint: `/key-pair/`

Method: `POST`

This endpoint generates an RSA key pair and stores the private key protected with a password in the database. Here is an example of how to use it:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"password": "your_password"}' http://domain.com/key-pair/
```

2. Sign File

Endpoint: `/sign-file/`

Method: `POST`

This endpoint signs a file with the private key stored in the database. Here is an example of how to use it:

```bash
curl -X POST -H "Content-Type: multipart/form-data" -F "password=your_password" -F "file_to_sign=@/path/to/your/file.txt" -F "private_key_file=@/path/to/your/private_key.pem" http://domain.com/sign-file/
```

The response will contain the digital signature of the file.

3. Verify Signature

Endpoint: `/verify-signature/`

Method: `POST`

This endpoint verifies if the digital signature corresponds to the original file and the provided public key. Here is an example of how to use it:

```bash
curl -X POST -H "Content-Type: multipart/form-data" -F "original_file=@/path/to/your/original_file.txt" -F "signature_file=@/path/to/your/signature.txt" -F "public_key_file=@/path/to/your/public_key.pem" http://domain.com/verify-signature/
```
The response will indicate whether the signature is valid or not.

4. **Optional:**

Deleting an RSA Key Pair
Endpoint: `/key-pair/{id}/`

Method: `DELETE`

This endpoint deletes an RSA key pair from the database by its ID. Here is an example of how to use it:

```bash
curl -X DELETE http://domain.com/key-pair/1/
```

Make sure to replace your-domain.com with your server's URL.

Remember to properly secure these endpoints in a production environment and configure HTTPS to maintain the security of private keys and communications.