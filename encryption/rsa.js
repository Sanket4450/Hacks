// RSA encryption with public and private keys

const crypto = require('crypto')

// Generate public and private keys
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
        type: 'pkcs1', // Public key format
        format: 'pem',
    },
    privateKeyEncoding: {
        type: 'pkcs1', // Private key format
        format: 'pem',
    },
})

// Encrypt data with public key
function encryptWithPubllicKey(data, publicKey) {
    return crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        Buffer.from(data)
    )
}

// Decrypt data with private key
function decryptWithPrivateKey(encryptedData, privateKey) {
    return crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        encryptedData
    )
}

const plainText = 'Hello! I am Sanket Talaviya'
console.log('Original data:', plainText + '\n')

const encryptedData = encryptWithPubllicKey(plainText, publicKey)
console.log('Encrypted data:', encryptedData.toString('base64') + '\n')

const decryptedData = decryptWithPrivateKey(encryptedData, privateKey)
console.log('Decrypted data:', decryptedData.toString() + '\n')
