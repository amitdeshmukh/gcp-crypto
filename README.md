# GCPCrypto Module

The GCPCrypto module provides a set of methods to interact with Google Cloud's Key Management Service (KMS) and Secret Manager. It is designed to create, encrypt, store, and decrypt cryptographic keys using Google Cloud's services.

## How it Works
The GCPCrypto class is instantiated with a Google Cloud project ID, location ID, and a key ring. It uses these to interact with Google Cloud's KMS and Secret Manager.

The class provides the following methods:

- `createCryptoKey(keyId, protectionLevel)`: This method creates a new CryptoKey within the specified KeyRing in Google Cloud KMS. The key ID and protection level (e.g., SOFTWARE or HSM) are required parameters.

- `encryptAndStoreSecretKey(keyId, aesKey, overwrite)`: This method encrypts the supplied AES-256 symmetric key using Cloud KMS, and stores the encrypted key in Google Secret Manager. The `keyId` and `aesKey` are required parameters. The overwrite parameter is optional and defaults to `false`. If overwrite is `true` and the secret already exists, it will be deleted before the new secret is stored.

- `decryptSecretKey(keyId)`: This method retrieves the encrypted key from Google Secret Manager and decrypts it using Cloud KMS. The `keyId` is a required parameter.

## Authentication

The module uses Application Default Credentials (ADC) to authenticate with Google Cloud services. ADC is a strategy that allows the module to find and use appropriate credentials based on its environment. This could be credentials set in an environment variable, credentials provided by the Google Cloud SDK, credentials provided by the Google Cloud Metadata server, etc.

Please ensure that the environment where this module is used is configured with appropriate credentials that have necessary permissions to interact with Google Cloud KMS and Secret Manager. More information on ADC can be found [here](https://cloud.google.com/docs/authentication/provide-credentials-adc).


## Installation

```bash
npm install @amitdeshmukh/gcp-crypto
# or
yarn add @amitdeshmukh/gcp-crypto
```

## Usage
Once installed, you can import and use the module like this:

```js
import GCPCrypto from 'gcp-crypto';

// Initialize the module with your project ID, GCP keyring location ID, and keyring name
const gcpCrypto = new GCPCrypto('your-project-id', 'your-location-id', 'your-key-ring');

// Create a CryptoKey in your KeyRing with protectionLevel
await gcpCrypto.createCryptoKey(keyId, 'SOFTWARE');

// Generate a random AES-256-GCM symmetric encryption/decryption key
import Cryptr from 'cryptr';
let cryptr = new Cryptr('myTotalySecretKey');
const aesKey = cryptr.encrypt(Math.random().toString(36).substring(2, 15));

// Encrypt the AES key with GCP KMS and store it in Secret Manager
const encryptedKey = await gcpCrypto.encryptAndStoreSecretKey(keyId, aesKey, true);
console.log('Encrypted key:', encryptedKey.toString('base64'));

// Use the key to encrypt something
const plainText = 'Hello World!';
cryptr = new Cryptr(aesKey);
const encryptedText = cryptr.encrypt(plainText);
console.log('Encrypted text:', encryptedText);

// Retrieve the key from Secret Manager and decrypt it using GCP KMS
const decryptedKey = await gcpCrypto.decryptSecretKey(keyId);
console.log('Decrypted AESkey:', decryptedKey);

// Use the key to decrypt encrypted text
cryptr = new Cryptr(decryptedKey);
const decryptedText = cryptr.decrypt(encryptedText);
console.log('Decrypted text:', decryptedText);

```
