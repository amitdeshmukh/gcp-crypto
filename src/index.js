import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { KeyManagementServiceClient } from '@google-cloud/kms';

class GCPCrypto {
  constructor(projectId, locationId, keyRing) {
    this.projectId = projectId;
    this.locationId = locationId;
    this.keyRing = keyRing;
    this.secretmanagerClient = new SecretManagerServiceClient();
    this.kmsClient = new KeyManagementServiceClient();
  }

  /**
   * Creates a new CryptoKey within the specified KeyRing.
   *
   * @param {string} keyId - The key ID to store the key under.
   * @param {string} protectionLevel - The protection level for the CryptoKey eg, SOFTWARE or HSM.
   * @throws {Error} Will throw an error if the CryptoKey creation fails.
   * @returns {Promise<Object>} A promise that resolves to the newly created CryptoKey.
   */
  async createCryptoKey(keyId, protectionLevel) {
    try {
      const [cryptoKey] = await this.kmsClient.createCryptoKey({
        parent: this.kmsClient.keyRingPath(this.projectId, this.locationId, this.keyRing),
        cryptoKeyId: keyId,
        cryptoKey: {
          purpose: 'ENCRYPT_DECRYPT',
          versionTemplate: {
            algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION',
            protectionLevel: protectionLevel,
          },
        },
      });

      return cryptoKey;
    } catch (error) {
      if (error.code === 6) {
        throw new Error(`KMS CryptoKey ${keyId} already exists in keyring ${this.keyRing}`);
      } else {
        throw error;
      }
    }
  }

  /**
   * Deletes a secret from the Google Secret Manager.
   *
   * @param {string} keyId - The ID of the secret to delete.
   * @throws {Error} Will throw an error if the deletion fails.
   */
  async deleteKeyFromSecretManager(keyId) {
    try {
      await this.secretmanagerClient.deleteSecret({
        name: `projects/${this.projectId}/secrets/${keyId}`,
      });
    } catch (error) {
      throw error;
    }
  }
  /**
   * Create a random AES-256 encryption key
   * Encrypt the key using Cloud KMS
   * Store the encrypted key in Google Secret Manager
   * @param {string} keyId The key ID to be used to store the key
   * @param {string} aesKey The AES key
   * @param {boolean} overwrite Overwrite the secret in Google Secret Manager if it already exists
   * @throws {Error} If the encrypt operation fails
   * @returns {Promise<string>} The encrypted key
   * */
  async encryptAndStoreSecretKey(keyId, aesKey, overwrite = false) {
    let encryptedKey;

    // Build the key name
    const keyName = this.kmsClient.cryptoKeyPath(
      this.projectId,
      this.locationId,
      this.keyRing,
      keyId
    );

    try {
      // Check if the secret already exists
      const secretId = `${keyId}`;
      const [secrets] = await this.secretmanagerClient.listSecrets({
        parent: `projects/${this.projectId}`,
      });
      const secretExists = secrets.some(secret => secret.name.includes(secretId));

      // If the secret exists and overwrite flag is set, delete the secret
      if (secretExists && overwrite) {
        await this.secretmanagerClient.deleteSecret({
          name: `projects/${this.projectId}/secrets/${secretId}`,
        });
      }  

      // Encrypt the key using Cloud KMS
      const [encryptResponse] = await this.kmsClient.encrypt({
        name: keyName,
        plaintext: Buffer.from(aesKey).toString('base64'),
      });
      encryptedKey = encryptResponse.ciphertext;

      // Store the encrypted key in Google Secret Manager
      const [secret] = await this.secretmanagerClient.createSecret({
        parent: `projects/${this.projectId}`,
        secretId: `${keyId}`,
        secret: {
          replication: {
            automatic: {},
          },
          labels: {
            keyid: keyId,
          },
        },
      });

      await this.secretmanagerClient.addSecretVersion({
        parent: secret.name,
        payload: {
          data: Buffer.from(encryptedKey, 'base64'),
        },
      });

  } catch (error) {
    if (error.code === 6 && error.message.includes('already exists')) {
      throw new Error(`Secret ${keyId} already exists and overwrite is not set`);
    } else {
      // Log the error or include additional context in the error message
      console.error(`Error in encryptAndStoreSecretKey: ${error.message}`);
      throw new Error(`Error during encryption or storage of secret key: ${error.message}`);
    }    
  }

    return encryptedKey;
  }

  /**
   * Retrieve the encrypted key from Google Secret Manager
   * Decrypt the key using Cloud KMS
   * @param {string} keyId The key ID to retrieve the key from
   * @throws {Error} If the decrypt operation fails
   * @returns {Promise<string>} The decrypted key
   * */
  async decryptSecretKey(keyId) {
    try {
      // Build the key name
      const keyName = this.kmsClient.cryptoKeyPath(
        this.projectId,
        this.locationId,
        this.keyRing,
        keyId
      );

      // Build the secret name
      const secretId = `${keyId}`;
      const secretName = `projects/${this.projectId}/secrets/${secretId}/versions/latest`;

      // Retrieve the encrypted key from Google Secret Manager
      const [version] = await this.secretmanagerClient.accessSecretVersion({
        name: secretName,
      });
      const encryptedKey = version.payload.data;

      // Decrypt the key using Cloud KMS
      const [decryptResponse] = await this.kmsClient.decrypt({
        name: keyName,
        ciphertext: encryptedKey,
      });

      return decryptResponse.plaintext.toString('utf8');    
    } catch (error) {
      throw error;
    }
  }

  /**
   * Retrieve and decrypt all keys from Google Secret Manager that are part of the current key ring
   * @throws {Error} If the decrypt operation fails
   * @returns {Promise<Object[]>} An array of objects containing the keyId and decrypted key
   */
  async decryptAllKeys() {
    try {
      // Retrieve all secrets from Google Secret Manager
      const [secrets] = await this.secretmanagerClient.listSecrets({
        parent: `projects/${this.projectId}`
      });

      // Decrypt each secret and collect the results
      const decryptedKeysPromises = secrets.map(async secret => {
        const secretId = secret.name.split('/').pop();
        try {
          const decryptedKey = await this.decryptSecretKey(secretId);
          return {
            keyId: secretId,
            decryptedKey
          };
        } catch (error) {
          // Handle the error for the individual key
          console.error(`Error decrypting key ${secretId}: ${error.message}`);
          // Return null or some error indicator if needed
          return null;
        }
      });

      // Filter out any null results from errors
      const decryptedKeys = (await Promise.all(decryptedKeysPromises)).filter(key => key !== null);
      
      return decryptedKeys;
    } catch (error) {
      // Handle the error for the entire operation
      console.error(`Error in decryptAllKeys: ${error.message}`);
      throw new Error(`Error during decryption of all keys: ${error.message}`);
    }
  }

  /**
   * Encrypts the provided plaintext using Google Cloud KMS and returns the ciphertext.
   * @param {string} keyId - The ID of the key used for encryption.
   * @param {string} plaintext - The plaintext to be encrypted.
   * @throws {Error} If the encryption operation fails.
   * @returns {Promise<string>} The encrypted ciphertext.
   */
  async encryptPlaintext(keyId, plaintext) {
    try {
      // Build the key name
      const keyName = this.kmsClient.cryptoKeyPath(
        this.projectId,
        this.locationId,
        this.keyRing,
        keyId
      );

      // Encrypt the plaintext using Cloud KMS
      const [encryptResponse] = await this.kmsClient.encrypt({
        name: keyName,
        plaintext: Buffer.from(plaintext).toString('base64'),
      });

      // Return the encrypted ciphertext
      return encryptResponse.ciphertext;
    } catch (error) {
      console.error(`Error in encryptPlaintext for keyId ${keyId}: ${error.message}`);
      throw new Error(`Error during encryption of plaintext: ${error.message}`);
    }
  }

  /**
   * Decrypts the provided ciphertext using Google Cloud KMS and returns the plaintext.
   * @param {string} keyId - The ID of the key used for decryption.
   * @param {string} ciphertext - The ciphertext to be decrypted.
   * @throws {Error} If the decryption operation fails.
   * @returns {Promise<string>} The decrypted plaintext.
   */
  async decryptCiphertext(keyId, ciphertext) {
    try {
      // Build the key name
      const keyName = this.kmsClient.cryptoKeyPath(
        this.projectId,
        this.locationId,
        this.keyRing,
        keyId
      );

      // Decrypt the ciphertext using Cloud KMS
      const [decryptResponse] = await this.kmsClient.decrypt({
        name: keyName,
        ciphertext: Buffer.from(ciphertext, 'base64'),
      });

      // Return the decrypted plaintext
      return decryptResponse.plaintext.toString('utf-8');
    } catch (error) {
      console.error(`Error in decryptCiphertext for keyId ${keyId}: ${error.message}`);
      throw new Error(`Error during decryption of ciphertext: ${error.message}`);
    }
  }  
}

// ES6 default export
export default GCPCrypto;

// CommonJS export for `require`
module.exports = GCPCrypto;