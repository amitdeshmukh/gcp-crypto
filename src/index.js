import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { KeyManagementServiceClient } from '@google-cloud/kms';

// Instantiates a Secret Manager client
const secretmanagerClient = new SecretManagerServiceClient();

// Instantiates a KMS client
const kmsClient = new KeyManagementServiceClient();

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
      const [cryptoKey] = await kmsClient.createCryptoKey({
        parent: kmsClient.keyRingPath(projectId, locationId, keyRing),
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
        throw new Error(`KMS CryptoKey ${keyId} already exists in keyring ${keyRing}`);
      } else {
        throw error;
      }
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
    // Build the key name
    const keyName = kmsClient.cryptoKeyPath(
      projectId,
      locationId,
      keyRing,
      keyId
    );

    // Check if the secret already exists
    const secretId = `${keyId}-aes-key`;
    const [secrets] = await secretmanagerClient.listSecrets({
      parent: `projects/${projectId}`,
    });
    const secretExists = secrets.some(secret => secret.name.includes(secretId));

    // If the secret exists and overwrite flag is set, delete the secret
    if (secretExists && overwrite) {
      await secretmanagerClient.deleteSecret({
        name: `projects/${projectId}/secrets/${secretId}`,
      });
    }  

    // Encrypt the key using Cloud KMS
    const [encryptResponse] = await kmsClient.encrypt({
      name: keyName,
      plaintext: Buffer.from(aesKey).toString('base64'),
    });
    const encryptedKey = encryptResponse.ciphertext;

    // Store the encrypted key in Google Secret Manager
    try {
      const [secret] = await secretmanagerClient.createSecret({
        parent: `projects/${projectId}`,
        secretId: `${keyId}-aes-key`,
        secret: {
          replication: {
            automatic: {},
          },
          labels: {
            keyid: keyId,
          },
        },
      });

      const [version] = await secretmanagerClient.addSecretVersion({
        parent: secret.name,
        payload: {
          data: Buffer.from(encryptedKey, 'base64'),
        },
      });
      console.log('Added secret version:', version.name);
    } catch (error) {
      if (error.code === 6) {
        throw new Error('Secret already exists');
      } else {
        throw error;
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
      const keyName = kmsClient.cryptoKeyPath(
        projectId,
        locationId,
        keyRing,
        keyId
      );

      // Build the secret name
      const secretId = `${keyId}-aes-key`;
      const secretName = `projects/${projectId}/secrets/${secretId}/versions/latest`;

      // Retrieve the encrypted key from Google Secret Manager
      const [version] = await secretmanagerClient.accessSecretVersion({
        name: secretName,
      });
      const encryptedKey = version.payload.data;

      // Decrypt the key using Cloud KMS
      const [decryptResponse] = await kmsClient.decrypt({
        name: keyName,
        ciphertext: encryptedKey,
      });

      return decryptResponse.plaintext.toString('utf8');    
    } catch (error) {
      throw new Error('Failed to obtain the key:', error);
    }
  }
}

// ES6 default export
export default GCPCrypto;

// CommonJS export for `require`
module.exports = GCPCrypto;