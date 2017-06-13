const AWS = require('aws-sdk');
const crypto = require('crypto');

const ALGORITHMS = {
  crypto: 'AES-256-CTR',
  kms: 'AES_256'
};
const STATIC_IV = new Buffer([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1337 / 256, 1337 % 256]);
const ENCODING = 'UTF-8';

createVaultClient = (options) => {
  const bucketName = options.bucketName;
  const vaultKey = options.vaultKey;

  const s3 = new AWS.S3();
  const kms = new AWS.KMS();

  const writeObject = (key, value) => {
    return s3.putObject({
      Bucket: bucketName,
      Key: key,
      Body: value,
      ACL: 'private'
    });
  };

  return {
    lookup: (name) => {
      return Promise.all([
        s3.getObject({
          Bucket: bucketName,
          Key: name + '.key'
        }).promise()
          .then((encryptedKey) => {
            return kms.decrypt({ CiphertextBlob: encryptedKey }).promise();
          }),
        s3.getObject({
          Bucket: bucketName,
          Key: name + '.encrypted'
        }).promise()
      ]).then((keyAndValue) => {
        const decryptedKey = keyAndValue[0].Plaintext;
        const encryptedValue = keyAndValue[1];
        const decipher = crypto.createDecipheriv(ALGORITHMS.crypto, decryptedKey, STATIC_IV);
        decipher.update(encryptedValue);
        return Promise.resolve(decipher.final(ENCODING));
      });
    },

    store: (name, data) => {
      return kms.generateDataKey({
        KeyId: vaultKey,
        KeySpec: ALGORITHMS.kms
      }).promise()
        .then((dataKey) => {
          const cipher = crypto.createCipheriv(ALGORITHMS.crypto, dataKey.Plaintext, STATIC_IV);
          cipher.update(data);
          return Promise.resolve({ key: dataKey.CiphertextBlob, value: cipher.final(ENCODING) });
        })
        .then((keyAndValue) => {
          return Promise.all([
            writeObject(name + '.key', keyAndValue.key).promise(),
            writeObject(name + '.encrypted', keyAndValue.value).promise()
          ]);
        });
    }
  }
};

module.exports = createVaultClient;
