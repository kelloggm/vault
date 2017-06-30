const AWS = require('aws-sdk');
const crypto = require('crypto');

const ALGORITHMS = Object.freeze({
  crypto: 'AES-256-CTR',
  kms: 'AES_256'
});
const STATIC_IV = new Buffer([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1337 / 256, 1337 % 256]);
const ENCODING = 'UTF-8';

const createRequestObject = (bucketName, key) => Object.freeze({
  Bucket: bucketName,
  Key: key
});

const createKeyRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}.key`);

const createEncryptedValueRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}.encrypted`);

createVaultClient = (options) => {
  const bucketName = options.bucketName;
  const vaultKey = options.vaultKey;

  const s3 = new AWS.S3();
  const kms = new AWS.KMS();

  const writeObject = (base, value) => s3.putObject(Object.assign({
    Body: value,
    ACL: 'private'
  }, base)).promise();

  return {
    lookup: (name) => Promise.all([
      s3.getObject(createKeyRequestObject(bucketName, name)).promise()
        .then((encryptedKey) => {
          return kms.decrypt({ CiphertextBlob: encryptedKey.Body }).promise();
        }),
      s3.getObject(createEncryptedValueRequestObject(bucketName, name)).promise()
    ]).then((keyAndValue) => {
      const decryptedKey = keyAndValue[0].Plaintext;
      const encryptedValue = keyAndValue[1].Body;
      const decipher = crypto.createDecipheriv(ALGORITHMS.crypto, decryptedKey, STATIC_IV);
      decipher.update(encryptedValue);
      return Promise.resolve(decipher.final(ENCODING));
    }),

    store: (name, data) => kms.generateDataKey({
      KeyId: vaultKey,
      KeySpec: ALGORITHMS.kms
    }).promise().then((dataKey) => {
      const cipher = crypto.createCipheriv(ALGORITHMS.crypto, dataKey.Plaintext, STATIC_IV);
      cipher.update(data);
      return Promise.resolve({ key: dataKey.CiphertextBlob, value: cipher.final(ENCODING) });
    }).then((keyAndValue) => {
      return Promise.all([
        writeObject(createKeyRequestObject(bucketName, name), keyAndValue.key),
        writeObject(createEncryptedValueRequestObject(bucketName, name), keyAndValue.value)
      ]);
    }),

    delete: (name) => Promise.all([
      s3.deleteObject(createEncryptedValueRequestObject(bucketName, name)).promise(),
      s3.deleteObject(createKeyRequestObject(bucketName, name)).promise()
    ]),

    exists: (name) => s3.headObject(createEncryptedValueRequestObject(bucketName, name)).promise().then(
      () => Promise.resolve(true),
      () => Promise.resolve(false)
    ),

    all: () => s3.listObjectsV2({
      Bucket: bucketName
    }).promise().then((data) => {
      return Promise.resolve(data.Contents
        .filter((object) => object.Key.endsWith('.encrypted'))
        .map(object => object.Key.slice(0, -('.encrypted'.length))));
    })
  }
};

module.exports = createVaultClient;
