const AWS = require('aws-sdk-mock');
const sinon = require('sinon');
require('should');
require('should-sinon');
const VaultClient = require('../lib/vaultClient');
const crypto = require("crypto");

const VAULT_KEY_FIXTURE = 'vaultKey';
const BUCKET_NAME_FIXTURE = 'bucket';
const SECRET_NAME_FIXTURE = 'name';
const ENCRYPTED_KEY_FIXTURE = 'key';
const DATA_FIXTURE = 'value';

describe('VaultClient', () => {
  let vaultClient;
  const getObjectSpy = sinon.stub();
  const decryptSpy = sinon.stub();
  const putObjectSpy = sinon.stub();
  const generateDataKeySpy = sinon.stub();

  before(() => {
    AWS.mock('S3', 'getObject', getObjectSpy);
    AWS.mock('S3', 'putObject', putObjectSpy);
    AWS.mock('KMS', 'decrypt', decryptSpy);
    AWS.mock('KMS', 'generateDataKey', generateDataKeySpy);
  });

  beforeEach(() => {
    getObjectSpy
      .onCall(0)
      .yields(null, ENCRYPTED_KEY_FIXTURE)
      .onCall(1)
      .yields(null, 'foo');

    putObjectSpy.yields();

    decryptSpy.yields(null, {
      Plaintext: crypto.randomBytes(32)
    });

    generateDataKeySpy.yields(null, {
      Plaintext: crypto.randomBytes(32),
      CiphertextBlob: crypto.randomBytes(32)
    });

    vaultClient = VaultClient({
      bucketName: BUCKET_NAME_FIXTURE,
      vaultKey: VAULT_KEY_FIXTURE
    });
  });

  afterEach(() => {
    getObjectSpy.reset();
    putObjectSpy.reset();
    decryptSpy.reset();
    generateDataKeySpy.reset();
  });

  after(() => {
    AWS.restore();
  });

  describe('factory', () => {
    it('returns an object', () => {
      vaultClient.should.be.an.Object();
    });
  });

  describe('lookup', () => {
    it('reads encrypted value from S3', () => {
      return vaultClient.lookup(SECRET_NAME_FIXTURE)
        .then(() => {
          getObjectSpy.should.have.been.calledWithMatch({ Key: SECRET_NAME_FIXTURE + '.encrypted' });
        });
    });

    it('reads encrypted key from S3', () => {
      return vaultClient.lookup(SECRET_NAME_FIXTURE)
        .then(() => {
          getObjectSpy.should.have.been.calledWithMatch({ Key: SECRET_NAME_FIXTURE + '.key' });
        });
    });

    it('reads encrypted key and value from the correct bucket', () => {
      return vaultClient.lookup(SECRET_NAME_FIXTURE)
        .then(() => {
          getObjectSpy.should.have.been.alwaysCalledWithMatch({ Bucket: BUCKET_NAME_FIXTURE });
        });
    });

    it('decrypts the encrypted key using KMS', () => {
      return vaultClient.lookup(SECRET_NAME_FIXTURE)
        .then(() => {
          decryptSpy.should.have.been.calledWithMatch({ CiphertextBlob: ENCRYPTED_KEY_FIXTURE });
        });
    });

    it('resolves to a string promise', () => {
      return vaultClient.lookup(SECRET_NAME_FIXTURE).then((result) => {
        result.should.be.a.String();
      });
    });
  });

  describe('store', () => {
    it('Writes encrypted value to S3', () => {
      return vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE)
        .then(() => {
          putObjectSpy.should.have.been.calledWithMatch({ Key: SECRET_NAME_FIXTURE + ".encrypted" });
        });
    });

    it('Writes encryption key to S3', () => {
      return vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE)
        .then(() => {
          putObjectSpy.should.have.been.calledWithMatch({ Key: SECRET_NAME_FIXTURE + ".key" });
        });
    });

    it('Writes key and value to correct bucket', () => {
      return vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE)
        .then(() => {
          putObjectSpy.should.have.been.alwaysCalledWithMatch({ Bucket: BUCKET_NAME_FIXTURE });
        });
    });

    it('Encrypts value using the correct vault key', () => {
      return vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE)
        .then(() => {
          generateDataKeySpy.should.have.been.calledWithMatch({ KeyId: VAULT_KEY_FIXTURE });
        });
    });
  });
});