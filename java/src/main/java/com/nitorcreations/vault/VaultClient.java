package com.nitorcreations.vault;

import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.util.IOUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

public class VaultClient {

  private final AmazonS3Client s3;
  private final AWSKMSClient kms;
  private final String bucketName;

  public VaultClient(AmazonS3Client s3, AWSKMSClient kms, String bucketName) {
    if (s3 == null) {
      throw new IllegalArgumentException("S3 client is needed");
    }
    if (kms == null) {
      throw new IllegalArgumentException("KMS client is needed");
    }
    if (bucketName == null) {
      throw new IllegalArgumentException("Bucket name is needed");
    }
    this.s3 = s3;
    this.kms = kms;
    this.bucketName = bucketName;
  }

  public String lookup(String name) throws VaultException {
    final byte[] encrypted, key;
    try {
      encrypted = readObject(name + ".encrypted");
      key = readObject(name + ".key");
    } catch (IOException e) {
      throw new IllegalStateException(String.format("Could not read secret %s from vault", name), e);
    }

    final ByteBuffer decryptedKey = kms.decrypt(new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(key))).getPlaintext();

    try {
      return new String(decrypt(encrypted, decryptedKey));
    } catch (GeneralSecurityException e) {
      throw new VaultException(String.format("Unable to decrypt secret %s", name), e);
    }
  }

  private byte[] decrypt(byte[] encrypted, ByteBuffer decryptedKey) throws GeneralSecurityException {
    return createCipher(decryptedKey, Cipher.DECRYPT_MODE).doFinal(encrypted);
  }

  private static Cipher createCipher(final ByteBuffer unencryptedKey, final int encryptMode) throws GeneralSecurityException {
    final byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1337 / 256, 1337 % 256 };
    final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

    cipher.init(encryptMode, new SecretKeySpec(unencryptedKey.array(), "AES"), new IvParameterSpec(iv));
    return cipher;
  }

  private byte[] readObject(String key) throws IOException {
    return IOUtils.toByteArray(this.s3.getObject(new GetObjectRequest(this.bucketName, key)).getObjectContent());
  }
}
