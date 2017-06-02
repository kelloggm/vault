package com.nitorcreations.vault;

import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Random;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class VaultClientTest {

  private static final String BUCKET_NAME_FIXTURE = "bucket";
  private static final String SECRET_NAME_FIXTURE = "foo";
  private static final String KEY_FIXTURE = "key";

  private AmazonS3Client s3Mock;
  private AWSKMSClient kmsMock;
  private VaultClient vaultClient;

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  @Test
  public void constructorThrowsIaeWhenS3Null() {
    expectedException.expect(IllegalArgumentException.class);
    new VaultClient(null, new AWSKMSClient(), BUCKET_NAME_FIXTURE);
  }

  @Test
  public void constructorThrowsIaeWhenKmsNull() {
    expectedException.expect(IllegalArgumentException.class);
    new VaultClient(new AmazonS3Client(), null, BUCKET_NAME_FIXTURE);
  }

  @Test
  public void constructorThrowsIaeWhenBucketNameNull() {
    expectedException.expect(IllegalArgumentException.class);
    new VaultClient(new AmazonS3Client(), new AWSKMSClient(), null);
  }

  @Before
  public void setUpS3() throws Exception {
    s3Mock = mock(AmazonS3Client.class);
    when(s3Mock.getObject(any(GetObjectRequest.class))).thenReturn(createS3Object("value"), createS3Object(KEY_FIXTURE));
  }

  @Before
  public void setUpKms() {
    kmsMock = mock(AWSKMSClient.class);
    when(kmsMock.decrypt(any(DecryptRequest.class))).thenReturn(createDecryptResult());
  }

  @Before
  public void setUpVaultClient() {
    vaultClient = new VaultClient(s3Mock, kmsMock, BUCKET_NAME_FIXTURE);
  }

  private static DecryptResult createDecryptResult() {
    DecryptResult result = new DecryptResult();
    final byte[] bytes = new byte[16];
    new Random().nextBytes(bytes);
    ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
    result.setPlaintext(byteBuffer);
    return result;
  }

  private static S3Object createS3Object(final String content) throws IOException {
    final S3Object s3Object = new S3Object();
    s3Object.setObjectContent(IOUtils.toInputStream(content, "UTF-8"));
    return s3Object;
  }

  @Test
  public void lookupReadsEncryptedValueFromS3() throws Exception {
    vaultClient.lookup(SECRET_NAME_FIXTURE);
    verify(s3Mock).getObject(argThat(getObjectRequest -> (SECRET_NAME_FIXTURE + ".encrypted").equals(getObjectRequest.getKey())));
  }

  @Test
  public void lookupReadsKeyFromS3() throws Exception {
    vaultClient.lookup(SECRET_NAME_FIXTURE);
    verify(s3Mock).getObject(argThat(getObjectRequest -> (SECRET_NAME_FIXTURE + ".key").equals(getObjectRequest.getKey())));
  }

  @Test
  public void lookupUsesCorrectBucket() throws Exception {
    vaultClient.lookup(SECRET_NAME_FIXTURE);
    verify(s3Mock, times(2)).getObject(argThat(getObjectRequest -> BUCKET_NAME_FIXTURE.equals(getObjectRequest.getBucketName())));
  }

  @Test
  public void lookupDecryptsSecretUsingKms() throws Exception {
    vaultClient.lookup(SECRET_NAME_FIXTURE);
    verify(kmsMock).decrypt(any());
  }
}
