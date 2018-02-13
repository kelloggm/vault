nitor-vault
===========

Command line tools and libraries for encrypting keys and values using client-side encryption with AWS KMS keys.

# Example usage

Initialize vault bucket and other infrastructure: `vault --init`. Will create a CloudFormation stack.

Encrypt a file and store in vault bucket: `vault -f <file>`

Decrypt a file: `vault -l <file>`

Encrypt a single value and store in vault bucket `vault -s my-key -v my-value`

Decrypt a single value `vault -l my-key`

## Using encrypted CloudFormation stack parameters

Encrypt a value like this: `$ aws kms encrypt --key-id <key id or ARN> --plaintext 'My secret value'`

The response to the above commadn will contain a `CiphertextBlob` with a base64 encoded value encrypted with your chosen KMS key. Use that value in a CF parameter.

To decrypt the parameter value at stack creation or update time, use a custom resource:

```
Parameters:
  MySecret:
    Type: String
    Description: Param value encrypted with KMS
Resources:
  DecryptSecret:
    Type: "Custom::VaultDecrypt"
    Properties:
      ServiceToken: "arn:aws:lambda:<region>:<account-id>:function:vault-decrypt"
      Ciphertext: { "Ref": "MySecret" }
  DatabaseWithSecretAsPassword:
    Type: "AWS::RDS::DBInstance"
    Properties:
      ...
      MasterUserPassword:
        Fn::Sub: ${DecryptSecret.Plaintext}
```

# Licence

[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)
