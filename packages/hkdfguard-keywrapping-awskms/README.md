# hkdfguard-keywrapping-awskms

Wraps DEKs under one symmetric AWS KMS key, through botocore, reading key files only from where no untrusted account could have replaced them.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-keywrapping-awskms
```

```python
import boto3
from hkdfguard.keywrapping.awskms import AwsKmsKeyWrapper

kms = boto3.client("kms")  # the application creates, configures and owns the client
wrapper = AwsKmsKeyWrapper(kms, "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
                           {"purpose": "my.service"})
```

The package depends on `botocore` only. Create the client with `boto3.client("kms")` or
`botocore.session.get_session().create_client("kms")`; either is a botocore client.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) ("Wrapping under AWS KMS
instead") and [Wrap keys with AWS KMS](https://github.com/runsecure/hkdfguard-python/blob/main/docs/how-to/use-aws-kms.md)
for the key, IAM permissions, credentials and key files.

Licensed under the Mozilla Public License 2.0.
