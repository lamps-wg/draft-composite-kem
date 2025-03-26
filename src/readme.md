# Requirements

## python
There is a python sub-component, it requires python3, pip, and venv:

1. Create a virtual environment
    ```shell
    python -m venv venv
    ```
2. Activate the virtual environment
    ```shell
    source venv/bin/activate
    ```
3. Install the dependencies

    ```shell
    pip install -r requirements.txt
    ```

## ML-DSA and ML-KEM

https://github.com/GiacomoPope/dilithium-py

https://github.com/GiacomoPope/kyber-py




# Output

The output format is intended to be reminiscent of the NIST ACVP KAT JSON format.

```
{
    "ca": "<ca_cert>,
    "tests": [
        {
          "tcId": "<composite_oid_name>",
          "ek": "<raw_key>",
          "x5c": "<x509_cert_of_ek>",
          "dk": "<sk>",
          "c": "<ciphertext>",
          "k": "<ss>"
        },
        ...
    ]
}
```

The ekx5c is an X.509 certificate containing the KEM key and signed by a CA cert which is common to all tests.