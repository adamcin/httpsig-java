Overview
========

Provides a HMAC implementation with support for SHA-256 and SHA-512.


API
===

Signer
------

To create a Signer, you must provide both a HMAC key and a KeyId. For example:

    Signer signer = new Signer(
                                    new HmacKey("keyId", "ssh. its a secret"),
                                    new HmacKeyId()
    );

Verifier
--------

The Verifier is the mechanism used by a server to verify the signature provided in
the Authorization header against the Request and the Challenge defined for the server.

To create a Verifier, you must provide a HMAC and a KeyId. For example:

    Verifier verifier = new Verifier(
                    new DefaultKeychain(Arrays.asList(new HmacKey("keyId", "ssh. its a secret"))),
                    new HmacKeyId()
    );
            