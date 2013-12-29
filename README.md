httpsig-java
============

Implementation of Joyent's [HTTP Signature Authentication](https://github.com/joyent/node-http-signature/blob/master/http_signing.md) in Java

Introduction
============

This project is an adaptation of an earlier work I started on an [SSHKey Authentication Scheme](https://github.com/adamcin/net.adamcin.sshkey). 

At some point, I discovered that Joyent had their own implementation of a similar scheme for JavaScript, so I decided to that porting my implementation over to their scheme would be better in the long run, as they had made more progress on a specification as well as already having some adoption. Luckily, I was able to switch over completely to the Joyent spec after only a few weeks of refactoring.

Only the RSA and DSA algorithms are supported at this point, by way of PEM-encoded public and private keys.

Additions to HTTP Signature Spec
================================

* Definition of a simple WWW-Authenticate Challenge format to provide support for client/server parameter negotiation.

* Two additional signing algorithms based on the SSH public key authentication protocol, defined in [RFC4253](http://tools.ietf.org/html/rfc4253#section-6.6), "ssh-rsa" and "ssh-dss". I defined these in order to support implementations of the scheme using opaque SSH implementations, where the DER extraction and padding involved in RFC4253 are unavoidable.

Overview
========

* **httpsig-api**: Provides the Key, Keychain, and KeyId interfaces along with concrete implementations for Signer, Verifier, RequestContent, Challenge, and Authorization.

* **httpsig-ssh-jce**: Provides a JCE-based Key implementation for SSH RSA and DSA public keys and unencrypted private keys, with complete support for building Keychains from authorized_keys files.

* **httpsig-ssh-bc**: Use PEMUtil to read PEM-encoded SSH private keys (even encrypted) using the BouncyCastle provider.

* **httpsig-http-helpers**: Provides helpful utilities for three Java HTTP client implementations (*Apache Commons HttpClient 3.x*, *Apache Http Client 4.x*, *Ning Async Http Client*) as well as for javax.servlet.http on the server-side.

* **net.adamcin.httpsig.osgi**: Convenient OSGi bundle exporting httpsig-api, httpsig-ssh-jce, httpsig-ssh-bc, and httpsig-http-helpers.

* **httpsig-ssh-jsch**: Alternative implementation of SSH key support using the JSch API.

* **httpsig-test-common**: Provides several public/private SSH key pairs and utility methods for writing unit tests.

API
===

Signer
------

The Signer is the mechanism used by a client to select a Key from the Keychain, and sign the RequestContent in order to construct an Authorization header, which the client can then add to the request.

To create a Signer, you must provide both a Keychain and a KeyId. For example:

    DefaultKeychain keychain = new DefaultKeychain();

    // Use PEMUtil from httpsig-ssh-bc to read an SSH private key from a file
    keychain.add(PEMUtil.readKey(new File("/home/user/.ssh/id_rsa"), "chang3m3"));

    // The UserKeysFingerprintKeyId class is provided by httpsig-ssh-jce to
    //   construct keyIds using the Joyent API convention, "/${username}/keys/${fingerprint}"
    Signer signer = new Signer(keychain, new UserKeysFingerprintKeyId("admin"));

A keychain may have 0-to-many keys. The Signer selects a key based on a Challenge. The client triggers this selection by passing a Challenge to the rotateKeys() method.

    Challenge challenge = Challenge.parse(wwwAuthnValue);

    // Challenge.parse() may return null if a Signature challenge
    //   could not be parsed from the provided header value.
    if (challenge != null) {
        // The Signer will rotate the keychain until it finds the first
        //   signing key that supports the algorithms listed in the Challenge.
        signer.rotateKeys(challenge);
    }

After selecting a key and building a RequestContent object, the client signs the content using the Signer.sign(requestContent) method in order to create an Authorization header.

    RequestContent.Builder requestContentBuilder = new RequestContent.Builder();

    // call requestContentBuilder.setRequestLine(requestLine) then
    // for all request headers, requestContentBuilder.addHeader(name, value)...

    Authorization authz = signer.sign(requestContentBuilder.build());

    // The Signer.sign() method may return null if the request content
    //   could not be signed.
    if (authz != null) {
        // add request header "Authorization", authz.getHeaderValue()
    }

If the subsequent request fails with a 401 Unauthorized / WWW-Authenticate: Signature, the client may rotate the keychain again to discard the invalid key.

    Challenge nextChallenge = Challenge.parse(wwwAuthnValue);

    // Challenge.parse() may return null
    if (nextChallenge != null) {
        // The current key will be discarded if it satisfies nextChallenge
        //   after failing to authenticate in failedAuthz.
        signer.rotateKeys(nextChallenge, failedAuthz);
    }

Verifier
--------

The Verifier is the mechanism used by a server to verify the signature provided in
the Authorization header against the Request and the Challenge defined for the server.

To create a Verifier, you must provide a Keychain and a KeyId. For example:

    // The AuthorizedKeys class is provided by httpsig-ssh-jce
    Keychain keychain = AuthorizedKeys.getDefaultKeychain();

    // The UserKeysFingerprintKeyId class is provided by httpsig-ssh-jce to
    //   construct keyIds using the Joyent API convention, "/${username}/keys/${fingerprint}"
    Verifier verifier = new Verifier(keychain, new UserKeysFingerprintKeyId("admin"));

After parsing an Authorization and building the RequestContent object from the HTTP request, the server verifies the Authorization header using Verifier.verify()

    // The challenge is defined by the server.
    Challenge challenge = ...

    Authorization authz = Authorization.parse(authzValue);

    // Authorization.parse() may return null if a valid Signature Authorization was
    //   not provided.
    if (authz != null) {
        RequestContent.Builder requestContentBuilder = new RequestContent.Builder();

        // call requestContentBuilder.setRequestLine(requestLine) then
        // for all request headers, requestContentBuilder.addHeader(name, value)

        if (verifier.verify(challenge, requestContentBuilder.build(), authz)) {
            // handle request after successful authentication
        }
    }

    // otherwise, send 401 Unauthorized / WWW-Authenticate: Signature

If an Authorization header specifies "date" as a signed header, during verify the Verifier will also compare the Date header value against the server time +/- a millisecond skew, which is set to 300000L (300 seconds) by default. To adjust the skew, the server
may call verifier.setSkew().

    // one minute skew
    verifier.setSkew(60000L);

    // disable date checking (not recommended)
    verifier.setSkew(-1L);

Challenge
---------

The Challenge class represents a "WWW-Authenticate: Signature" header. It follows the RFC2617 syntax for parameters, the three of which are defined as:

* **realm**: The authentication realm defined by RFC2617

* **headers**: The space-delimited list of headers that are required in Authorization signatures. The order of these headers is not significant.

* **algorithms**: The space-delimited list of signature algorithms supported by the server.

Authorization
-------------

The Authorization class represents an "Authorization: Signature" header. It follows the RFC2617 syntax for parameters, the four of which are defined as:

* **keyId**: The identifier of the key used for signing and verification. If a principal is associated with authentication, it may be included in the keyId value,
but this specification does not define a method by which a client and server may negotiate the keyId format.

* **headers**: The space-delimited list of headers in the order used to build the signed request content.

* **algorithm**: The signing algorithm used by the client

* **signature**: The Base64-encoded signature of the request content.


RequestContent
--------------

The RequestContent class represents the sign-able portion of an HTTP Request. This includes the request line (as in "GET /some/page.html?foo=bar HTTP/1.1") and all of the request headers, excluding the "Authorization" header.

It is created using the RequestContent.Builder class:

    // example HTTP headers provided by a client implementation
    Map<String, String> headers = ...

    RequestContent.Builder requestContentBuilder = new RequestContent.Builder();

    // set the HTTP request line
    requestContentBuilder.setRequestLine("GET /index.html HTTP/1.1");

    // add each HTTP header in request order
    for (Map.Entry<String, String> header : headers.entrySet()) {
        requestContentBuilder.addHeader(header.getKey(), header.getValue());
    }

    // if the date header is not set, set it to the current time, but remember
    //   to add the resulting date header back to the original client request
    if (requestContentBuilder.build().getDate() == null) {
        requestContentBuilder.addDateNow();

        String dateValue = requestContentBuilder.build().getDate();

        // add header ("date", dateValue) to client HTTP request...
    }

    // build the request content
    RequestContent requestContent = requestContentBuilder.build();


