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

    // The DefaultKeychain class is provided for convenience
    DefaultKeychain keychain = new DefaultKeychain();

    // Use PEMUtil from httpsig-ssh-bc to read an SSH private key from a file
    keychain.add(PEMUtil.readKey(new File("/home/user/.ssh/id_rsa"), null));

    // The UserFingerprintKeyId class is provided by httpsig-ssh-jce to construct
    // keyIds of the form, "/${username}/${fingerprint}"
    Signer signer = new Signer(keychain, new UserFingerprintKeyId("admin"));

For the Signer to select a key...

Verifier
--------

The Verifier is the mechanism used by a server to verify the signature provided in
the Authorization header against the Request and the Challenge defined for the server.

Challenge
---------

The Challenge class represents a "WWW-Authenticate: Signature" header. It

Authorization
-------------

RequestContent
--------------

