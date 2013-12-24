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

* **httpsig-api**: Provides the Key and KeyIdentifier interfaces along with concrete implementations for Signer, Verifier, RequestContent, Challenge, and Authorization.

* **httpsig-ssh-jce**: Provides a JCE-based Key implementation for SSH RSA and DSA public keys and unencrypted private keys.

* **httpsig-ssh-bc**: Use PEMUtil to read encrypted SSH private keys using the BouncyCastle provider.

* **httpsig-http-helpers**: Provides helpful utilities for three Java HTTP client implementations (*Apache Commons HttpClient 3.x*, *Apache Http Client 4.x*, *Ning Async Http Client*) as well as for javax.servlet.http on the server-side.

* **net.adamcin.httpsig.osgi**: Convenient OSGi bundle exporting httpsig-api, httpsig-ssh-jce, httpsig-ssh-bc, and httpsig-http-helpers.

* **httpsig-ssh-jsch**: Alternative implementation of SSH key support using the JSch API.

* **httpsig-test-common**: Provides several public/private SSH key pairs and utility methods for writing unit tests.

API
===

Challenge
---------

Authorization
-------------

RequestContent
--------------

Signer
------

Verifier
--------
