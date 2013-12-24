httpsig-java
============

Implementation of Joyent's [HTTP Signature Authentication](https://github.com/joyent/node-http-signature/blob/master/http_signing.md) in Java

Introduction
============

This project is an adaptation of an earlier work I started on an [SSHKey Authentication Scheme](https://github.com/adamcin/net.adamcin.sshkey). 

At some point, I discovered that Joyent had their own implementation of a similar scheme for JavaScript, so I decided to that porting my implementation over to their scheme would be better in the long run, as they had made more progress on a specification as well as already having some adoption. Luckily, I was able to switch over completely to the Joyent spec after only a few weeks of refactoring.

Additions to HTTP Signature Spec
================================

* Definition of a simple WWW-Authenticate Challenge format to provide limited support for client/server parameter negotiation

* Two additional signing algorithms based on the SSH public key authentication protocol, defined in [RFC4253](http://tools.ietf.org/html/rfc4253#section-6.6), "ssh-rsa" and "ssh-dss".

*
The HTTP Signature scheme as specified may seem rather ambiguous for people who generally don't pay attention to authentication details except when asked for a username or password.



Overview
========

* *httpsig-api*: Provides the Key and KeyIdentifier interfaces along with concrete implementations for Signer, Verifier, SignatureBuilder, Challenge, and Authorization.

* *httpsig-jce*: Provides a JCE-based Key implementation for RSA and DSA key algorithms.

* *httpsig-bouncycastle*:

* *httpsig-helpers*:

* *net.adamcin.httpsig.osgi*:

* *httpsig-jsch*:

* *httpsig-test-common*: