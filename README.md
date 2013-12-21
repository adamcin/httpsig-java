httpsig-java
============

Implementation of Joyent's [HTTP Signature Authentication](https://github.com/joyent/node-http-signature/blob/master/http_signing.md) in Java

Introduction
============

This project is an adaptation of an earlier work I started on an [SSHKey Authentication Scheme](https://github.com/adamcin/net.adamcin.sshkey). 

At some point, I discovered that Joyent had their own implementation of a similar scheme for JavaScript, so I decided to that porting my implementation over to their scheme would be better in the long run, as they had made more progress on a specification as well as already having some adoption. Luckily, I was able to switch over completely to the Joyent spec after only a few weeks of refactoring.

The HTTP Signature scheme as specified may seem rather ambiguous for people who generally don't pay attention to authentication details except when asked for a username or password. I find it easier to first describe the use-case that initially inspired me to embark on this project. 

As a DevOps Engineer at Acquity Group (now part of Accenture Interactive), part of my job is to maintain the Jenkins build and deployment pipelines for our Managed Services clients, and specifically those who are running Adobe CQ5.

... in progress

Overview
========
