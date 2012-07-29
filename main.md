% Transport Layer Security and Security on the World Wide Web
% Luke Granger-Brown
% July 2012

<!-- Essay length should be 2000-3000 words! -->

<!-- [[BIB]] [[BIBSTYLE=harvard3]] [[TOC]] -->

# What is TLS?
TLS is a protocol which provides cryptographic security for communications over the networks, particularly the Internet. It is the successor of Secure Sockets Layer (SSL), which was originally developed by Netscape Communications.

## The Secure Network Programming API
The first ideas of TLS can be found within the Secure Network Programming API. The original goals of the SNP API were to provide a transport API which closely resembled the sockets that programmers were already using, to enable them to easily and transparently build security into their applications, and to allow old or preexisting applications to have secure communication capabilities added to them transparently. SNP originated in a research paper [@snp1994] first presented in 1994 by a group of researchers from the University of Texas. The researchers recognised the problems with the very low level security APIs already available to developers - they were complex and unwieldy, demanding lots of application-specific code to integrate security. They were also flawed, in that any new cryptographic algorithms would require many changes to adapt applications to make use of them, and required an in-depth knowledge of the rapidly changing security landscape.

SNP never saw common use on the World Wide Web.

## SSL 2.0 and PCT 1.0
Netscape Communications Corporation (Netscape) then developed the Secure Sockets Layer, which used much of the same concepts as SNP. It is unknown whether the authors of the SSL protocol had read the SNP paper. SSL 1.0 was only ever developed internally within Netscape and never saw a public release, but SSL 2.0 was first released in 1994 as a proprietary standard [@ssl20]. Microsoft then developed the Private Communications Technology 1.0 (PCT 1.0) [@pct10], which was allegedly designed to force Netscape into handing the SSL standard over to a standards body. It also addressed some security flaws in SSL 2.0.

Both of these protocols are now disused and contain security flaws (such as the use in SSL 2.0 of the MD5 message authentication function [@rfc6176], and the ability for a third party to arbitrarily close SSL 2.0 network connections [@rfc6176]) which means that they are now disabled by default in all modern Web browsers and servers.

## SSL 3.0
The "March 1996" draft of SSL 3.0 [@ssl30march1996] was then released as a complete rewrite of SSL by Paul Kocher working with two Netscape engineers. It was revised to form a "November 1996" Internet Draft [@ssl30november1996], and was then later published as an IETF RFC, numbered 6101 [@rfc6101]. It is this revised version which is the basis of TLS 1.0 upwards.

SSL 3.0 had 4 stated goals (taken from the March 1996 document, in order of importance):

1. Cryptographic security (allowing secure communications between two parties)
2. Interoperability (independent programmers should be able to produce applications to a common standard which can exchange cryptographic parameters without knowledge of one another's code)
3. Extensibility (new public key and bulk encryption methods should be able to be incorporated easily, to prevent the need to create a new protocol and avoiding the need for an entirely new security library)
4. Relative efficiency (cryptography is CPU intensive, so the SSL protocol contains mitigation schemes for both this and also reducing network activity)

SSL 3.0 is still in use today, and is enabled in most Web browsers by default, including Internet Explorer, Firefox and Google Chrome. For the purposes of this essay, I will treat Firefox and Google Chrome similarly, as they both use the Mozilla project's Network Security Services library [@mozillanss] [@chromenss]. Note that Chrome versions prior to June 15th 2012 used platform specific APIs on Windows and OS X, rather than NSS, and Chrome on Android still uses OpenSSL.

## TLS 1.0
TLS 1.0 was defined by an Internet Standards Track Request For Comments (RFC), numbered 2246 [@rfc2246], as an upgrade, albeit an incompatible one, to SSL 3.0 [@rfc6101]. Most of the specification is very close to SSLv3, with wording which is identical in many cases, and section numbers remaining consistent. The differences include:

* Changing the uses of MACs to HMACs
* Requiring the implementation of TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA in all TLS compliant applications (TLS, with ephemeral Diffie-Hellman key exchange, using DSS signatures, with Triple-DES EDE used as the encryption system in cipher-block-chaining mode, using SHA1 as the MAC)
* Key derivation now uses both MD5 and SHA1. In SSLv3, half of the master key was dependent on MD5, which is not resistant to collisions and is considered insecure.

TLS 1.0 is the most widely used version of the TLS standard, although efforts are underway to upgrade to later versions of the TLS standard.

## TLS 1.1 and 1.2
TLS 1.1 was defined in RFC4346 [@rfc4346] to enhance the security of TLS 1.0. TLS 1.2 was defined in RFC5246 [@rfc5246] (and refined in RFC6176 [@rfc6176] to finally remove the SSL 2.0 fallbacks).

# An overview of Web security

## Certificates
Certificates are files which consist of pieces of identifying information (such as the serial number, subject and expiration date), as well as a signature from an issuer. They also have a (usually separate) "private key" which is a set of bytes which matches the public key and is used to sign information as coming from a particular certificate. If when the signature is decrypted with the public key, valid information can be retrieved and read, that signature can be verified as having come from that certificate. If garbage data is read, then it is likely that the wrong public key was used to decrypt the signature and thus that signature does not correspond with that certificate.

## Certificate Authorities
Certificate Authorities (CAs) are a key concept behind the verification of the identities of either the client or server. CAs are organisations, usually commercial companies, such as VeriSign, Comodo and DigiNotar, which issue certificates signed by a root certificate. These "root certificates" are included with each client or server, and many certificate authorities cross-sign such that each CA is trusted by a number of other CAs. They are known as root certificates because they form the "root" of the certificate chain. These certificates can be used for many applications, such as to verify the country of origin of ePassports, to allow certificate-based log on to computer systems, as well as for verifying the identity of servers and clients. Their public keys can also be used in public key cryptography to encrypt messages which can only be decrypted by the holder of the matching certificate (which contains the private key).

### Controversy
As CAs tend to be very large corporations, with many resellers, it is vitally important that they can fully verify the identities of the entities to which they are issuing certificates. The entire CA architecture is based upon trust. If this trust breaks down, any certificates issued by that certificate authority become worthless. Notable incidents include when VeriSign issued two certificates in 2001 with the name "Microsoft Corporation" to a person supposedly representing Microsoft, as well as fraudulent DigiNotar certificates used to execute man-in-the-middle attacks in Iran. DigiNotar has since been "stricken from the record", and removed from all major browsers and operating systems. This effectively terminates all business with that CA - they can no longer issue valid certificates.

It is believed that some CAs are controlled indirectly by governments, and it is therefore possible that they may issue "subordinate" root certificates which are given the ability to sign further certificates. These certificates could allow man-in-the-middle attacks by generating them for websites such as Facebook or your bank to allow all your supposedly secure traffic to be intercepted and inspected by these authorities. This is believed to have happened in Iran (hackers obtained certificates from DigiNotar, and they later appeared in use by users attempting to connect to Gmail, possibly for the detection of political activists).

With approximately 650 known certificate authorities, it is difficult to validate the security of all of the authorities and organisations behind them. Even if certificate authorities were found to be insecure and are removed this represents a problem for all the websites who use certificates issued by them. For example, Moxie Marlinspike said that although he distrusts the CA Comodo, he cannot remove their certificate because over one-fifth of Web sites use certificates issued by Comodo and those Web sites would no longer be able to be connected to securely.

### Alternatives
Several people have come up with, usually decentralised, alternatives to the certificate authority system, but none are in common use today.

One alternative is Moxie Marlinspike's Convergence [@convergence] relies on users trusting a set of "notaries", which can be run by anyone. Their decisions only affect those who choose to trust that notary, and can be set to require trust from multiple notaries. It was unveiled in the talk he gave at BlackHat USA 2011, SSL And The Future Of Authenticity [@marlinspikeblackhat2011].

The difference between a notary and the current certificate authority system is that it is possible to remove trust from a single notary without rendering large swathes of the web inaccessible.

## Certificate Pinning
Certificate pinning is a way of avoiding the possibilities of "evil" root certificate authorities. This is, however, application protocol- (and even sometimes application-) specific. Certificate pinning provides a method for a certificate's public key hash to be set as the only hash which is permissible for a given Web site's certificate, normally for a given timespan. This means that even if a valid signed certificate is sent for that particular domain, it will be rejected by the client as it does not match the previous certificate used.

Chrome 13 added built-in certificate pinning for websites such as Gmail and the Google Accounts log-on page, as well as adding HTTP Strict Transport Security, allowing Web sites to elect this to occur for themselves by sending an HTTP header over TLS, as well as allowing Web sites to tell the Web browser they must always be accessed over HTTPS (known as SSLstrip protection).

SSLstrip attacks are a class of attacks which transparently and secretlymajormajor proxy all HTTP requests, locate HTTPS links and replace all HTTPS links with HTTP links. They intercept all the traffic intended to be sent securely and send them to the proxy over HTTP, and the proxy then connects to the target server over HTTPS, providing such niceties as a fake padlock-style icon to be displayed in the browser to give users a false sense of security.

Notably, however, certificate pinning also breaks various user-intended man-in-the-middle proxies. The Portsmouth Grammar School's (PGS) own web proxy breaks when presented with Chrome, because when you attempt to access a website which is blocked, or attempt to download a file from an allowed website over HTTPS, but that website has a pinned certificate, you are presented with a dialog allowing you no option to continue, rather than the block page or file-scanning page which you would otherwise expect - users are known to be unreliable and simply click "allow" so for the security to work at all, the option to bypass it must be removed.

To mitigate this, Chrome allows user-installed certificate authorities to override pinned certificates, however PGS' Smoothwall install does not appear to have a self-signed CA root, nor one which is installed on all the client PCs.

## Attacks against TLS
As TLS is so widely used, it has endured many attacks and revisions designed to mitigate the effect of these attacks.

One of these attacks, known as the BEAST attack or Browser Exploit Against SSL/TLS, became fairly well known. It allows the stealing of cookies from a TLS session, which could allow the attacker to log in as you (cookies are the mechanism to allow web sites to remember you and allow you to log in to websites). The original BEAST attack was detected a long time before it was actually demonstrated, because it was deemed to be impractical - it was fixed in the TLS 1.1 standard. It relies on issues with Cipher Block Chaining in TLS 1.0.

### Encryption, ECB, CBC and BEAST
Encrypting short messages is simple - for systems like AES which have 16-byte blocks, and your message is 16-bytes, you can simply encrypt the entire message. The issue arises when you need to encrypt longer messages.

The simplest system for doing so is to simply cut the message up into 16-byte blocks and then encrypt each with the key separately - this system is known as ECB, or Electronic Code Book. Wikipedia provides a neat illustration on why this is a bad idea:

![Figure 1a: Linux Penguin, pre-encryption](Tux.jpg) ![Figure 1b: Linux Penguin, encrypted with ECB](Tux_ecb.jpg) ![Figure 1c: Linux Penguin, encrypted with a more secure encryption scheme](Tux_secure.jpg)
---------------------------------------------------- ------------------------------------------------------------ -------------------------------------------------------------------------------------------
Prior to encryption                                  Encrypted with ECB                                           Encrypted with, e.g. CBC

As you can see, the outline of the penguin is still easily distinguishible in the ECB version - it may be possible to figure out what the original message was, based merely on the data that is retained. In addition, ECB also allows for easier replay attacks, where the attacker knows what the plaintext is likely to do, and can repeat actions that have previously been performed simply by repeating the encrypted message.

CBC takes another value in addition to the key: an initialisation vector, or IV. This IV is XORed with the plaintext before it is encrypted, and then the encrypted ciphertext of that block is XORed with the next block's plaintext before it is encrypted, and then *that* block's ciphertext is XORed with the next block's plaintext, etc.

In TLS 1.0, however, there is a fatal mistake: the same IV is used across several different messages (sets of blocks). This means that, given time and enough messages, it is possible to work out bits of a message.

The BEAST attack did something similar to this, in a 16-byte block:\
XXXXXXXXXXXXXXXp\
where X is set by the attacker, and p is a single byte (the first byte of the secret) sent by the original party. Since a byte can only take 256 different values, it is trivial for a computer to work out what the first byte of this secret is.

Having worked this out, BEAST then tries this:\
XXXXXXXXXXXXXXpq\
Again, X is set by the attacker, but p is now known by the attacker - they just worked it out. q is the next byte of the secret, and can again only take 256 different values.

This sequence is repeated until the entire secret is known.

TLS 1.1 fixed this by randomizing the IV for each message, but as a workaround for TLS 1.0, OpenSSL and some other libraries have a feature known as the "empty record" feature, which is technically permissible by the SSL 3.0 and TLS 1.0 standard, but causes some non-compliant TLS implementations to fail, so is disabled by default. This feature sends a blank block for every message before actually sending the message that should have been sent. This effectively randomizes the IV, mitigating this vulnerability. Most web browsers, however, use a slightly different approach: they send only a single byte of application data in the first record, then the rest of the data in the second record. This is because some libraries treat the 0-byte record as a 0-byte read, which applications can take to mean that the connection has ended.

Another workaround for avoiding this vulnerability was simply to not use any CBC ciphers and to use (in the case of HTTPS) RC4 instead, which uses a keystream rather than a block cipher.

## Why are we still using TLS 1.0?
Adam Langley, a Google engineer working on Chrome, noted that many servers are buggy when it comes to negotiating different versions of TLS [@tlsversions]. Instead of participating properly in the version negotiation, they will simply fail and either send a TLS error or simply close the connection if the client tries to use a higher TLS version. It's not just the target server that has to be contended with and issues detected - some intermediate network MITM devices will also fail connections if the client tries to negotiate a TLS version higher than 1.0, usually by simply closing the connection.

This means that although Google and other services now support TLS 1.2, and iOS 5 supports TLS 1.2, the security benefits of higher versions of TLS are lost due to the need to renegotiate connections at a lower version if they fail - this can be forced simply by an attacker sending a single non-encrypted packet! Chrome will even fall back to SSL 3.0 if another TLS error occurs, which eliminates the forward secrecy provided by the Elliptic Curve Diffie-Hellman Ephemeral key exchange.

Forward secrecy, and perfect forward secrecy, is the guarantee that this communication has keys independent from all other keys used before. This means that even if an attacker breaks one particular communication's keys, all other communications are still secure.

# References
Citation abbreviations:

* IC - Independent Consultant
* NC/NCC - Netscape Communications Corporation
* MP - Mozilla Project

