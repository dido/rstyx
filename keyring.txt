
= Inferno's Keyring Authentication Protocol

Since I don't seem to have seen the Inferno authentication protocol
documented fully anywhere else, I think I ought to write up what I've
learned about it here, from reading both the Inferno manual pages
and some of the source code (which is fragmented and confusing) and
Charles Forsyth's styx-n-9p code.

== Protocol Messages

The authentication protocol sends data over the wire using UTF-8 text
only; any binary data such as key information must first be encoded as
Base64 text.

A single protocol message consists of a byte length , which is
represented as a four-digit zero padded number, followed by a newline
(UTF-8 linefeed U+000A), followed by the actual data itself.

Error messages result with the byte length limited to three digits,
and prefixed with an exclamation point.

== Authentication information

The authentication information for a user consists of the following
information:

1. A public key.
2. A private key.
3. A certificate, i.e. the user's public key signed by another public
   key which is recognized by the entire system as a whole.
4. The certificate signer's public key.
5. Diffie-Hellman parameters in common use throughout the system (a
   large prime number p and a generator of the Galois group Z_p used
   in the Diffie-Hellman protocol.

Each of these five pieces of data is stored in a file in the format of
a protocol message.  Any big numbers (such as the prime base and
generator for the Diffie-Hellman protocol) are encoded as big-endian
numbers, Base64-encoded as required by the protocol message format.
It is to be noted that if the high-order bit of the number to be
encoded in Base64 is 1, there should be an extra one byte with value
of 0 prepended to the byte string representing the number.

Presumably, other public key algorithms are supported by Inferno
authentication, but at the moment I only know of how Inferno uses
RSA.

RSA public keys are represented as follows:

1. the string 'rsa'
2. the public modulus (OpenSSL's n parameter)
3. the public exponent (OpenSSL's e)

RSA secret (private) keys are represented as follows:

1. the string 'rsa'
2. the public modulus (n)
3. the public exponent (e)
4. the private exponent (d)
5. the secret prime factor p
6. the secret prime factor q
7. the prime exponent d mod (p-1)
8. the prime exponent d mod (q-1)
9. the coefficient q^-1 mod p

It is to be noted that Inferno's libsec reverses the roles of p and q,
compared to PKCS#1-compliant implementations such as OpenSSL and
Java's cryptography layer, so the values of 5, 6, 7, and 8 must be
reversed.

RSA certificates have the following information:

1. The signature algorithm (rsa)
2. The hash algorithm (usually sha1)
3. The name of the signer
4. The expiration date in seconds from the epoch, 0 if the certificate
   is to never expire
5. The hash of the data, followed by the signer's name, followed by a
   space, followed by the expiration date.

Diffie-Hellman parameters are represented as follows:

1. The prime modulus p of the Diffie-Hellman system
2. The generator g (called alpha in libsec and styx-n-9p)

== Protocol Flow

1. On connecting, each peer first sends the version number of the
   protocol it understands as a protocol message.  The version number
   may be any number up to four digits long.  The only version number
   recognized by Inferno (up to 4th edition) is 1.
2. Each peer checks the version number of its partner and checks to
   see whether it supports that version.  If it does not, send an
   error message to the peer saying that the authentication protocol
   is not recognized.
3. If the version negotiation has successfully taken place, the
   participant uses the Diffie-Hellman station to station protocol to
   perform authentication.  The participant generates a random secret
   r0, computes alpha**r0 mod p, and sends this, followed by its
   certificate and its public key, to its peer.
4. The participant then receives from the peer its own value alpha**r1
   mod p and the peer's certificate and public key.
5. The participant verifies the authenticity of the peer's
   certificate.
6. The participant sends a certificate to the peer signed using its
   own private key consisting of alpha**r0 mod p followed by alpha**r1
   mod p.
7. The peer sends a certificate to the participant signed using its
   own private key consisting of alpha**r1 mod p followed by alpha**r0
   mod p.
8. The participant verifies that the certificate sent by the peer can
   be decrypted using the peer's public key, and the resulting hash
   matches with the hash of alpha**r1 mod p followed by alpha**r0
   mod p.
9. If the verification is successful, the participant sends a protocol
   message containing 'OK' to the peer.
10. The peer should also send an OK back to the client.

At this point, both participant and peer share the secret
alpha**(r0*r1), which may be used for further communication.

== Cryptography

A client may then send an encryption/digest algorithm descriptor for
further use of the connection, which is then encrypted using SSL.
Usually 'none' is used here.

An encrypted connection uses the SSLv2/TLS record layer protocol (but
not the SSL handshaking protocol).

$Id: keyring.txt 262 2007-09-18 05:15:21Z dido $
