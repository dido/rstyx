#!/usr/bin/env ruby
#
# Author:: Rafael R. Sevilla
# Copyright:: Copyright (c) 2005-2007,2017 Rafael R. Sevilla
# Homepage:: https://github.com/dido/rstyx
# License:: GNU Lesser General Public License / Ruby License
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2005-2007,2017 Rafael Sevilla
# This file is part of RStyx
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of either 1) the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version; or 2) Ruby's license.
#
# See the file COPYING for complete licensing information
#
#----------------------------------------------------------------------------
#
# This is an implementation of the Inferno authentication protocol
# (keyring). Adapted from the styx-n-9p Java code.
#
require 'openssl'
require 'rstyx/errors'
require 'digest/sha1'

module RStyx
  module Keyring
    MAX_MSG = 4096

    ##
    # Convert a big-endian byte string _str_ into a bignum.
    #
    def self.str2big(str)
      val = 0
      str.each_byte do |b|
        val = val*256 + b
      end
      return(val)
    end

    ##
    # Convert a big-endian, base64-encoded byte string _str2_ into a bignum
    #
    def self.s2big(str2)
      str = str2.unpack("m")[0]
      return(str2big(str))
    end

    ##
    # Convert a bignum _val_ into a big-endian base64-encoded byte string
    #
    def self.big2s(val)
      str = ""
      while val > 0
        c = val % 256
        str = c.chr + str
        val = val / 256
      end
      # Force leading 0 byte for compatibility with older representation
      # See libinterp/keyring.c function bigtobase64.
      if str.length != 0 && ((str[0] & 0x80) != 0)
        str = "\0" + str
      end
      str = [str].pack("m")
      # Ruby will add newlines into the Base64 representation.  Remove
      # them; they're useless.
      str.tr!("\n", "")
      return(str)
    end

    ##
    # Modular exponentiation.  Computes _b_^_e_ mod _m_ using the square
    # and multiply method.
    #
    def self.mod_exp(b, e, m)
      res = 1
      while e > 0
        if e[0] == 1
          res = (res * b) % m
        end
        e >>= 1
        b = (b*b) % m
      end
      return(res)
    end

    ##
    # Determine the size of _i_ in bits.
    #
    def self.bit_size(i)
      hibit = i.size * 8 - 1
      while (i[hibit] == 0)
        hibit -= 1
        break if hibit < 0
      end

      return(hibit + 1)
    end

    ##
    # Generate a random number between p and q.  Uses OpenSSL::Random to
    # generate the random number.
    #
    def self.randpq(p, q)
      if p > q
        t = p
        p = q
        q = t
      end
      diff = q - p
      if diff < 2
        raise RuntimeError.new("range must be at least two")
      end
      l = Keyring.bit_size(diff)
      t = 1 << l
      l = (l + 7) & ~7          # nearest byte
      slop = t % diff
      r = -1
      while r < slop
        buf = OpenSSL::Random.random_bytes(l)
        r = 0
        buf.each_byte do |b|
          r = r*256 + b
        end
      end
      return((r % diff) + p)
    end

    ##
    # Try to receive a message. Returns an array:
    # 0. The total length required for decode (0 -> message decoded)
    # 1. The message received or the error message
    # 2. The remaining unconsumed data
    def self.recvmsg(data)
      if data.length < 5
        # Not enough data to read the length, return the data
        return([5, nil, data])
      end
      if data[4..4] != "\n"
        raise IOError, "bad message syntax"
      end

      num,z = data.unpack("A5A*")
      iserr = false
      n = 0
      if num =~ /^(!?)([0-9]+)$/
        iserr = $1 == "!"
        n = $2.to_i
      else
        raise IOError, "bad message syntax"
      end

      if n < 0 || n > MAX_MSG
        raise IOError, "bad message syntax"
      end

      if z.length < n
        # insufficient data
        return([n, nil, data])
      end

      if iserr
        raise RemoteAuthErr, z[0..n-1]
      end
      return([0, z[0..n-1], z[n..-1]])
    end

    ##
    # Get protocol messages from a file descriptor
    def self.getmsg(fd)
      msg = ""
      loop do
        len, msg, = self.recvmsg(msg)
        if len == 0
          return(msg)
        end
        msg << fd.read(len)
      end
    end

    ##
    # An Inferno public key.
    #
    class InfPublicKey
      ##
      # The actual public key, as an OpenSSL::PKey::RSA object
      #
      attr_accessor :pk
      ##
      # The owner of the public key
      #
      attr_accessor :owner

      ##
      # Create a new Inferno public key, given the OpenSSL
      # public key and the owner
      #
      def initialize(pk, owner)
        @pk = pk
        @owner = owner
      end

      ##
      # Create a new public key, given a public key record string such
      # as might be read from an Inferno keyring file.
      #
      def self.from_s(s)
        a = s.split("\n")
        if a.length < 4
          raise InvalidKeyException.new("bad public key syntax")
        end

        if a[0] != "rsa"
          raise InvalidKeyException.new("unknown key algorithm #{a[0]}")
        end

        n = Keyring.s2big(a[2])
        e = Keyring.s2big(a[3])
        pk = OpenSSL::PKey::RSA.new
        pk.n = n
        pk.e = e
        return(InfPublicKey.new(pk, a[1]))
      end

      ##
      # Return the public key information as a string suitable for writing
      # as a protocol message or in the Inferno keyfile format.
      def to_s
        str = <<EOS
rsa
#{@owner}
#{Keyring.big2s(@pk.n.to_i)}
#{Keyring.big2s(@pk.e.to_i)}
EOS
        return(str)
      end
    end

    ##
    # An Inferno private key.
    #
    class InfPrivateKey
      ##
      # The private (secret) key as an  OpenSSL::PKey::RSA object
      #
      attr_accessor :sk
      ##
      # The owner of the private key
      #
      attr_accessor :owner

      ##
      # Create a new Inferno private key, given the OpenSSL
      # private key and the owner
      #
      def initialize(sk, owner)
        @sk = sk
        @owner = owner
      end

      ##
      # Create a new private key, given a private key record string such
      # as might be read from an Inferno keyring file.
      #
      def self.from_s(s)
        a = s.split("\n")
        if a.length < 10
          raise InvalidKeyException.new("bad private key syntax")
        end

        if a[0] != "rsa"
          raise InvalidKeyException.new("unknown key algorithm #{a[0]}")
        end

        # Mind your p's and q's: libsec's p is OpenSSL's q!  OpenSSL follows
        # PKCS#1 in reversing their roles.  We need to reverse p and q, and
        # dmp1 and dmq1 to use OpenSSL, but for now we do everything in pure
        # Ruby as much as we can.
        sk = OpenSSL::PKey::RSA.new
        sk.n = Keyring.s2big(a[2])
        sk.e = Keyring.s2big(a[3])
        sk.d = Keyring.s2big(a[4])
        sk.p = Keyring.s2big(a[5])
        sk.q = Keyring.s2big(a[6])
        sk.dmp1 = Keyring.s2big(a[7])
        sk.dmq1 = Keyring.s2big(a[8])
        sk.iqmp = Keyring.s2big(a[9])
        return(InfPrivateKey.new(sk, a[1]))
      end

      ##
      # Get the public key information from the private key, which
      # is basically just n and p
      def getpk
        pk = OpenSSL::PKey::RSA.new
        pk.n = @sk.n
        pk.e = @sk.e
        return(InfPublicKey.new(pk, @owner))
      end

      ##
      # Return the private key information as a string suitable for writing
      # as a protocol message or in the Inferno keyfile format.
      def to_s
        str = <<EOS
rsa
#{@owner}
#{Keyring.big2s(@sk.n.to_i)}
#{Keyring.big2s(@sk.e.to_i)}
#{Keyring.big2s(@sk.d.to_i)}
#{Keyring.big2s(@sk.p.to_i)}
#{Keyring.big2s(@sk.q.to_i)}
#{Keyring.big2s(@sk.dmp1.to_i)}
#{Keyring.big2s(@sk.dmq1.to_i)}
#{Keyring.big2s(@sk.iqmp.to_i)}
EOS
        return(str)
      end

      ##
      # Sign a certificate, with an expiration time_exp_ in seconds from
      # the Epoch, and the data to sign _a_.
      #
      def sign(exp, a)
        sha1 = Digest::SHA1.new
        sha1.update(a)
        sha1.update("#{@owner} #{exp}")
        digest = str2big(sha1.digest)
        sig = rsadecrypt(@sk, digest)
        return(Certificate.new("rsa", "sha1", sk.owner, exp, sig))
      end
    end

    ##
    # An Inferno certificate.
    #
    class Certificate
      ##
      # Signature algorithm
      #
      attr_accessor :sa
      ##
      # Hash algorithm
      attr_accessor :ha
      ##
      # Name of signer
      attr_accessor :signer
      ##
      # Expiration date
      #
      attr_accessor :exp
      ##
      # The signature data itself
      #
      attr_accessor :rsa

      ##
      # Create a new certificate instance given the signature algorithm
      # _sa_, the hash algorithm _ha_, the signer name _signer_, the
      # expiration date _exp_ and the signature data _rsa_.
      #
      def initialize(sa, ha, signer, exp, rsa)
        @sa = sa
        @ha = ha
        @signer = signer
        @exp = exp
        @rsa = rsa
      end

      ##
      # Create a new Certificate, given a certificate record string such
      # as might be read from an Inferno keyring file.
      #
      def self.from_s(s)
        a = s.split("\n")
        if a.length < 5
          raise InvalidCertificateException.new("bad certificate syntax")
        end

        sa = a[0]
        ha = a[1]
        signer = a[2]
        exp = a[3].to_i
        rsa = Keyring.s2big(a[4])
        return(Certificate.new(sa, ha, signer, exp, rsa))
      end

      ##
      # Return the certificate information as a string suitable for writing
      # as a protocol message or in the Inferno keyfile format.
      def to_s
        str = <<EOS
#{@sa}
#{@ha}
#{@signer}
#{@exp}
#{Keyring.big2s(@rsa)}
EOS
        return(str)
      end
    end

    ##
    # Set cryptographic algorithms in use, given a connection object _fd_
    # a role _role_ (which may be :client or :server), and a list of
    # algorithms.  Only the first algorithm listed is in use.  This is
    # a stub until we can figure out exactly how Inferno does cryptographic
    # protocol negotiation.
    #
    def self.setlinecrypt(fd, role, algs)
      if role == :client
        if (!algs.nil? && algs.length > 0)
          alg = algs[0]
        else
          alg = "none"          # we need to either figure out how to use SSL without its handshake or write our own code to do cryptography manually.
        end
        sendmsg(fd, alg)
      elsif role == :server
        alg = self.getmsg(fd)
        if alg != "none"
          raise IOError.new("unsupported algorithm: " + alg)
        end
      else
        raise IOException.new("invalid role #{role.to_s}")
      end
      return(alg)
    end

    ##
    # Perform mutual authentication over a network connection _fd_.
    # The _role_ is the role of the connection, which may be either
    # of the symbols :client or :server, _info_ holds an Authinfo
    # object containing this peer's authentication information, and
    # _algs_ the bulk encryption algorithms supported by this peer.
    # See Inferno's keyring-auth(2) for more details on how this
    # should work.
    #
    def self.auth(fd, role, info, algs)
      res = basicauth(fd, info)
      setlinecrypt(fd, role, algs)
      return(res)
    end

    ##
    # Perform RSA encryption given a (public or private) key _pk_ and
    # plaintext _data_ represented as a BigInteger.  Returns the RSA
    # ciphertext as a BigInteger
    #
    def self.rsaencrypt(pk, data)
      return(mod_exp(data, pk.e.to_i, pk.n.to_i))
    end

    ##
    # Perform RSA decryption given a private key _sk_ and ciphertext
    # _data_.
    #
    def self.rsadecrypt(sk, data)
      p = sk.p.to_i
      v1 = data % p
      q = sk.q.to_i
      v2 = data % q
      v1 = mod_exp(v1, sk.dmp1.to_i, p)
      v2 = mod_exp(v2, sk.dmq1.to_i, q)
      return((((v2 - v1)*sk.iqmp) % q)*p + v1)
    end

    ##
    # Verify an RSA signature, given the hash _m_, the signature data _sig_,
    # and the signer public key _key_.
    #
    def self.rsaverify(m, sig, key)
      return(rsaencrypt(key, sig) == m)
    end

    ##
    # Verify a certificate _c_ given the public key of the signer _pk_, and
    # the actual data of the certificate _a_.
    #
    def self.verify(pk, c, a)
      # Check if the certificate algorithm is supported.  At the moment
      # only RSA signatures over SHA-1 are supported.
      unless c.sa == "rsa" && (c.ha == "sha1" || c.ha == "sha")
        return(false)
      end
      sha1 = Digest::SHA1.new
      sha1.update(a)
      sha1.update("#{c.signer} #{c.exp}")
      val = str2big(sha1.digest)
      return(rsaverify(val, c.rsa, pk.pk))
    end

    ##
    # Authentication information, includes private key (if any),
    # public key, certificate, CA public key, and DH parameters.
    class Authinfo
      ##
      # My private (secret) key
      attr_accessor :sk
      ##
      # My public key
      attr_accessor :pk
      ##
      # Signature of my public key
      attr_accessor :cert
      ##
      # Signer's public key
      attr_accessor :spk
      ##
      # Diffie-Hellman p (prime number)
      attr_accessor :p
      ##
      # Diffie-Hellman alpha (generator of Z_p)
      attr_accessor :alpha

      def initialize(sk, pk, cert, spk, alpha, p)
        @sk = sk
        @pk = pk
        @cert = cert
        @spk = spk
        @alpha = alpha
        @p = p
      end

      ##
      # Read authentication information from an IO instance _fd_.
      # This returns an Authenticator instance initialized with the
      # information read from the file.
      #
      def self.readauthinfo(fd)
        spk = InfPublicKey.from_s(Keyring::getmsg(fd))
        cert = Certificate.from_s(Keyring::getmsg(fd))
        mysk = InfPrivateKey.from_s(Keyring::getmsg(fd))
        alpha = Keyring.s2big(Keyring::getmsg(fd))
        p = Keyring.s2big(Keyring::getmsg(fd))
        return(self.new(mysk, mysk.getpk, cert, spk, alpha, p))
      end
    end

    ##
    # Inferno Keyring auth
    class Authenticator < Auth::Authenticator

      ##
      # Authentication information
      attr_accessor :ai

      ##
      # After authentication secret
      attr_accessor :secret

      ##
      # Peer authentication
      attr_accessor :peerauth

      ##
      # Authentication state
      attr_reader :authstate

      ##
      # Authentication error
      attr_reader :autherror

      ##
      # Permitted algorithms for authentication
      attr_reader :reqalgs

      def initialize(authinfo, reqalgs)
        super
        @ai = authinfo
        @data = []
        @authstate = :idle
        @autherror = nil
      end

      def receive_data(data)
        begin
          loop do
            @data << data
            jdata = @data.join
            len, msg, rest = Keyring::recvmsg(jdata)
            # Full message not yet received
            return if len > 0
            @data = []
            # Full message received, process according to current authstate
            case @authstate
            when :idle
              # Do nothing
            when :vneg
              # See if the received version is valid
              if msg.to_i == 1
                # Valid version received, proceed to Diffie-Hellman auth
                @authstate = :dhauth
                # Send to the peer our alpha**r0, certificate, and pubkey
                low = @ai.p >> (Keyring::bit_size(@ai.p) / 4)
                @r0 = Keyring::randpq(low, @ai.p)
                @alphar0 = Keyring::mod_exp(@ai.alpha, @r0, @ai.p)
                sendmsg(Keyring::big2s(@alphar0))
                sendmsg(@ai.cert.to_s)
                sendmsg(@ai.pk.to_s)
              else
                raise LocalAuthError, "incompatible authentication protocol"
              end
            when :dhauth
              # Receive peer's alpha**r1 mod p and the peer's certificate
              # and public key.
              @alphar1 = Keyring::s2big(msg)
              if @ai.p <= @alphar1
                raise LocalAuthError, "implausible parameter value"
              end

              if @alphar0 == @alphar1
                raise LocalAuthError, "possible replay attack"
              end
              @authstate = :dhcert
            when :dhcert
              # Receive peer's certificate
              @hiscert = Certificate.from_s(msg)
              @authstate = :dhpk
            when :dhpk
              @hispkbuf = msg
              @hispk = InfPublicKey.from_s(@hispkbuf)
              unless Keyring::verify(@ai.spk, @hiscert, @hispkbuf)
                raise LocalAuthError, "pk doesn't match certificate"
              end
              if @hiscert.exp != 0 && Time.at(@hiscert.exp) < Time.now
                raise LocalAuthError, "certificate expired"
              end
              @authstate = :dhauth2
              # Send certificate to the peer with alpha**r0 mod p and
              # alpha**r1 mod p
              alphabuf = Keyring::big2s(@alphar0) + Keyring::big2s(@alphar1)
              alphacert = @ai.sk.sign(0, alphabuf)
              sendmsg(alphacert.to_s)
            when :dhauth2
              # Receive the peer's certficate
              alphacert = Certificate.from_s(msg)
              alphabuf = Keyring.big2s(@alphar1) + Keyring.big2s(@alphar0)
              # Verify the certificate from the peer
              unless Keyring::verify(@hispk, alphacert, alphabuf)
                raise LocalAuthError, "signature did not match pk"
              end

              # alpha0r1 is the shared secret
              alpha0r1 = Keyring::mod_exp(alphar1, @r0, @ai.p)
              @secret = "".force_encoding("ASCII-8BIT")
              val = alpha0r1
              while val > 0
                c = val % 256
                @secret << c.chr
                val = val / 256
              end
              # remove any leading nulls
              @secret =~ /\0*(.*)/
              @secret = $1
              # Peer authentication info
              @peerauth = Authinfo.new(nil, @hispk, @hiscert, @ai.spk,
                                       @ai.alpha, @ai.p)
              # Send protocol message OK back to client
              sendmsg("OK")
              @authstate = :waitok
            when :waitok
              if msg =~ /^OK$/
                @authenticated = true
                self.succeed
              end
              @authstate = :idle
            end
            data = rest
          end
        rescue InvalidCertificateException, InvalidKeyException, NoSuchAlgorithmException, LocalAuthErr
          send_errmsg("remote: #{$!.message}")
          @autherror = $!
        rescue RemoteAuthErr
          send_errmsg("missing your authentication data")
          @autherror = AuthenticationException.new($!.message)
        rescue
          @autherror = $!
        end
        @authstate = :idle
        self.fail($!.message)
      end

      def sendmsg(data)
        send_data(sprintf("%04d\n", data.length))
        send_data(data)
      end

      def senderrmsg(data)
        send_data(sprintf("!%03d\n", data.length))
        send_data(data)
      end

      def authenticate
        # Initiate authentication by sending version
        sendmsg("1")
        @authstate = :vneg
        return(self)
      end

    end


  end

end
