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
# Unit tests for Styx messages
#
#
require 'test/unit'
require 'rstyx/common'
require 'rstyx/messages'

class MessageTest < Test::Unit::TestCase
  ##
  # Test the Qid class
  #
  def test_qid
    # Generate a distinctive Styx message
    qid = RStyx::Message::Qid.new(0x01,0xdeadbeef,0xfeedfacec0ffeeee)
    bytes = qid.to_bytes
    # Test if the serialized version is as expected
    assert(bytes == "\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe".force_encoding("ASCII-8BIT"))

    # Try to deserialize and check whether the output is as expected
    qqid = RStyx::Message::Qid.from_bytes(bytes)
    assert(qqid.qtype == 0x01)
    assert(qqid.version == 0xdeadbeef)
    assert(qqid.path == 0xfeedfacec0ffeeee)

    # Test decoding short values
    assert_raise(RStyx::StyxException) { RStyx::Message::Qid.from_bytes("".force_encoding("ASCII-8BIT")) }
    assert_raise(RStyx::StyxException) { RStyx::Message::Qid.from_bytes("     ".force_encoding("ASCII-8BIT")) }

    # Test decoding 13 bytes and with trailing garbage
    assert_nothing_raised { RStyx::Message::Qid.from_bytes("             ".force_encoding("ASCII-8BIT")) }
    assert_nothing_raised { qqid = RStyx::Message::Qid.from_bytes("\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfesome trailing garbage".force_encoding("ASCII-8BIT")) }

    # test if the decoding still works even in the face of trailing garbage
    assert_equal(0x01, qqid.qtype)
    assert_equal(0xdeadbeef, qqid.version)
    assert_equal(0xfeedfacec0ffeeee, qqid.path)

    # test equality
    qid = RStyx::Message::Qid.new(0x01,0xdeadbeef,0xfeedfacec0ffeeee)
    qid2 = RStyx::Message::Qid.new(0x01,0xdeadbeef,0xfeedfacec0ffeeef)
    assert_not_equal(qid, qid2)

    qid2 = RStyx::Message::Qid.new(0x01,0xdeadbeef,0xfeedfacec0ffeeee)
    assert_equal(qid, qid2)

  end

  ##
  # Test the Stat class
  #
  def test_stat
    # generate a dummy Stat for testing
    de = RStyx::Message::Stat.new
    de.dtype = 0x1234
    de.dev = 0x567890ab
    de.qid = RStyx::Message::Qid.new(0x01, 0xdeadbeef,0xfeedfacec0ffeeee)
    de.mode = 0x9abcdef0
    de.atime = 0xdeadbeef
    de.mtime = 0xcafebabe
    de.length = 0xfedcba9876543210
    de.name = "foo"
    de.uid = "bar"
    de.gid = "baz"
    de.muid = "quux"
    bytes = de.to_bytes
    expect = "\x3c\x00\x34\x12\xab\x90\x78\x56\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\xf0\xde\xbc\x9a\xef\xbe\xad\xde\xbe\xba\xfe\xca\x10\x32\x54\x76\x98\xba\xdc\xfe\x03\x00foo\x03\x00bar\x03\x00baz\x04\x00quux".force_encoding("ASCII-8BIT")
    assert(bytes == expect)

    # Generate a new direntry based on the above string
    de2 = RStyx::Message::Stat.from_bytes(expect)
    assert(de2.dtype == 0x1234)
    assert(de2.dev == 0x567890ab)
    assert(de2.qid.qtype == 0x01)
    assert(de2.qid.version == 0xdeadbeef)
    assert(de2.qid.path == 0xfeedfacec0ffeeee)
    assert(de2.mode == 0x9abcdef0)
    assert(de2.atime == 0xdeadbeef)
    assert(de2.mtime == 0xcafebabe)
    assert(de2.length == 0xfedcba9876543210)
    assert(de2.name == "foo")
    assert(de2.uid == "bar")
    assert(de2.gid == "baz")
    assert(de2.muid == "quux")

    # Test decoding truncated strings
    assert_raise(RStyx::StyxException) { RStyx::Message::Stat.from_bytes("") }
    assert_raise(RStyx::StyxException) { RStyx::Message::Stat.from_bytes("\x3c\x00\x34\x12\xab\x90\x78\x56\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\xf0\xde\xbc\x9a\xef\xbe\xad\xde\xbe\xba\xfe\xca\x10\x32\x54\x76") }
    assert_raise(RStyx::StyxException) { RStyx::Message::Stat.from_bytes("\x3c\x00\x34\x12\xab\x90\x78\x56\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\xf0\xde\xbc\x9a\xef\xbe\xad\xde\xbe\xba\xfe\xca\x10\x32\x54\x76\x98\xba\xdc\xfe\x03\x00foo\x03\x00bar\x03\x00baz\x04\x00qu") }

    # Test decoding strings with garbage at the end
    # Generate a new direntry based on the above string
    assert_nothing_raised do
      de2 = RStyx::Message::Stat.from_bytes(expect + "trailing garbage")
    end
    assert(de2.dtype == 0x1234)
    assert(de2.dev == 0x567890ab)
    q = RStyx::Message::Qid.new(0x01, 0xdeadbeef,0xfeedfacec0ffeeee)
    assert(de2.qid.qtype == 0x01)
    assert(de2.qid.version == 0xdeadbeef)
    assert(de2.qid.path == 0xfeedfacec0ffeeee)
    assert(de2.mode == 0x9abcdef0)
    assert(de2.atime == 0xdeadbeef)
    assert(de2.mtime == 0xcafebabe)
    assert(de2.length == 0xfedcba9876543210)
    assert(de2.name == "foo")
    assert(de2.uid == "bar")
    assert(de2.gid == "baz")
    assert(de2.muid == "quux")
  end

  ##
  # Test the Tversion class
  #
  def test_tversion
    tv = RStyx::Message::Tversion.new(:msize => 0xdeadbeef, :version => "9P2000", :tag => 0x1234)
    bytes = tv.to_bytes
    expect = "\x13\x00\x00\x00\x64\x34\x12\xef\xbe\xad\xde\x06\x009P2000".force_encoding("ASCII-8BIT")
    assert(expect == bytes)
    # Try to decode the expect string
    tvm = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(tvm.class == RStyx::Message::Tversion)
    assert(tvm.tag == 0x1234)
    assert(tvm.msize == 0xdeadbeef)
    assert(tvm.version == "9P2000")

    # Try to decode short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x13\x00\x00\x00\x64\x34\x12\xef\xbe\xad\xde\x06\x009P200") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x13\x00\x00\x00\x64\x34\x12\xef\xbe\xad") }

    # Try to decode the expect string with trailing garbage
    tvm = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    assert(tvm.class == RStyx::Message::Tversion)
    assert(tvm.tag == 0x1234)
    assert(tvm.msize == 0xdeadbeef)
    assert(tvm.version == "9P2000")

  end

  ##
  # Test the Rversion class
  #
  def test_rversion
    rv = RStyx::Message::Rversion.new(:msize => 0xdeadbeef, :version => "9P2000", :tag => 0x1234)
    bytes = rv.to_bytes
    expect = "\x13\x00\x00\x00\x65\x34\x12\xef\xbe\xad\xde\x06\x009P2000".force_encoding("ASCII-8BIT")
    assert(expect == bytes)
    # Try to decode the expect string
    rvm = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(rvm.class == RStyx::Message::Rversion)
    assert(rvm.tag == 0x1234)
    assert(rvm.msize == 0xdeadbeef)
    assert(rvm.version == "9P2000")

    # Try to decode short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x13\x00\x00\x00\x65\x34\x12\xef\xbe\xad\xde\x06\x009P200") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x13\x00\x00\x00\x65\x34\x12\xef\xbe") }

    # Try to decode with trailing garbage
    assert_nothing_raised do
      rvm = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(rvm.class == RStyx::Message::Rversion)
    assert(rvm.tag == 0x1234)
    assert(rvm.msize == 0xdeadbeef)
    assert(rvm.version == "9P2000")
  end

  ##
  # Test the Tauth class.
  #
  def test_tauth
    ta = RStyx::Message::Tauth.new(:uname => "foo", :afid => 0x9abcdef0, :aname => "bar", :tag => 0x1234)
    bytes = ta.to_bytes
    expect = "\x66\x34\x12\xf0\xde\xbc\x9a\x03\x00foo\x03\x00bar".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    expect = [len].pack("V") + expect
    assert(bytes == expect)
    ta2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(ta2.class == RStyx::Message::Tauth)
    assert(ta2.tag == 0x1234)
    assert(ta2.afid == 0x9abcdef0)
    assert(ta2.uname == "foo")
    assert(ta2.aname == "bar")

    # Try to decode short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::Tauth.from_bytes("1234567890") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x66\x34\x12\xf0\xde\xbc\x9a\x03\x00foo\x03\x00b") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x66\x34\x12\xf0\xde\xbc") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x66\x34") }

    # decode with trailing garbage
    assert_nothing_raised do
      ta2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(ta2.class == RStyx::Message::Tauth)
    assert(ta2.tag == 0x1234)
    assert(ta2.afid == 0x9abcdef0)
    assert(ta2.uname == "foo")
    assert(ta2.aname == "bar")
  end

  ##
  # Test the Rauth class.
  #
  def test_rauth
    ra = RStyx::Message::Rauth.new(:aqid => RStyx::Message::Qid.new(0x01, 0xdeadbeef, 0xfeedfacec0ffeeee), :tag => 0x1234)
    bytes = ra.to_bytes
    expect = "\x67\x34\x12\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    expect = [len].pack("V") + expect
    assert(expect == bytes)
    ra2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(ra2.class == RStyx::Message::Rauth)
    assert(ra2.tag == 0x1234)
    assert(ra2.aqid.qtype == 0x01)
    assert(ra2.aqid.version == 0xdeadbeef)
    assert(ra2.aqid.path == 0xfeedfacec0ffeeee)
    # Try to decode short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x67\x34\x12\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed".force_encoding("ASCII-8BIT")) }

    # Decode with trailing garbage
    assert_nothing_raised do
      ra2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage".force_encoding("ASCII-8BIT"))
    end
    assert(ra2.class == RStyx::Message::Rauth)
    assert(ra2.tag == 0x1234)
    assert(ra2.aqid.qtype == 0x01)
    assert(ra2.aqid.version == 0xdeadbeef)
    assert(ra2.aqid.path == 0xfeedfacec0ffeeee)
  end

  ##
  # Test the Rerror class
  #
  def test_rerror
    rerr = RStyx::Message::Rerror.new(:ename => "error", :tag => 0x1234)
    bytes = rerr.to_bytes
    expect = "\x0e\x00\x00\x00\x6b\x34\x12\x05\x00error"
    assert(bytes == expect)

    # Try to decode the expect string
    emsg = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(emsg.class == RStyx::Message::Rerror)
    assert(emsg.tag == 0x1234)
    assert(emsg.ename == "error")

    # Try to decode short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x0e\x00\x00") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x0e\x00\x00\x00\x6b\x34\x12\x05\x00erro") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x0e\x00\x00\x00\x6b\x34\x12\x05\x00erro") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes("\x0e\x00\x00\x00\x6b\x34\x12") }

    # Try to decode strings with trailing garbage
    assert_nothing_raised do
      emsg = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(emsg.class == RStyx::Message::Rerror)
    assert(emsg.tag == 0x1234)
    assert(emsg.ename == "error")
  end

  ##
  # Test the Tflush class.
  #
  def test_tflush
    tf = RStyx::Message::Tflush.new(:oldtag => 0x5678, :tag => 0x1234)
    bytes = tf.to_bytes
    expect = "\x6c\x34\x12\x78\x56"
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # decode expect
    tf2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(tf2.class == RStyx::Message::Tflush)
    assert(tf2.tag == 0x1234)
    assert(tf2.oldtag == 0x5678)

    # try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x6c\x34\x12\x78") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x6c\x34\x12") }

    # decode with trailing garbage
    tf2 = nil
    assert_nothing_raised do
      tf2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(tf2.class == RStyx::Message::Tflush)
    assert(tf2.tag == 0x1234)
    assert(tf2.oldtag == 0x5678)
  end

  ##
  # Test the Rflush class.
  #
  def test_rflush
    tf = RStyx::Message::Rflush.new(:tag => 0x1234)
    bytes = tf.to_bytes
    expect = "\x6d\x34\x12"
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # decode expect
    rf2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(rf2.class == RStyx::Message::Rflush)
    assert(rf2.tag == 0x1234)

    # try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x6d\x34") }

    # decode with trailing garbage
    rf2 = nil
    assert_nothing_raised do
      rf2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(rf2.class == RStyx::Message::Rflush)
    assert(rf2.tag == 0x1234)

  end

  ##
  # Test the Tattach class.
  #
  def test_tattach
    ta = RStyx::Message::Tattach.new(:fid=> 0x12345678, :uname => "foo", :afid => 0x9abcdef0, :aname => "bar", :tag => 0x1234)
    bytes = ta.to_bytes
    expect = "\x68\x34\x12\x78\x56\x34\x12\xf0\xde\xbc\x9a\x03\x00foo\x03\x00bar".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V") 
    expect = packlen + expect
    assert(expect == bytes)

    # Decode expect string
    ta2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(ta2.class == RStyx::Message::Tattach)
    assert(ta2.tag == 0x1234)
    assert(ta2.fid == 0x12345678)
    assert(ta2.afid == 0x9abcdef0)
    assert(ta2.uname == "foo")
    assert(ta2.aname == "bar")

    # Try to decode short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x68\x34\x12\x78\x56\x34\x12\xf0\xde\xbc\x9a\x03\x00foo\x03\x00ba") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x68\x34\x12\x78\x56\x34\x12\xf0\xde\xbc\x9a\x03\x00fo") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x68\x34\x12\x78\x56\x34\x12\xf0\xde\xbc") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x68\x34\x12\x78\x56\x34\x12\xf0") }

    # Decode expect string with trailing garbage
    assert_nothing_raised do
      ta2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(ta2.class == RStyx::Message::Tattach)
    assert(ta2.tag == 0x1234)
    assert(ta2.fid == 0x12345678)
    assert(ta2.afid == 0x9abcdef0)
    assert(ta2.uname == "foo")
    assert(ta2.aname == "bar")
  end

  ##
  # Test the Rattach class.
  #
  def test_rattach
    ra = RStyx::Message::Rattach.new(:qid => RStyx::Message::Qid.new(0x01, 0xdeadbeef, 0xfeedfacec0ffeeee), :tag => 0x1234)
    bytes = ra.to_bytes
    expect = "\x69\x34\x12\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V") 
    expect = packlen + expect
    assert(expect == bytes)

    ra2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(ra2.class == RStyx::Message::Rattach)
    assert(ra2.tag == 0x1234)
    assert(ra2.qid.qtype == 0x01)
    assert(ra2.qid.version == 0xdeadbeef)
    assert(ra2.qid.path == 0xfeedfacec0ffeeee)

    # Try to decode short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x69\x34\x12\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed") }

    # Decode with trailing garbage
    assert_nothing_raised do
      ra2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(ra2.class == RStyx::Message::Rattach)
    assert(ra2.tag == 0x1234)
    assert(ra2.qid.qtype == 0x01)
    assert(ra2.qid.version == 0xdeadbeef)
    assert(ra2.qid.path == 0xfeedfacec0ffeeee)
  end

  ##
  # Test the Twalk class.
  #
  def test_twalk
    tw = RStyx::Message::Twalk.new(:fid => 0x12345678, :newfid => 0x9abcdef0,
                                   :wnames => ["foo", "bar", "baz",
                                               "quux", "blargle"],
                                   :tag => 0x1234)
    bytes = tw.to_bytes
    expect = "\x6e\x34\x12\x78\x56\x34\x12\xf0\xde\xbc\x9a\x05\x00\x03\x00foo\x03\x00bar\x03\x00baz\x04\x00quux\x07\x00blargle".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V") 
    expect = packlen + expect
    assert(expect == bytes)
    tw2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(tw2.class == RStyx::Message::Twalk)
    assert(tw2.tag == 0x1234)
    assert(tw2.fid == 0x12345678)
    assert(tw2.newfid == 0x9abcdef0)
    assert(tw2.path = "foo/bar/baz/quux/blargle")

    # Test short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x6e\x34\x12\x78\x56\x34\x12\xf0\xde\xbc\x9a\x05\x00\03\x00foo\x03\x00bar\x03\x00baz\x04\x00quux") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x6e\x34\x12\x78\x56\x34\x12\xf0\xde\xbc\x9a") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x6e\x34\x12\x78\x56\x34\x12\xf0\xde") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x6e\x34\x12\x78\x56\x34\x12\xf0") }

    # trailing garbage test
    assert_nothing_raised do
      tw2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(tw2.class == RStyx::Message::Twalk)
    assert(tw2.tag == 0x1234)
    assert(tw2.fid == 0x12345678)
    assert(tw2.newfid == 0x9abcdef0)
    assert(tw2.path = "foo/bar/baz/quux/blargle")
  end

  ##
  # Test the Rwalk class.
  #
  def test_rwalk
    qidlist = [
      RStyx::Message::Qid.new(0x01,0xdeadbeef,0xfeedfacec0ffeeee),
      RStyx::Message::Qid.new(0x02,0x12345678,0xfedcba9876543210),
      RStyx::Message::Qid.new(0x03,0x87654321,0x0123456789abcdef)
    ]
    rw = RStyx::Message::Rwalk.new(:qids => qidlist, :tag => 0x1234)
    bytes = rw.to_bytes
    expect = "\x6f\x34\x12\x03\x00\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\x02\x78\x56\x34\x12\x10\x32\x54\x76\x98\xba\xdc\xfe\x03\x21\x43\x65\x87\xef\xcd\xab\x89\x67\x45\x23\x01".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V") 
    expect = packlen + expect
    assert(expect == bytes)

    rw2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(rw2.class == RStyx::Message::Rwalk)
    assert(rw2.tag == 0x1234)
    assert(rw2.qids.length == 3)
    qid = rw2.qids[0]
    assert(qid.qtype == 0x01)
    assert(qid.version == 0xdeadbeef)
    assert(qid.path == 0xfeedfacec0ffeeee)
    qid = rw2.qids[1]
    assert(qid.qtype == 0x02)
    assert(qid.version == 0x12345678)
    assert(qid.path == 0xfedcba9876543210)
    qid = rw2.qids[2]
    assert(qid.qtype == 0x03)
    assert(qid.version == 0x87654321)
    assert(qid.path == 0x0123456789abcdef)

    # Try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x6f\x34\x12\x03\x00\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\x02\x78\x56\x34\x12\x10\x32\x54\x76\x98\xba\xdc\xfe\x03\x21\x43\x65\x87") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x6f\x34\x12\x03\x00") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x6f\x34\x12\x03") }

    # Trailing garbage
    assert_nothing_raised do
      rw2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(rw2.class == RStyx::Message::Rwalk)
    assert(rw2.tag == 0x1234)
    assert(rw2.qids.length == 3)
    qid = rw2.qids[0]
    assert(qid.qtype == 0x01)
    assert(qid.version == 0xdeadbeef)
    assert(qid.path == 0xfeedfacec0ffeeee)
    qid = rw2.qids[1]
    assert(qid.qtype == 0x02)
    assert(qid.version == 0x12345678)
    assert(qid.path == 0xfedcba9876543210)
    qid = rw2.qids[2]
    assert(qid.qtype == 0x03)
    assert(qid.version == 0x87654321)
    assert(qid.path == 0x0123456789abcdef)
  end

  ##
  # Test the Topen class.
  #
  def test_topen
    to = RStyx::Message::Topen.new(:fid => 0x12345678,
                                   :mode => RStyx::OWRITE | RStyx::OTRUNC | RStyx::ORCLOSE,
                                   :tag => 0x1234)
    bytes = to.to_bytes
    expect = "\x70\x34\x12\x78\x56\x34\x12\x51"
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    to2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(to2.class == RStyx::Message::Topen)
    assert(to2.tag == 0x1234)
    assert(to2.mode == 0x51)
    assert(to2.fid == 0x12345678)

    # Try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x70\x34\x12\x78\x56\x34\x12") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x70\x34\x12\x78\x56") }

    # Try decoding with trailing garbage
    assert_nothing_raised do
      to2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(to2.class == RStyx::Message::Topen)
    assert(to2.tag == 0x1234)
    assert(to2.mode == 0x51)
    assert(to2.fid == 0x12345678)
  end

  ##
  # Test the Ropen class.
  #
  def test_ropen
    ro = RStyx::Message::Ropen.new(:qid => RStyx::Message::Qid.new(0x01,0xdeadbeef,0xfeedfacec0ffeeee), :iounit => 0xfedcba98, :tag => 0x1234)
    bytes = ro.to_bytes
    expect = "\x71\x34\x12\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\x98\xba\xdc\xfe".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # Decode expect
    ro2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(ro2.class == RStyx::Message::Ropen)
    assert(ro2.tag == 0x1234)
    assert(ro2.qid.qtype == 0x01)
    assert(ro2.qid.version == 0xdeadbeef)
    assert(ro2.qid.path == 0xfeedfacec0ffeeee)
    assert(ro2.iounit == 0xfedcba98)

    # Try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x71\x34\x12\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\x98\xba") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x71\x34\x12\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed") }

    # Decode with trailing garbage
    assert_nothing_raised do
      ro2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(ro2.class == RStyx::Message::Ropen)
    assert(ro2.tag == 0x1234)
    assert(ro2.qid.qtype == 0x01)
    assert(ro2.qid.version == 0xdeadbeef)
    assert(ro2.qid.path == 0xfeedfacec0ffeeee)
    assert(ro2.iounit == 0xfedcba98)
  end

  ##
  # Test the Tcreate class
  #
  def test_tcreate
    tc = RStyx::Message::Tcreate.new(:fid => 0x12345678, :name => "foo",
                                     :mode => RStyx::OWRITE | RStyx::OTRUNC |
                                     RStyx::ORCLOSE,
                                     :perm => 0xfedcba98,
                                     :tag => 0x1234)
    bytes = tc.to_bytes
    expect = "\x72\x34\x12\x78\x56\x34\x12\x03\x00foo\x98\xba\xdc\xfe\x51".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V") 
    expect = packlen + expect
    assert(expect == bytes)

    # Decode expect
    tc2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(tc2.class == RStyx::Message::Tcreate)
    assert(tc2.tag == 0x1234)
    assert(tc2.fid == 0x12345678)
    assert(tc2.name == "foo")
    assert(tc2.perm == 0xfedcba98)
    assert(tc2.mode == 0x51)

    # Try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x72\x34\x12\x78\x56\x34\x12\x03\x00foo\x98\xba\xdc\xfe") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x72\x34\x12\x78\x56\x34\x12\x03\x00foo\x98\xba") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x72\x34\x12\x78\x56\x34\x12\x03\x00f") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x72\x34\x12\x78\x56\x34") }
    # Decode with trailing garbage
    tc2 = nil
    assert_nothing_raised do
      tc2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(tc2.class == RStyx::Message::Tcreate)
    assert(tc2.tag == 0x1234)
    assert(tc2.fid == 0x12345678)
    assert(tc2.name == "foo")
    assert(tc2.perm == 0xfedcba98)
    assert(tc2.mode == 0x51)
  end

  ##
  # Test the Rcreate class.
  #
  def test_rcreate
    rc = RStyx::Message::Rcreate.new(:qid => RStyx::Message::Qid.new(0x01,0xdeadbeef,0xfeedfacec0ffeeee), :iounit => 0xfedcba98, :tag => 0x1234)
    bytes = rc.to_bytes
    expect = "\x73\x34\x12\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\x98\xba\xdc\xfe".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # Decode expect
    rc2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(rc2.class == RStyx::Message::Rcreate)
    assert(rc2.tag == 0x1234)
    assert(rc2.qid.qtype == 0x01)
    assert(rc2.qid.version == 0xdeadbeef)
    assert(rc2.qid.path == 0xfeedfacec0ffeeee)
    assert(rc2.iounit == 0xfedcba98)

    # Try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x73\x34\x12\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\x98\xba") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x73\x34\x12\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed") }

    # Decode with trailing garbage
    rc2 = nil
    assert_nothing_raised do
      rc2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(rc2.class == RStyx::Message::Rcreate)
    assert(rc2.tag == 0x1234)
    assert(rc2.qid.qtype == 0x01)
    assert(rc2.qid.version == 0xdeadbeef)
    assert(rc2.qid.path == 0xfeedfacec0ffeeee)
    assert(rc2.iounit == 0xfedcba98)
  end

  ##
  # Test the Tread class.
  #
  def test_tread
    tr = RStyx::Message::Tread.new(:fid => 0xdeadbeef, :offset => 0xfeedfacec0ffeeee, :count => 0xcafebabe, :tag => 0x1234)
    bytes = tr.to_bytes
    expect = "\x74\x34\x12\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\xbe\xba\xfe\xca".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # Decode expect
    tr2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(tr2.class == RStyx::Message::Tread)
    assert(tr2.tag == 0x1234)
    assert(tr2.fid == 0xdeadbeef)
    assert(tr2.offset == 0xfeedfacec0ffeeee)
    assert(tr2.count == 0xcafebabe)

    # Try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x74\x34\x12\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\xbe\xba\xfe") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x74\x34\x12\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x74\x34\x12\xef\xbe\xad\xde\xee\xee\xff\xc0\xce") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x74\x34\x12\xef\xbe\xad\xde\xee") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x74\x34\x12\xef\xbe\xad\xde\xee") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x74\x34\x12\xef\xbe\xad") }

    # Decode with trailing garbage
    tr2 = nil
    assert_nothing_raised do
      tr2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(tr2.class == RStyx::Message::Tread)
    assert(tr2.tag == 0x1234)
    assert(tr2.fid == 0xdeadbeef)
    assert(tr2.offset == 0xfeedfacec0ffeeee)
    assert(tr2.count == 0xcafebabe)
  end

  ##
  # test cases for Rread class
  #
  def test_rread
    data = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mama nancy oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee \xff\xfe\xfd\xfc".force_encoding("ASCII-8BIT")
    rr = RStyx::Message::Rread.new(:data => data, :tag => 0x1234)
    bytes = rr.to_bytes
    expect = "\x75\x34\x12\xa0\x00\x00\x00".force_encoding("ASCII-8BIT") + data
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # Decode expect
    rr2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(rr2.class == RStyx::Message::Rread)
    assert(rr2.tag == 0x1234)
    assert(rr2.count == data.length)
    assert(rr2.data == data)

    # Try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(expect.chop) }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x75\x34\x12\xa0\x00\x00".force_encoding("ASCII-8BIT")) }
    # Try decoding empty
    assert_nothing_raised { RStyx::Message::StyxMessage.from_bytes("\x0b\x00\x00\x00\x75\x34\x12\x00\x00\x00\x00".force_encoding("ASCII-8BIT")) }

    # Decode with trailing garbage
    rr2 = nil
    assert_nothing_raised do
      rr2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage".force_encoding("ASCII-8BIT"))
    end
    assert(rr2.class == RStyx::Message::Rread)
    assert(rr2.tag == 0x1234)
    assert(rr2.count == data.length)
    assert(rr2.data == data)
  end

  ##
  # Tests for Twrite class
  #
  def test_twrite
    data = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mama nancy oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu"
    tw = RStyx::Message::Twrite.new(:fid => 0x12345678, :offset => 0xfeedfacec0ffeeee, :data => data, :tag => 0x1234)
    expect = "\x76\x34\x12\x78\x56\x34\x12\xee\xee\xff\xc0\xce\xfa\xed\xfe\xa0\x00\x00\x00".force_encoding("ASCII-8BIT") + data
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    bytes = tw.to_bytes
    assert(expect == bytes)

    # Decode expect
    tw2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(tw2.class == RStyx::Message::Twrite)
    assert(tw2.tag == 0x1234)
    assert(tw2.fid == 0x12345678)
    assert(tw2.offset == 0xfeedfacec0ffeeee)
    assert(tw2.data == data)
    # Try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(expect.chop) }

    # Try decoding empty
    assert_raise(RStyx::StyxException) { RStyx::Message::Twrite.from_bytes("1234567890123456789012") }

    assert_nothing_raised { RStyx::Message::StyxMessage.from_bytes("\x17\x00\x00\x00\x75\x34\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") }
    # Decode with trailing garbage
    tw2 = nil
    assert_nothing_raised do
      tw2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(tw2.class == RStyx::Message::Twrite)
    assert(tw2.tag == 0x1234)
    assert(tw2.fid == 0x12345678)
    assert(tw2.offset == 0xfeedfacec0ffeeee)
    assert(tw2.data == data)
  end

  ##
  # Tests for Rwrite class
  def test_rwrite
    rw = RStyx::Message::Rwrite.new(:count => 0x12345678, :tag => 0x1234)
    bytes = rw.to_bytes
    expect = "\x77\x34\x12\x78\x56\x34\x12"
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # decode expect
    rw2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(rw2.class == RStyx::Message::Rwrite)
    assert(rw2.tag == 0x1234)
    assert(rw2.count == 0x12345678)

    # Try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(expect.chop) }
    # Decode with trailing garbage
    rw2 = nil
    assert_nothing_raised do
      rw2 = RStyx::Message::StyxMessage.from_bytes(expect)
    end
    assert(rw2.class == RStyx::Message::Rwrite)
    assert(rw2.tag == 0x1234)
    assert(rw2.count == 0x12345678)
  end

  ##
  # Test the Tclunk class.
  #
  def test_tclunk
    tc = RStyx::Message::Tclunk.new(:fid => 0xdeadbeef, :tag => 0x1234)
    expect = "\x78\x34\x12\xef\xbe\xad\xde".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == tc.to_bytes)

    # decode expect
    tc2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(tc2.class == RStyx::Message::Tclunk)
    assert(tc2.tag == 0x1234)
    assert(tc2.fid == 0xdeadbeef)

    # try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x78\x34\x12\xef\xbe\xad") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x78\x34\x12") }

    # decode with trailing garbage
    tc2 = nil
    assert_nothing_raised do
      tc2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(tc2.class == RStyx::Message::Tclunk)
    assert(tc2.tag == 0x1234)
    assert(tc2.fid == 0xdeadbeef)
  end

  ##
  # Test the Rclunk class.
  #
  def test_rclunk
    rc = RStyx::Message::Rclunk.new(:tag => 0x1234)
    bytes = rc.to_bytes
    expect = "\x79\x34\x12"
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # decode expect
    rc2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(rc2.class == RStyx::Message::Rclunk)
    assert(rc2.tag == 0x1234)

    # try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x79\x34") }

    # decode with trailing garbage
    rc2 = nil
    assert_nothing_raised do
      rc2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(rc2.class == RStyx::Message::Rclunk)
    assert(rc2.tag == 0x1234)
  end

  ##
  # Test the Tremove class.
  #
  def test_tremove
    tr = RStyx::Message::Tremove.new(:fid => 0xdeadbeef, :tag => 0x1234)
    bytes = tr.to_bytes
    expect = "\x7a\x34\x12\xef\xbe\xad\xde".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # decode expect
    tr2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(tr2.class == RStyx::Message::Tremove)
    assert(tr2.tag == 0x1234)
    assert(tr2.fid == 0xdeadbeef)

    # try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x7a\x34\x12\xef\xbe\xad") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x7a\x34\x12") }

    # decode with trailing garbage
    tr2 = nil
    assert_nothing_raised do
      tr2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(tr2.class == RStyx::Message::Tremove)
    assert(tr2.tag == 0x1234)
    assert(tr2.fid == 0xdeadbeef)
  end

  ##
  # Test the Rremove class.
  #
  def test_rremove
    rr = RStyx::Message::Rremove.new(:tag => 0x1234)
    bytes = rr.to_bytes
    expect = "\x7b\x34\x12"
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # decode expect
    rr2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(rr2.class == RStyx::Message::Rremove)
    assert(rr2.tag == 0x1234)

    # try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x7b\x34") }

    # decode with trailing garbage
    rr2 = nil
    assert_nothing_raised do
      rr2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(rr2.class == RStyx::Message::Rremove)
    assert(rr2.tag == 0x1234)
  end

  ##
  # Test the Tstat class.
  #
  def test_tstat
    ts = RStyx::Message::Tstat.new(:fid => 0xdeadbeef, :tag => 0x1234)
    bytes = ts.to_bytes
    expect = "\x7c\x34\x12\xef\xbe\xad\xde".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # decode expect
    ts2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(ts2.class == RStyx::Message::Tstat)
    assert(ts2.tag == 0x1234)
    assert(ts2.fid == 0xdeadbeef)

    # try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x7c\x34\x12\xef\xbe\xad") }
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(packlen + "\x7c\x34\x12") }

    # decode with trailing garbage
    ts2 = nil
    assert_nothing_raised do
      ts2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage")
    end
    assert(ts2.class == RStyx::Message::Tstat)
    assert(ts2.tag == 0x1234)
    assert(ts2.fid == 0xdeadbeef)
  end

  ##
  # Test the Rstat class.
  #
  def test_rstat
    de = RStyx::Message::Stat.new
    de.dtype = 0x1234
    de.dev = 0x567890ab
    de.qid = RStyx::Message::Qid.new(0x01, 0xdeadbeef,0xfeedfacec0ffeeee)
    de.mode = 0x9abcdef0
    de.atime = 0xdeadbeef
    de.mtime = 0xcafebabe
    de.length = 0xfedcba9876543210
    de.name = "foo"
    de.uid = "bar"
    de.gid = "baz"
    de.muid = "quux"
    rs = RStyx::Message::Rstat.new(:stat => de, :tag => 0x1234)
    bytes = rs.to_bytes
    expect = "\x7d\x34\x12\x3e\x00\x3c\x00\x34\x12\xab\x90\x78\x56\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\xf0\xde\xbc\x9a\xef\xbe\xad\xde\xbe\xba\xfe\xca\x10\x32\x54\x76\x98\xba\xdc\xfe\x03\x00foo\x03\x00bar\x03\x00baz\x04\x00quux".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # decode expect
    rs2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(rs2.class == RStyx::Message::Rstat)
    assert(rs2.tag == 0x1234)
    assert(rs2.stat.dtype == 0x1234)
    assert(rs2.stat.dev == 0x567890ab)
    assert(rs2.stat.qid.qtype == 0x01)
    assert(rs2.stat.qid.version == 0xdeadbeef)
    assert(rs2.stat.qid.path == 0xfeedfacec0ffeeee)
    assert(rs2.stat.mode == 0x9abcdef0)
    assert(rs2.stat.atime == 0xdeadbeef)
    assert(rs2.stat.mtime == 0xcafebabe)
    assert(rs2.stat.length == 0xfedcba9876543210)
    assert(rs2.stat.name == "foo")
    assert(rs2.stat.uid == "bar")
    assert(rs2.stat.gid == "baz")
    assert(rs2.stat.muid == "quux")

    # try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(expect.chop) }

    # Trailing garbage test
    rs2 = nil
    assert_nothing_raised { rs2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage") }
    assert(rs2.class == RStyx::Message::Rstat)
    assert(rs2.tag == 0x1234)
    assert(rs2.stat.dtype == 0x1234)
    assert(rs2.stat.dev == 0x567890ab)
    assert(rs2.stat.qid.qtype == 0x01)
    assert(rs2.stat.qid.version == 0xdeadbeef)
    assert(rs2.stat.qid.path == 0xfeedfacec0ffeeee)
    assert(rs2.stat.mode == 0x9abcdef0)
    assert(rs2.stat.atime == 0xdeadbeef)
    assert(rs2.stat.mtime == 0xcafebabe)
    assert(rs2.stat.length == 0xfedcba9876543210)
    assert(rs2.stat.name == "foo")
    assert(rs2.stat.uid == "bar")
    assert(rs2.stat.gid == "baz")
    assert(rs2.stat.muid == "quux")
  end

  ##
  # Test the Twstat class.
  #
  def test_twstat
    de = RStyx::Message::Stat.new
    de.dtype = 0x1234
    de.dev = 0x567890ab
    de.qid = RStyx::Message::Qid.new(0x01, 0xdeadbeef,0xfeedfacec0ffeeee)
    de.mode = 0x9abcdef0
    de.atime = 0xdeadbeef
    de.mtime = 0xcafebabe
    de.length = 0xfedcba9876543210
    de.name = "foo"
    de.uid = "bar"
    de.gid = "baz"
    de.muid = "quux"
    tw = RStyx::Message::Twstat.new(:fid => 0x12345678, :stat => de, :tag => 0x1234)
    bytes = tw.to_bytes
    expect = "\x7e\x34\x12\x78\x56\x34\x12\x3e\x00\x3c\x00\x34\x12\xab\x90\x78\x56\x01\xef\xbe\xad\xde\xee\xee\xff\xc0\xce\xfa\xed\xfe\xf0\xde\xbc\x9a\xef\xbe\xad\xde\xbe\xba\xfe\xca\x10\x32\x54\x76\x98\xba\xdc\xfe\x03\x00foo\x03\x00bar\x03\x00baz\x04\x00quux".force_encoding("ASCII-8BIT")
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # decode expect
    tw2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(tw2.class == RStyx::Message::Twstat)
    assert(tw2.tag == 0x1234)
    assert(tw2.stat.dtype == 0x1234)
    assert(tw2.stat.dev == 0x567890ab)
    assert(tw2.stat.qid.qtype == 0x01)
    assert(tw2.stat.qid.version == 0xdeadbeef)
    assert(tw2.stat.qid.path == 0xfeedfacec0ffeeee)
    assert(tw2.stat.mode == 0x9abcdef0)
    assert(tw2.stat.atime == 0xdeadbeef)
    assert(tw2.stat.mtime == 0xcafebabe)
    assert(tw2.stat.length == 0xfedcba9876543210)
    assert(tw2.stat.name == "foo")
    assert(tw2.stat.uid == "bar")
    assert(tw2.stat.gid == "baz")
    assert(tw2.stat.muid == "quux")

    # try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(expect.chop) }
    # Trailing garbage test
    tw2 = nil
    assert_nothing_raised { tw2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage") }
    assert(tw2.class == RStyx::Message::Twstat)
    assert(tw2.tag == 0x1234)
    assert(tw2.stat.dtype == 0x1234)
    assert(tw2.stat.dev == 0x567890ab)
    assert(tw2.stat.qid.qtype == 0x01)
    assert(tw2.stat.qid.version == 0xdeadbeef)
    assert(tw2.stat.qid.path == 0xfeedfacec0ffeeee)
    assert(tw2.stat.mode == 0x9abcdef0)
    assert(tw2.stat.atime == 0xdeadbeef)
    assert(tw2.stat.mtime == 0xcafebabe)
    assert(tw2.stat.length == 0xfedcba9876543210)
    assert(tw2.stat.name == "foo")
    assert(tw2.stat.uid == "bar")
    assert(tw2.stat.gid == "baz")
    assert(tw2.stat.muid == "quux")
  end

  ##
  # Test the Rwstat class.
  #
  def test_rwstat
    rw = RStyx::Message::Rwstat.new(:tag => 0x1234)
    bytes = rw.to_bytes
    expect = "\x7f\x34\x12"
    len = expect.length + 4
    packlen = [len].pack("V")
    expect = packlen + expect
    assert(expect == bytes)

    # decode expect
    rw2 = RStyx::Message::StyxMessage.from_bytes(expect)
    assert(rw2.class == RStyx::Message::Rwstat)
    assert(rw2.tag == 0x1234)
    # try decoding short strings
    assert_raise(RStyx::StyxException) { RStyx::Message::StyxMessage.from_bytes(expect.chop) }
    # trailing garbage test
    assert_nothing_raised { rw2 = RStyx::Message::StyxMessage.from_bytes(expect + "trailing garbage") }
    assert(rw2.class == RStyx::Message::Rwstat)
    assert(rw2.tag == 0x1234)
  end

  # Decode live Styx messages received from actual Styx server
  # implementations.
  def test_decode
    # Rversion from Inferno
    str = "\023\000\000\000eA\271\030 \000\000\006\0009P2000"
    m = RStyx::Message::StyxMessage.from_bytes(str)
    assert_equal(RStyx::Message::Rversion, m.class)
    assert_equal(47425, m.tag)
    assert_equal(8216, m.msize)
    assert_equal("9P2000", m.version)

    # Rattach from Inferno
    str = "\024\000\000\000i.w\200\240q^F\240\307\006\000\000\000\000\000"
    m = RStyx::Message::StyxMessage.from_bytes(str)
    assert_equal(RStyx::Message::Rattach, m.class)
    assert_equal(30510, m.tag)
    assert_equal(1180594592, m.qid.version)
    assert_equal(128, m.qid.qtype)
    assert_equal(444320, m.qid.path)

    # Rclunk from Inferno
    str = "\a\000\000\000y7\372"
    m = RStyx::Message::StyxMessage.from_bytes(str)
    assert_equal(RStyx::Message::Rclunk, m.class)
    assert_equal(64055, m.tag)
  end

end
