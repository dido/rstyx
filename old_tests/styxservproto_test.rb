#!/usr/bin/ruby
#
# Author:: Rafael R. Sevilla (mailto:dido@imperium.ph)
# Copyright:: Copyright (c) 2005-2007 Rafael R. Sevilla
# Homepage:: http://rstyx.rubyforge.org/
# License:: GNU Lesser General Public License / Ruby License
#
# $Id: tc_styxservproto.rb 301 2007-09-24 03:00:14Z dido $
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2005-2007 Rafael Sevilla
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
require 'test/unit'
require 'flexmock'
require 'flexmock'
require 'rstyx/server'

##
# A simple class that simply accepts any method on itself
# and does nothing.
#
class Absorber
  def method_missing(name, *args)
    # do nothing
  end
end

module RStyx
  module Server
    # Stub for sessions
    class Session
      def initialize
      end

      def self.mock=(m)
        @@mock = m
      end

      def initialize(conn)
      end

      def reset_session(msize)
        return(@@mock.reset_session(msize))
      end

      def version_negotiated?
        return(@@mock.version_negotiated?)
      end

      def has_fid?(fid)
        return(@@mock.has_fid?(fid))
      end

      def add_tag(t)
        return(@@mock.add_tag(t))
      end

      def has_tag?(tag)
        return(@@mock.has_tag?(tag))
      end

      def execute?(styxfile)
        return(@@mock.execute?(styxfile))
      end

      def writable?(styxfile)
        return(@@mock.writable?(styxfile))
      end

      def []=(fid, file)
        return(@@mock[fid] = file)
      end

      def [](fid)
        return(@@mock[fid])
      end

      def flush_tag(fid)
        return(@@mock.flush_tag(fid))
      end

      def release_tag(fid)
        return(@@mock.release_tag(fid))
      end

      def confirm_open(sf, mode)
        return(@@mock.confirm_open(sf, mode))
      end

      def user
        return(@@mock.user)
      end

      def iounit
        return(@@mock.iounit)
      end

      def clunk(fid)
        return(@@mock.clunk(fid))
      end

    end
  end
end

##
# Fake connection object mixin used to mix the StyxServerProtocol
# module or a copy thereof.
#
class FakeConnection
  include RStyx::Server::StyxServerProtocol

  ##
  # Mock objects are required for:
  #
  # 1. Methods called to self
  # 2. Methods called to the session object
  # 3. Methods called to the root object
  # 4. (Optionally) Methods called to the logger
  #
  def initialize(selfmock, sessionmock, rootmock, log=Absorber.new)
    @selfmock = selfmock
    RStyx::Server::Session.mock = sessionmock
    self.root = rootmock
    self.log = log
    post_init
  end

  def getpeername
    return(nil)
  end

  def method_missing(meth, *args)
    @selfmock.send(meth, *args)
  end
end

class TestStyxServProto < Test::Unit::TestCase
  include FlexMock::TestCase
  def test_tversion
    sessmock1 = flexmock
    selfmock = flexmock(:get_peername => nil)
    serv = FakeConnection.new(selfmock, sessmock1, nil)
    sessmock1.should_receive(:reset_session).with(Integer).returns do |m|
      assert_equal(1024, m)

    end
    resp = serv.tversion(RStyx::Message::Tversion.new(:version => "9P2000",
                                                      :msize => 1024))
    assert_equal(RStyx::Message::Rversion, resp.class)
    assert_equal("9P2000", resp.version)
    assert_equal(8216, resp.msize)

    sessmock = flexmock
    serv = FakeConnection.new(selfmock, sessmock, nil)
    resp = serv.tversion(RStyx::Message::Tversion.new(:version => "foo",
                                                      :msize => 1024))
    assert_equal(RStyx::Message::Rversion, resp.class)
    assert_equal("unknown", resp.version)
  end

  def test_tauth
    selfmock = flexmock(:get_peername => nil)
    serv = FakeConnection.new(selfmock, nil, nil)
    resp = serv.tauth(RStyx::Message::Tauth.new(:fid => 1,
                                                :afid => 2,
                                                :uname => "foo",
                                                :aname => "bar"))
    assert_equal(RStyx::Message::Rerror, resp.class)
    assert_equal("Authentication methods through auth messages are not supported.", resp.ename)
  end

  def test_tattach
    selfmock = flexmock(:get_peername => nil)
    # Test no version negotiation error
    FlexMock.use("sessmock") do |sessmock|
      sessmock.should_receive(:version_negotiated?).returns(false)
      serv = FakeConnection.new(selfmock, sessmock, nil)
      assert_raises(RStyx::StyxException) do
        serv.tattach(RStyx::Message::Tattach.new(:fid => 1,
                                                 :afid => 2,
                                                 :uname => "foo",
                                                 :aname => "bar"))
      end
    end

    # Test used fid error
    FlexMock.use("sessmock") do |sessmock|
      sessmock.should_receive(:version_negotiated?).returns(true)
      sessmock.should_receive(:has_fid?).with(1).returns(true)
      serv = FakeConnection.new(selfmock, sessmock, nil)
      assert_raises(RStyx::StyxException) do
        serv.tattach(RStyx::Message::Tattach.new(:fid => 1,
                                                 :afid => 2,
                                                 :uname => "foo",
                                                 :aname => "bar"))
      end
    end

    # test successful condition
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("rootmock") do |rootmock|
        sessmock.should_receive(:version_negotiated?).returns(true)
        sessmock.should_receive(:has_fid?).with(1).returns(false)
        sessmock.should_receive(:[]=).with(1, rootmock)
        # Return a phony QID with a distinctive pattern
        rootmock.should_receive(:qid).returns(RStyx::Message::Qid.new(0x12345678, 0x87654321, 0xfeedfacec0ffeee))
        serv = FakeConnection.new(selfmock, sessmock, rootmock)
        resp = serv.tattach(RStyx::Message::Tattach.new(:fid => 1,
                                                        :afid => 2,
                                                        :uname => "foo",
                                                        :aname => "bar"))
        assert_equal(0x12345678, resp.qid.qtype)
        assert_equal(0x87654321, resp.qid.version)
        assert_equal(0xfeedfacec0ffeee, resp.qid.path)
      end
    end
  end

  def test_tflush
    selfmock = flexmock(:get_peername => nil)
    FlexMock.use("sessmock") do |sessmock|
      sessmock.should_receive(:flush_tag).with(100)
      serv = FakeConnection.new(selfmock, sessmock, nil)
      resp = serv.tflush(RStyx::Message::Tflush.new(:oldtag => 100))
      assert_equal(RStyx::Message::Rflush, resp.class)
    end
  end

  def test_twalk
    selfmock = flexmock(:get_peername => nil)
    # Test for wnames > MAXWELEM
    serv = FakeConnection.new(selfmock, nil, nil)
    assert_raises(RStyx::StyxException) do
      serv.twalk(RStyx::Message::Twalk.new(:fid => 1,
                                           :newfid => 2,
                                           :wnames => ["1", "2", "3",
                                                       "4", "5", "6",
                                                       "7", "8", "9",
                                                       "10,", "11", "12",
                                                       "13", "14", "15",
                                                       "16", "17", "18"]))
    end

    # test for walking to an open fid
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(:pwn3d)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          serv.twalk(RStyx::Message::Twalk.new(:fid => 42,
                                               :newfid => 43,
                                               :wnames => ["1", "2"]))
        end
      end
    end

    # Test attempting to reassign a fid that is already in use
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(nil)
        sessmock.should_receive(:has_fid?).with(43).returns(true)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          serv.twalk(RStyx::Message::Twalk.new(:fid => 42,
                                               :newfid => 43,
                                               :wnames => ["1", "2"]))
        end
      end
    end

    # Test walking to something which isn't a directory
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(nil)
        sessmock.should_receive(:has_fid?).with(43).returns(false)
        filemock.should_receive(:directory?).returns(false)
        filemock.should_receive(:name).returns("foo")
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          serv.twalk(RStyx::Message::Twalk.new(:fid => 42,
                                               :newfid => 43,
                                               :wnames => ["1", "2"]))
        end
      end
    end

    # Test for the case where file permissions are violated
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(nil)
        sessmock.should_receive(:has_fid?).with(43).returns(false)
        filemock.should_receive(:directory?).returns(true)
        filemock.should_receive(:name).returns("foo")
        sessmock.should_receive(:execute?).returns(false)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          serv.twalk(RStyx::Message::Twalk.new(:fid => 42,
                                               :newfid => 43,
                                               :wnames => ["..", "2"]))
        end
      end
    end

    # Test for the case where we are unable to walk further than the
    # first element
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(nil)
        sessmock.should_receive(:has_fid?).with(43).returns(false)
        filemock.should_receive(:directory?).returns(true)
        filemock.should_receive(:name).returns("foo")
        filemock.should_receive(:atime=)
        filemock.should_receive(:[]).with("1").returns(nil)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          serv.twalk(RStyx::Message::Twalk.new(:fid => 42,
                                               :newfid => 43,
                                               :wnames => ["1", "2"]))
        end
      end
    end

    # Test successful walk without fid assignment
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(nil)
        sessmock.should_receive(:has_fid?).with(43).returns(false)
        filemock.should_receive(:directory?).returns(true)
        filemock.should_receive(:name).returns("foo")
        filemock.should_receive(:atime=)
        filemock.should_receive(:[]).with("1").returns(filemock)
        filemock.should_receive(:[]).with("2").returns(nil)
        filemock.should_receive(:qid).returns(RStyx::Message::Qid.new(0x12345678, 0x87654321, 0xfeedfacec0ffeee))
        filemock.should_receive(:refresh)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        resp = serv.twalk(RStyx::Message::Twalk.new(:fid => 42,
                                                    :newfid => 43,
                                                    :wnames => ["1", "2"]))
        assert_equal(RStyx::Message::Rwalk, resp.class)
        assert_equal(1, resp.qids.length)
        assert_equal(RStyx::Message::Qid.new(0x12345678,
                                             0x87654321,
                                             0xfeedfacec0ffeee),
                     resp.qids[0])
      end
    end

    # Test successful walk with fid assignment
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(nil)
        sessmock.should_receive(:has_fid?).with(43).returns(false)
        filemock.should_receive(:directory?).returns(true)
        filemock.should_receive(:name).returns("foo")
        filemock.should_receive(:atime=)
        filemock.should_receive(:[]).with("1").returns(filemock)
        filemock.should_receive(:[]).with("2").returns(filemock)
        qids = [ RStyx::Message::Qid.new(0x12345678,
                                         0x87654321,
                                         0xfeedfacec0ffeee),
                 RStyx::Message::Qid.new(0x89abcdef,
                                         0x01234567,
                                         0x0123456789abcdef)
               ]
        filemock.should_receive(:qid).returns { qids.shift }
        filemock.should_receive(:refresh)
        sessmock.should_receive(:[]=).with(43, filemock)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        resp = serv.twalk(RStyx::Message::Twalk.new(:fid => 42,
                                                    :newfid => 43,
                                                    :wnames => ["1", "2"]))
        assert_equal(RStyx::Message::Rwalk, resp.class)
        assert_equal(2, resp.qids.length)
        assert_equal(RStyx::Message::Qid.new(0x12345678,
                                             0x87654321,
                                             0xfeedfacec0ffeee),
                     resp.qids[0])
        assert_equal(RStyx::Message::Qid.new(0x89abcdef,
                                             0x01234567,
                                             0x0123456789abcdef),

                     resp.qids[1])
      end
    end


  end

  def test_topen
    selfmock = flexmock(:get_peername => nil)
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        sessmock.should_receive(:confirm_open).with(filemock, RStyx::OTRUNC)
        filemock.should_receive(:add_client)
        filemock.should_receive(:set_mtime)
        sessmock.should_receive(:user)
        filemock.should_receive(:qid).returns(RStyx::Message::Qid.new(0x12345678, 0x87654321, 0xfeedfacec0ffeee))
        sessmock.should_receive(:iounit).returns(0xdeadbeef)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        resp = serv.topen(RStyx::Message::Topen.new(:fid => 42,
                                                    :mode => RStyx::OTRUNC))
        assert_equal(RStyx::Message::Qid.new(0x12345678, 0x87654321, 0xfeedfacec0ffeee), resp.qid)
        assert_equal(0xdeadbeef, resp.iounit)
      end
    end
  end

  def test_tcreate
    selfmock = flexmock(:get_peername => nil)
    # First, test the error condition of trying to create a file
    # inside a fid representing a file.
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:directory?).returns(false)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          resp = serv.tcreate(RStyx::Message::Tcreate.new(:fid => 42,
                                                          :mode => RStyx::OTRUNC))
        end
      end
    end

    # Second, test the error condition where we try to create a file
    # where the connection does not have permission to write.
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:directory?).returns(true)
        sessmock.should_receive(:writable?).returns(false)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          resp = serv.tcreate(RStyx::Message::Tcreate.new(:fid => 42,
                                                          :mode => RStyx::OTRUNC))
        end
      end
    end

    # Third, try to create a file with DMAUTH set.
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:directory?).returns(true)
        sessmock.should_receive(:writable?).returns(true)
        filemock.should_receive(:permissions).returns(0777)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          resp = serv.tcreate(RStyx::Message::Tcreate.new(:fid => 42,
                                                          :mode => RStyx::OREAD,
                                                          :perm => RStyx::DMAUTH | 0644))
        end
      end
    end

    # Fourth, try to create a directory in a mode besides OREAD.
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:directory?).returns(true)
        sessmock.should_receive(:writable?).returns(true)
        filemock.should_receive(:permissions).returns(0777)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          resp = serv.tcreate(RStyx::Message::Tcreate.new(:fid => 42,
                                                          :mode => RStyx::OTRUNC,
                                                          :perm => RStyx::DMDIR | 0755))
        end
      end
    end

    # Finally, successful creation.
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:directory?).returns(true)
        sessmock.should_receive(:writable?).returns(true)
        filemock.should_receive(:permissions).returns(0777)
        filemock.should_receive(:newfile).with("foo", 0644, false,
                                               false, false).returns(filemock)
        filemock.should_receive(:<<).with(filemock)
        sessmock.should_receive(:[]=).with(42, filemock)
        filemock.should_receive(:add_client)
        filemock.should_receive(:qid).returns(RStyx::Message::Qid.new(0x12345678, 0x87654321, 0xfeedfacec0ffeee))
        sessmock.should_receive(:iounit).returns(0xdeadbeef)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        resp = serv.tcreate(RStyx::Message::Tcreate.new(:fid => 42,
                                                        :name => "foo",
                                                        :perm => 0644,
                                                        :mode =>
                                                        RStyx::OTRUNC))
        assert_equal(RStyx::Message::Rcreate, resp.class)
        assert_equal(RStyx::Message::Qid.new(0x12345678,
                                             0x87654321,
                                             0xfeedfacec0ffeee), resp.qid)
        assert_equal(0xdeadbeef, resp.iounit)
      end
    end

  end

  def test_tread
    selfmock = flexmock(:get_peername => nil)
    # Test error condition -- file not open for reading
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(nil)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          resp = serv.tread(RStyx::Message::Tread.new(:fid => 42,
                                                      :offset => 0xfeedfacec0ffeeee,
                                                      :count => 100))
        end
      end
    end

    # Test trying to read more than the session iounit
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(filemock)
        filemock.should_receive(:readable?).returns(true)
        sessmock.should_receive(:iounit).returns(8216)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          resp = serv.tread(RStyx::Message::Tread.new(:fid => 42,
                                                      :offset => 0xfeedfacec0ffeeee,
                                                      :count => 10000))
        end
      end
    end

    # Test successful read
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(filemock)
        filemock.should_receive(:readable?).returns(true)
        sessmock.should_receive(:iounit).returns(8216)
        filemock.should_receive(:read).returns do |a1,a2,a3|
          assert_equal(0xfeedfacec0ffeeee, a2)
          assert_equal(1000, a3)
          true
        end
        serv = FakeConnection.new(selfmock, sessmock, nil)
        resp = serv.tread(RStyx::Message::Tread.new(:fid => 42,
                                                    :offset => 0xfeedfacec0ffeeee,
                                                    :count => 1000))
        assert(resp)
      end
    end

  end

  def test_twrite
    selfmock = flexmock(:get_peername => nil)
    # Test error condition -- file not open for writing
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(nil)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          resp = serv.twrite(RStyx::Message::Twrite.new(:fid => 42,
                                                        :offset => 0xfeedfacec0ffeeee,
                                                        :data => "0" * 1000))
        end
      end
    end

    # Test trying to write more than the session iounit
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(filemock)
        filemock.should_receive(:writable?).returns(true)
        sessmock.should_receive(:iounit).returns(8216)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        assert_raises(RStyx::StyxException) do
          resp = serv.twrite(RStyx::Message::Twrite.new(:fid => 42,
                                                        :offset => 0xfeedfacec0ffeeee,
                                                        :data => "0" * 10000))
        end
      end
    end

    # Test successful write
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(filemock)
        filemock.should_receive(:writable?).returns(true)
        sessmock.should_receive(:iounit).returns(8216)
        filemock.should_receive(:write).returns do |a1,a2,a3,a4|
          assert_equal(0xfeedfacec0ffeeee, a2)
          assert_equal("0" * 1000, a3)
          assert(!a4)
          true
        end
        filemock.should_receive(:truncate?).returns(false)
        filemock.should_receive(:appendonly?).returns(false)
        filemock.should_receive(:length).returns(42)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        resp = serv.twrite(RStyx::Message::Twrite.new(:fid => 42,
                                                      :offset => 0xfeedfacec0ffeeee,
                                                      :data => "0" * 1000))
        assert(resp)
      end
    end


    # Test successful write on an append only file
    FlexMock.use("sessmock") do |sessmock|
      FlexMock.use("filemock") do |filemock|
        sessmock.should_receive(:[]).with(42).returns(filemock)
        filemock.should_receive(:client).returns(filemock)
        filemock.should_receive(:writable?).returns(true)
        sessmock.should_receive(:iounit).returns(8216)
        filemock.should_receive(:write).returns do |a1,a2,a3,a4|
          assert_equal(42, a2)
          assert_equal("0" * 1000, a3)
          assert(!a4)
          true
        end
        filemock.should_receive(:truncate?).returns(false)
        filemock.should_receive(:appendonly?).returns(true)
        filemock.should_receive(:length).returns(42)
        serv = FakeConnection.new(selfmock, sessmock, nil)
        resp = serv.twrite(RStyx::Message::Twrite.new(:fid => 42,
                                                      :offset => 0xfeedfacec0ffeeee,
                                                      :data => "0" * 1000))
        assert(resp)
      end
    end
  end

  def test_tclunk
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    sessmock.should_receive(:clunk).with(Integer).returns do |f|
      assert_equal(42, f)
    end
    serv = FakeConnection.new(selfmock, sessmock, nil)
    resp = serv.tclunk(RStyx::Message::Tclunk.new(:fid => 42))
    assert_equal(RStyx::Message::Rclunk, resp.class)
  end

  def test_tremove_permission_denied
    # Permission denied
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    sessmock.should_receive(:clunk).with(Integer).returns do |f|
      assert_equal(42, f)
    end
    filemock.should_receive(:parent).returns(filemock)
    sessmock.should_receive(:writable?).with(filemock).returns(false)
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.tremove(RStyx::Message::Tremove.new(:fid => 42))
    end
  end

  def test_tremove_not_empty
    # Directory not empty
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    sessmock.should_receive(:clunk).with(Integer).returns do |f|
      assert_equal(42, f)
    end
    filemock.should_receive(:parent).returns(filemock)
    sessmock.should_receive(:writable?).with(filemock).returns(true)
    filemock.should_receive(:instance_of?).with(RStyx::Server::SDirectory).returns(true)
    filemock.should_receive(:child_count).returns(42)
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.tremove(RStyx::Message::Tremove.new(:fid => 42))
    end
  end

  def test_tremove_success
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    sessmock.should_receive(:clunk).with(Integer).returns do |f|
      assert_equal(42, f)
    end
    filemock.should_receive(:parent).returns(filemock)
    sessmock.should_receive(:writable?).with(filemock).returns(true)
    filemock.should_receive(:remove)
    sessmock.should_receive(:user).returns("foo")
    filemock.should_receive(:set_mtime).with(Time, String).returns { |t,s| assert_equal("foo", s) }
    serv = FakeConnection.new(selfmock, sessmock, nil)
    resp = serv.tremove(RStyx::Message::Tremove.new(:fid => 42))
    assert_equal(RStyx::Message::Rremove, resp.class)
  end

  def test_tstat
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    filemock.should_receive(:stat)
    sessmock.should_receive(:[]).with(42).returns(filemock)
    serv = FakeConnection.new(selfmock, sessmock, nil)
    resp = serv.tstat(RStyx::Message::Tstat.new(:fid => 42))
    assert_equal(RStyx::Message::Rstat, resp.class)
  end

  def test_twstat_name_change_nowrite
    # Test twstat for name change with no write permissions to
    # parent directory
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    filemock.should_receive(:parent).returns(filemock)
    sessmock.should_receive(:writable?).with(filemock).returns(false)
    stat = RStyx::Message::Stat.new
    stat.name = "foo"
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end

  end

  def test_twstat_name_change_conflict
    # Test twstat for name change to a name of a file already
    # present in the parent directory
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    filemock.should_receive(:parent).returns(filemock)
    sessmock.should_receive(:writable?).with(filemock).returns(true)
    filemock.should_receive(:has_child?).with("foo").returns(true)
    stat = RStyx::Message::Stat.new
    stat.name = "foo"
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end
  end

  def test_twstat_name_change_success
    # test twstat for successful name change
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    filemock.should_receive(:parent).returns(filemock)
    sessmock.should_receive(:writable?).with(filemock).returns(true)
    filemock.should_receive(:has_child?).with("foo").returns(false)
    stat = RStyx::Message::Stat.new
    stat.name = "foo"
    stat.size = -1
    stat.mode = RStyx::MAXUINT
    stat.mtime = RStyx::MAXUINT
    stat.dtype = 0xffff
    stat.dev = 0xffffffff
    stat.qid = RStyx::Message::Qid.new(0xff, 0xffffffff,
                                       0xffffffffffffffff)
    stat.gid = stat.uid = stat.muid = ""
    stat.atime = 0xffffffff
    filemock.should_receive(:can_setname?)
    filemock.should_receive(:name=).with(String).returns { |s| assert_equal("foo", s) }
    serv = FakeConnection.new(selfmock, sessmock, nil)
    resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    assert_equal(RStyx::Message::Rwstat, resp.class)
  end

  def test_twstat_size_noperm
    # permission denied for file size change
    # Test twstat for name change with no write permissions to
    # parent directory
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    sessmock.should_receive(:writable?).with(filemock).returns(false)
    stat = RStyx::Message::Stat.new
    stat.name = ""
    stat.size = 42
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end

  end

  def test_twstat_size_success
    # test twstat for successful size change
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    sessmock.should_receive(:writable?).with(filemock).returns(true)
    stat = RStyx::Message::Stat.new
    stat.name = ""
    stat.size = 42
    stat.mode = RStyx::MAXUINT
    stat.mtime = RStyx::MAXUINT
    stat.dtype = 0xffff
    stat.dev = 0xffffffff
    stat.qid = RStyx::Message::Qid.new(0xff, 0xffffffff,
                                       0xffffffffffffffff)
    stat.gid = stat.uid = stat.muid = ""
    stat.atime = 0xffffffff
    filemock.should_receive(:can_setlength?).with(Integer).returns { |s| assert_equal(42, s) }
    filemock.should_receive(:length=).with(Integer).returns { |s| assert_equal(42, s) }
    serv = FakeConnection.new(selfmock, sessmock, nil)
    resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    assert_equal(RStyx::Message::Rwstat, resp.class)
  end

  def test_twstat_mode_not_owner
    # test twstat error condition, where mode changer is not the owner of
    # the file.
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    sessmock.should_receive(:user).returns("foo")
    filemock.should_receive(:uid).returns("bar")
    stat = RStyx::Message::Stat.new
    stat.name = ""
    stat.size = -1
    stat.mode = 0644
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end
  end

  def test_twstat_mode_add_dirbit
    # test twstat error condition, where the mode of an ordinary file is
    # to be changed to that of a directory.
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    sessmock.should_receive(:user).returns("foo")
    filemock.should_receive(:uid).returns("foo")
    filemock.should_receive(:directory?).returns(false)
    stat = RStyx::Message::Stat.new
    stat.name = ""
    stat.size = -1
    stat.mode = 0644 | RStyx::DMDIR
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end
  end

  def test_twstat_mode_success
    # test twstat for successful mode change
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    sessmock.should_receive(:user).returns("foo")
    filemock.should_receive(:uid).returns("foo")
    filemock.should_receive(:directory?).returns(false)
    filemock.should_receive(:can_setmode?)
    filemock.should_receive(:mode=).with(Integer).returns { |m| assert_equal(0644, m) }
    stat = RStyx::Message::Stat.new
    stat.name = ""
    stat.size = -1
    stat.mode = 0644
    stat.mtime = RStyx::MAXUINT
    stat.dtype = 0xffff
    stat.dev = 0xffffffff
    stat.qid = RStyx::Message::Qid.new(0xff, 0xffffffff,
                                       0xffffffffffffffff)
    stat.gid = stat.uid = stat.muid = ""
    stat.atime = 0xffffffff
    serv = FakeConnection.new(selfmock, sessmock, nil)
    resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
  end

  def test_twstat_mtime_not_owner
    # test twstat error condition, where mtime changer is not the owner of
    # the file.
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    sessmock.should_receive(:user).returns("foo")
    filemock.should_receive(:uid).returns("bar")
    stat = RStyx::Message::Stat.new
    stat.name = ""
    stat.size = -1
    stat.mode = RStyx::MAXUINT
    stat.mtime = Time.now.to_i
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end
  end

  def test_twstat_mtime_success
    # test twstat for successful mtime change
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    sessmock.should_receive(:user).returns("foo")
    filemock.should_receive(:uid).returns("foo")
    filemock.should_receive(:directory?).returns(false)
    filemock.should_receive(:can_setmtime?)
    filemock.should_receive(:mtime=).with(Integer).returns { |m| assert_equal(1190545938, m) }
    stat = RStyx::Message::Stat.new
    stat.name = ""
    stat.size = -1
    stat.mode = RStyx::MAXUINT
    stat.mtime = 1190545938
    stat.dtype = 0xffff
    stat.dev = 0xffffffff
    stat.qid = RStyx::Message::Qid.new(0xff, 0xffffffff,
                                       0xffffffffffffffff)
    stat.gid = stat.uid = stat.muid = ""
    stat.atime = 0xffffffff
    serv = FakeConnection.new(selfmock, sessmock, nil)
    resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    assert_equal(RStyx::Message::Rwstat, resp.class)
  end

  def test_twstat_misc_failures
    # test twstat for miscellaneous failure modes
    # Try to change group ID (not permitted by an RStyx server)
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    filemock = flexmock
    sessmock.should_receive(:[]).with(42).returns(filemock)
    filemock.should_receive(:synchronize).with(Proc).returns { |block| block.call }
    stat = RStyx::Message::Stat.new
    stat.name = ""
    stat.size = -1
    stat.mode = RStyx::MAXUINT
    stat.mtime = RStyx::MAXUINT
    stat.dtype = 0xfffff
    stat.dev = 0xffffffff
    stat.qid = RStyx::Message::Qid.new(0xff, 0xffffffff,
                                       0xffffffffffffffff)
    stat.gid = "foo"
    stat.uid = stat.muid = ""
    stat.atime = 0xffffffff
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end

    # Try changing dtype
    stat = RStyx::Message::Stat.new
    stat.name = ""
    stat.size = -1
    stat.mode = RStyx::MAXUINT
    stat.mtime = RStyx::MAXUINT
    stat.dtype = 0xff00
    stat.dev = 0xffffffff
    stat.qid = RStyx::Message::Qid.new(0xff, 0xffffffff,
                                       0xffffffffffffffff)
    stat.gid = stat.uid = stat.muid = ""
    stat.atime = 0xffffffff
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end

    # Try changing dev
    stat.dtype = 0xffff
    stat.dev = 0xdeadbeef
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end

    # Try changing Qid
    stat.dev = 0xffffffff
    stat.qid = RStyx::Message::Qid.new(0xfe, 0xf000baaa, 0xdeadbeeff00baaa)
    serv = FakeConnection.new(selfmock, sessmock, nil)
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end

    # Try changing atime
    stat.qid = RStyx::Message::Qid.new(0xff, 0xffffffff,
                                       0xffffffffffffffff)
    stat.atime = Time.now.to_i
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end

    # try changing uid
    stat.atime = 0xffffffff
    stat.uid = "foo"
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end

    # try changing muid
    stat.uid = ""
    stat.muid = "foo"
    assert_raises(RStyx::StyxException) do
      resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    end

    # Try an empty change
    stat.muid = ""
    resp = serv.twstat(RStyx::Message::Twstat.new(:stat => stat, :fid => 42))
    assert_equal(RStyx::Message::Rwstat, resp.class)
  end

  def test_reply
    msg = RStyx::Message::Rversion.new(:version => "9P2000",
                                       :msize => 8216)
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    sessmock.should_receive(:has_tag?).returns(true)
    selfmock.should_receive(:send_data).with(String).returns do |msg|
      umsg = RStyx::Message::StyxMessage.from_bytes(msg)
      assert_equal(RStyx::Message::Rversion, umsg.class)
      assert_equal("9P2000", umsg.version)
      assert_equal(8216, umsg.msize)
      assert_equal(42, umsg.tag)
    end
    sessmock.should_receive(:release_tag).with(Integer).returns { |t| assert_equal(42, t) }
    serv = FakeConnection.new(selfmock, sessmock, nil)
    resp = serv.reply(msg, 42)    
  end

  def test_process_styxmsg_badtag
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    logmock = flexmock
    sessmock.should_receive(:add_tag).with(Integer).returns do |t|
      assert_equal(42, t)
      raise RStyx::TagInUseException.new(t)
    end
    logmock.should_receive(:error).with(String).returns do |s|
      assert_equal("(unknown peer) RStyx::TagInUseException (Tversion :tag=>\"42\" :msize=>\"8216\" :version=>\"9P2000\")", s)
    end
    msg = RStyx::Message::Tversion.new(:version => "9P2000",
                                       :msize => 8216,
                                       :tag => 42)
    serv = FakeConnection.new(selfmock, sessmock, nil, logmock)
    serv.process_styxmsg(msg)
  end

  def test_process_styxmsg_badfid
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    sessmock.should_receive(:add_tag).with(Integer).returns do |t|
      assert_equal(42, t)
    end
    sessmock.should_receive(:[]).with(Integer).returns do |t|
      assert_equal(42, t)
      raise RStyx::FidNotFoundException.new(t)
    end
    msg = RStyx::Message::Twrite.new(:fid => 42,
                                     :tag => 42)
    sessmock.should_receive(:has_tag?).returns(true)
    selfmock.should_receive(:send_data).with(String).returns do |msg|
      umsg = RStyx::Message::StyxMessage.from_bytes(msg)
      assert_equal(RStyx::Message::Rerror, umsg.class)
    end
    serv = FakeConnection.new(selfmock, sessmock, nil)
    sessmock.should_receive(:release_tag).with(Integer).returns { |t| assert_equal(42, t) }

    serv.process_styxmsg(msg)
  end

  def test_process_styxmsg_emptyreply
    msgmock = flexmock
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    sessmock.should_receive(:add_tag).with(42)
    sessmock.should_receive(:[]).with(Integer).returns do |t|
      assert_equal(42, t)
      raise RStyx::FidNotFoundException.new(t)
    end
    sessmock.should_receive(:has_tag?).returns(true)
    selfmock.should_receive(:send_data).with(String).returns do |msg|
      umsg = RStyx::Message::StyxMessage.from_bytes(msg)
      assert_equal(RStyx::Message::Rerror, umsg.class)
    end
    selfmock.should_receive(:flexmock).returns(nil)
    msgmock.should_receive(:tag).returns(42)
    serv = FakeConnection.new(selfmock, sessmock, nil)
    sessmock.should_receive(:release_tag).with(Integer).returns { |t| assert_equal(42, t) }

    serv.process_styxmsg(msgmock)
  end

  def test_process_styxmsg_internalerror
    msgmock = flexmock
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    sessmock.should_receive(:add_tag).with(42)
    sessmock.should_receive(:[]).with(Integer).returns do |t|
      assert_equal(42, t)
      raise RStyx::FidNotFoundException.new(t)
    end
    selfmock.should_receive(:absorber).returns(nil)
    sessmock.should_receive(:has_tag?).returns(true)
    selfmock.should_receive(:send_data).with(String).returns do |msg|
      umsg = RStyx::Message::StyxMessage.from_bytes(msg)
      assert_equal(RStyx::Message::Rerror, umsg.class)
    end
    selfmock.should_receive(:flexmock).returns { raise "error" }
    msgmock.should_receive(:tag).returns(42)
    serv = FakeConnection.new(selfmock, sessmock, nil)
    sessmock.should_receive(:release_tag).with(Integer).returns { |t| assert_equal(42, t) }

    serv.process_styxmsg(msgmock)
  end

  def test_process_styxmsg_success
    selfmock = flexmock(:get_peername => nil)
    sessmock = flexmock
    sessmock.should_receive(:add_tag).with(Integer).returns do |t|
      assert_equal(42, t)
    end
    sessmock.should_receive(:[]).with(Integer).returns do |t|
      assert_equal(42, t)
    end
    msg = RStyx::Message::Tclunk.new(:fid => 42, :tag => 42)
    sessmock.should_receive(:clunk).with(42)
    sessmock.should_receive(:has_tag?).returns(true)
    selfmock.should_receive(:send_data).with(String).returns do |msg|
      umsg = RStyx::Message::StyxMessage.from_bytes(msg)
      assert_equal(RStyx::Message::Rclunk, umsg.class)
    end
    serv = FakeConnection.new(selfmock, sessmock, nil)
    sessmock.should_receive(:release_tag).with(Integer).returns { |t| assert_equal(42, t) }

    serv.process_styxmsg(msg)
  end

end
