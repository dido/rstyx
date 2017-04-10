#!/usr/bin/ruby
#
# Author:: Rafael R. Sevilla (mailto:dido@imperium.ph)
# Copyright:: Copyright (c) 2005-2007 Rafael R. Sevilla
# Homepage:: http://rstyx.rubyforge.org/
# License:: GNU Lesser General Public License / Ruby License
#
# $Id: tc_client.rb 288 2007-09-19 07:36:50Z dido $
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
require 'rstyx'

Thread.abort_on_exception = true

class StyxClientTester
  include RStyx::Client::StyxClient
  attr_reader :stopcount

  def initialize(mockobj=nil)
    @mockobj = mockobj
    self.post_init
  end

  # Delegate to the mock object other methods
  def method_missing(sym, *args)
    @mockobj.send(sym, *args)
  end
end

# fake stub for EventMachine
module EventMachine
  # Phony event loop
  def EventMachine.run
  end

  # Stop the phony event loop if it is in use
  def EventMachine.stop_event_loop
    @@stopcount ||= 0
    @@stopcount += 1
  end

  def EventMachine.stopcount
    return(@@stopcount)
  end

  # Set the mock object for the fake event machine
  def EventMachine.mockobj=(m)
    @mockobj = m
  end

  # This returns a StyxClientTester instance with the mock object
  def EventMachine.connect(host, port, c)
    return(StyxClientTester.new(@mockobj))
  end
end

module RStyx
  # redefine for testing
  MAX_FID = 0xff
  #  DEBUG = true
end

class StyxClientTest < Test::Unit::TestCase
  # Test message sending, successful cases.
  def test_send_message
    FlexMock.use("mock") do |mock|
      q = Queue.new
      mock.should_receive(:send_data).with(String).returns do |data|
        m = RStyx::Message::StyxMessage.from_bytes(data)
        # Send an extra Rversion with a different tag number--this
        # should # be ignored.  We make the message size and version
        # different in this case.
        rv = RStyx::Message::Rversion.new(:msize => 0x12345678,
                                          :version => "FooBar")
        rv.tag = m.tag + 1
        q << rv
        # Prepared response message
        rv = RStyx::Message::Rversion.new(:msize => 0xdeadbeef,
                                          :version => "9P2000")
        # make their tags the same, as this is the response
        rv.tag = m.tag
        q << rv
      end
      c = StyxClientTester.new(mock)
      Thread.new do
        # Send the test tversion message
        msg =
          c.send_message(RStyx::Message::Tversion.new(:msize => 0xdeadbeef,
                                                      :version => "9P2000"))
        assert_equal(RStyx::Message::Rversion, msg.class)
        assert_equal(0xdeadbeef, msg.msize)
        assert_equal("9P2000", msg.version)
      end
      data = q.shift.to_bytes
      data << q.shift.to_bytes
      c.receive_data(data)
    end

    FlexMock.use("mock") do |mock|
      q = Queue.new
      # Try sending the received data in pieces, see if things still work
      mock.should_receive(:send_data).with(String).returns do |data|
        m = RStyx::Message::StyxMessage.from_bytes(data)
        # Prepared response message
        rv = RStyx::Message::Rversion.new(:msize => 0xdeadbeef,
                                          :version => "9P2000")
        # make their tags the same, as this is the response
        rv.tag = m.tag
        q << rv
      end
      c = StyxClientTester.new(mock)
      Thread.new do
        # Send the test tversion message
        msg =
          c.send_message(RStyx::Message::Tversion.new(:msize => 0xdeadbeef,
                                                      :version => "9P2000"))
        assert_equal(RStyx::Message::Rversion, msg.class)
        assert_equal(0xdeadbeef, msg.msize)
        assert_equal("9P2000", msg.version)
      end
      # one byte at a time
      smsg = q.shift.to_bytes
      smsg.each_byte do |b|
        c.receive_data(b.chr)
      end
    end
  end

  # Test receiving error cases
  def test_error_cases
    FlexMock.use("mock") do |mock|
      q = Queue.new
      mock.should_receive(:send_data).with(String).returns do |data|
        m = RStyx::Message::StyxMessage.from_bytes(data)
        # Prepared response message
        rv = RStyx::Message::Rerror.new(:ename => "test error")
        # make their tags the same, as this is the response
        rv.tag = m.tag
        q << rv
      end
      c = StyxClientTester.new(mock)
      Thread.new do
        # Send the test tversion message
        begin
          msg = c.send_message(RStyx::Message::Tversion.new(:msize => 0xdeadbeef,
                                                            :version => "9P2000"))
        rescue RStyx::StyxException => e
          assert_equal("test error", e.message)
        rescue Exception => e
          flunk("exception of unexpected type #{e.class.to_s} received")
        else
          flunk("no exception received where expected")
        end
      end
      c.receive_data(q.shift.to_bytes)
    end

    FlexMock.use("mock") do |mock|
      q = Queue.new
      # Try sending a reply different from what was expected.  Typical
      # case of this sort that would appear in practice might be if
      # a message gets flushed.
      mock.should_receive(:send_data).with(String).returns do |data|
        m = RStyx::Message::StyxMessage.from_bytes(data)
        # Prepared response message
        rv = RStyx::Message::Rflush.new
        # make their tags the same, as this is the response
        rv.tag = m.tag
        q << rv
      end
      c = StyxClientTester.new(mock)
      Thread.new do
        # Send the test tversion message
        begin
          msg = c.send_message(RStyx::Message::Tversion.new(:msize => 0xdeadbeef,
                                                            :version => "9P2000"))
        rescue RStyx::StyxException => e
          assert_match(/^Unexpected.*received in response to/, e.message)
        rescue Exception => e
          flunk("exception of unexpected type #{e.class.to_s} received")
        else
          flunk("no exception received where expected")
        end
      end
      c.receive_data(q.shift.to_bytes)

    end

  end

  # Test disconnect
  def test_disconnect
    # Here be dragons...  We're attempting to synchronize the behavior
    # of several threads.
    FlexMock.use("mock") do |mock|
      EventMachine.mockobj=mock
      mock.should_receive(:stop_event_loop)
      c = StyxClientTester.new(mock)
      flush_count = 0

      mock.should_receive(:send_data).with(String).returns do |data|
        m = RStyx::Message::StyxMessage.from_bytes(data)
        # Respond only to Tflush messages, no response to other
        # messages sent.
        if m.class == RStyx::Message::Tflush
          flush_count += 1
          rv = RStyx::Message::Rflush.new(:tag => m.tag)
          c.receive_data(rv.to_bytes)
        end
      end

      q = Queue.new
      # This thread waits for something to appear in the
      # queue, sent by the send_message_async below, before
      # sending the disconnect
      Thread.new do
        q.shift
        c.disconnect
        # Test postconditions
        assert_equal(10, flush_count)
        assert_equal(1, EventMachine.stopcount)
      end

      # This thread sends several Tversion messages, and expects them to
      # all be flushed, i.e. each send_message_async should receive
      # an Rflush message as the response.
      Thread.new do
        1.upto(10) do
          c.send_message_async(RStyx::Message::Tversion.new(:msize => 0xdeadbeef,
                                                            :version => "9P2000")) do |tx, rx|
            # We should be expecting rx to be an Rflush message
            assert_equal(RStyx::Message::Rflush, rx.class)
          end
        end

        # Wake up the thread waiting on the queue above, now that the
        # message is out.
        q << 0
      end
    end
  end

end

#
# Test the connection class
#
class ConnectionTest < Test::Unit::TestCase
  # Test the fid get/return methods
  def test_fid_methods
    c = RStyx::Client::Connection.new
    fid = c.send(:get_free_fid)
    assert(c.usedfids.include?(fid))
    c.send(:return_fid, fid)
    assert(!c.usedfids.include?(fid))

    # Get all fids, and test for the error condition of running
    # out of fids.
    0.upto(RStyx::MAX_FID) do |i|
      c.send(:get_free_fid)
    end
    assert_raises(RStyx::StyxException) do
      c.send(:get_free_fid)
    end
  end

  def test_connect
    # Just raises an exception--as this class shouldn't be used
    # as is.
    c = RStyx::Client::Connection.new
    assert_raises(RStyx::StyxException) do
      c.connect
    end
  end
end
