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
# Unit tests for Inferno Keyring
#
require 'test/unit'
require 'eventmachine'
require 'rstyx/common'
require 'rstyx/auth'
require 'rstyx/keyring'
require 'rstyx/errors'

class KeyringTest < Test::Unit::TestCase
  def test_recvmsg
    n, = RStyx::Keyring::recvmsg("")
    assert_equal(5, n)
    # Invalid formats
    assert_raise(IOError) { RStyx::Keyring::recvmsg("123\n456") }
    assert_raise(IOError) { RStyx::Keyring::recvmsg("123a\n456") }
    assert_raise(IOError) { RStyx::Keyring::recvmsg("!12b\n456") }
    # Message exceeds maximum length (4096)
    assert_raise(IOError) { RStyx::Keyring::recvmsg("9999\n456") }

    # Valid formats
    n, data, rest = RStyx::Keyring::recvmsg("0003\n456")
    assert_equal(0, n)
    assert_equal("456", data)
    assert_equal("", rest)

    n, data, rest = RStyx::Keyring::recvmsg("0003\n456789")
    assert_equal(0, n)
    assert_equal("456", data)
    assert_equal("789", rest)

    n, data, rest = RStyx::Keyring::recvmsg("0003\n456")
    assert_equal(0, n)
    assert_equal("456", data)
    assert_equal("", rest)

    # Error messages
    assert_raise(RStyx::RemoteAuthErr) { RStyx::Keyring::recvmsg("!003\n456") }

    assert_raise(RStyx::RemoteAuthErr) { RStyx::Keyring::recvmsg("!003\n456789") }
  end
end
