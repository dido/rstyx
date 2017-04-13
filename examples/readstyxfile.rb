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
# Styx file reader
#
require 'rstyx'

RSTYX_HOST = "localhost"
RSTYX_PORT = 9876

file = ARGV[0]
authinfofile = ARGV[1]
authinfo = RStyx::Auth::DummyAuthenticator.new
unless authinfofile.nil?
  File.open(authinfofile) do |fp|
    authinfo = RStyx::Keyring::Authinfo.readauthinfo(fp)
  end
end

module RStyx
  DEBUG = 1
end

Thread.abort_on_exception = true

RStyx::Client::TCPConnection.new(RSTYX_HOST, RSTYX_PORT,
                                 authinfo).connect do |conn|
  conn.open(file, "r") do |fp|
    d = fp.read
    p d
  end
end
