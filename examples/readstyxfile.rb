#!/usr/bin/ruby
#
# Author:: Rafael R. Sevilla (mailto:dido@imperium.ph)
# Copyright:: Copyright (c) 2005-2007 Rafael R. Sevilla
# Homepage:: http://rstyx.rubyforge.org/
# License:: GNU Lesser General Public License / Ruby License
#
# $Id: readstyxfile.rb 290 2007-09-19 07:39:21Z dido $
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
# Styx file reader
#
require 'rstyx'

RSTYX_HOST = "localhost"
RSTYX_PORT = 9876

file = ARGV[0]
authinfofile = ARGV[1]
authinfo = nil
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
