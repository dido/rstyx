#!/usr/bin/ruby
#
# Author:: Rafael R. Sevilla (mailto:dido@imperium.ph)
# Copyright:: Copyright (c) 2005-2007 Rafael R. Sevilla
# Homepage:: http://rstyx.rubyforge.org/
# License:: GNU Lesser General Public License / Ruby License
#
# $Id: fileondisk.rb 292 2007-09-19 07:42:21Z dido $
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
# Test server that serves up a file (or directory) on the host machine's
# filesystem.
#
require 'rstyx'
require 'logger'

log = Logger.new(STDOUT)
sd = RStyx::Server::SDirectory.new("/")
sf = RStyx::Server::FileOnDisk.new(ARGV[0])
authinfo = nil
unless ARGV[1].nil?
  File.open(ARGV[1]) do |fp|
    authinfo = RStyx::Keyring::Authinfo.readauthinfo(fp)
  end
end
sf.add_changelistener do |f|
  puts "File contents changed"
end
sd << sf
serv = RStyx::Server::TCPServer.new(:bindaddr => "0.0.0.0",
                                    :port => 9876,
                                    :root => sd,
                                    :log => log,
                                    :debug => Logger::DEBUG,
                                    :auth => authinfo)
Thread.abort_on_exception = true
serv.run.join

