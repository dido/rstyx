#!/usr/bin/ruby
#
# Author:: Rafael R. Sevilla (mailto:dido@imperium.ph)
# Copyright:: Copyright (c) 2005-2007 Rafael R. Sevilla
# Homepage:: http://rstyx.rubyforge.org/
# License:: GNU Lesser General Public License / Ruby License
#
# $Id: testserver.rb 293 2007-09-19 07:43:41Z dido $
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
# Test server that serves up a simple file named test.file that is
# an InMemoryFile.
#
require 'rstyx'
require 'logger'

log = Logger.new(STDOUT)
sd = RStyx::Server::SDirectory.new("/")
sf = RStyx::Server::InMemoryFile.new("test.file")
authinfo = nil
unless ARGV[0].nil?
  File.open(ARGV[0]) do |fp|
    authinfo = RStyx::Keyring::Authinfo.readauthinfo(fp)
  end
end
sf.contents = "hello"
sf.add_changelistener do |f|
  puts "File contents changed to #{f.contents}"
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

