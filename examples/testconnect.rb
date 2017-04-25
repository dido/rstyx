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
# Test connections. Rather unwieldy direct use of the library's evented
# callback API.
#
require 'rstyx'
require 'digest/sha1'

serv = ARGV[0]
serv ||= "tcp!localhost!9876"
filename = ARGV[1]
filename ||= "test.txt"

module RStyx
  DEBUG = 1
end

EventMachine::run do
   RStyx::Client::connect(serv) do |c|
    c.callback do
      puts "Connection to #{serv} successful\nOpening #{filename}"
      fp = c.open(filename)
      fp.callback do
        puts "Opened #{filename}. Stat."
        s=fp.astat
        s.callback do
          puts "Stat: #{s.response.stat}\nReading."
          r=fp._sysread
          r.errback do |err|
            puts "Error reading #{err}"
            EventMachine::stop_event_loop
          end
          r.callback do |data, offset|
            puts "To offset #{offset} digest: #{Digest::SHA1.hexdigest(data)} data read:\n#{data}"
            df=c.disconnect
            df.callback { EventMachine::stop_event_loop }
            df.errback do |err|
              puts "Error closing #{err}"
              EventMachine::stop_event_loop
            end
          end
        end
        s.errback do |err|
          puts "Error: #{err}"
          EventMachine::stop_event_loop
        end
      end

      fp.errback do |err|
        puts "Error: #{err}"
        EventMachine::stop_event_loop
      end
    end
    c.errback do |err|
      puts "Error connecting #{err}"
      EventMachine::stop_event_loop
    end
  end
end
