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
# Test connections
#
require 'rstyx'

HOST = "localhost"
PORT = 9876

module RStyx
  DEBUG = 1
end

EventMachine::run do
  EventMachine.connect(HOST, PORT, RStyx::Client::StyxClient) do |c|
    c.callback do
      puts "Connection to #{HOST}!#{PORT} successful"
      c.disconnect.callback { EventMachine::stop_event_loop }
    end
    c.errback do |err|
      puts "Error connecting #{err}"
      EventMachine::stop_event_loop
    end
  end
end
