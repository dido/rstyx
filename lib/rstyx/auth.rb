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
# Authentication
#
module RStyx
  module Auth
    ##
    # Base class for Authenticators
    class Authenticator
      include EventMachine::Deferrable
      attr_accessor :connection

      def initialize
        @authenticated = false
        @connection = nil
      end

      def send_data(data)
        return(@connection.send_data(data))
      end

      def receive_data(data)
      end

      def authenticated?
        return(@authenticated)
      end

      def authenticate
      end
    end

    ##
    # Dummy authenticator
    class DummyAuthenticator < Authenticator
      def initialize
        super
        @authenticated = true
        self.succeed
      end
    end
  end
end

