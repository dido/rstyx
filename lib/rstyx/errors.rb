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
# Styx Exception classes.
#

module RStyx

  ##
  # Exception class for Styx errors.  Same as standard Exception
  # class for now, but here so we can distinguish Styx errors and
  # for later extension.
  #
  class StyxException < RuntimeError
  end

  ##
  # Raised when a FID not in use is referenced.
  #
  class FidNotFoundException < StyxException
    attr_accessor :fid

    def initialize(fid)
      @fid = fid
    end

    def message
      return("FID #{@fid} is already in use.")
    end
  end

  ##
  # Tag in use exception, raised when a tag already in use is reallocated.
  #
  class TagInUseException < StyxException
    attr_accessor :tag

    def initialize(tag)
      @tag = tag
    end

    def message
      return("Tag #{@tag} is already in use.")
    end
  end

  class FileExists < StyxException
  end

  class AuthenticationException < StyxException
  end

  class NoSuchAlgorithmException < AuthenticationException
  end

  class LocalAuthErr < AuthenticationException
  end

  class RemoteAuthErr < AuthenticationException
  end

  class InvalidCertificateException < AuthenticationException
  end

  class InvalidKeyException < AuthenticationException
  end

end
