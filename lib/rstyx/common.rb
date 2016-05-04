#!/usr/bin/ruby
#
# Author:: Rafael R. Sevilla (mailto:dido@imperium.ph)
# Copyright:: Copyright (c) 2005-2007 Rafael R. Sevilla
# Homepage:: http://rstyx.rubyforge.org/
# License:: GNU Lesser General Public License / Ruby License
#
# $Id: common.rb 298 2007-09-21 08:52:12Z dido $
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
# Common code and defined constants
#
module RStyx
  # File access modes in Styx
  OREAD = 0
  OWRITE = 1
  ORDWR = 2
  OEXEC = 3
  OTRUNC = 0x10
  ORCLOSE = 0x40

  # Constants related to the file type
  DMDIR =    0x80000000         # directory
  DMAPPEND = 0x40000000         # append-only file
  DMEXCL =   0x20000000         # exclusive use file
  DMAUTH =   0x08000000         # file used for authentication

  # Maximum FID numbers and the NOFID constant.
  MAX_FID = 0xfffffffe
  NOFID = 0xffffffff

  # Maximum tag number
  MAX_TAG = 0xffff

  # Seek mode constants
  SEEK_SET = 0
  SEEK_CUR = 1
  SEEK_END = 2

  # Maximum number of path elements
  MAXWELEM = 16

  #
  # Debugging
  # Debug levels:
  # 0 = no debugging output
  # 1 = Show dumps of all messages sent and received
  # 2 = In addition to dumps of messages, also the byte strings sent and
  #     received
  #
  DEBUG = 0

  # Limits of unsigned quanitities
  MAXUINT = 0xffffffff
end
