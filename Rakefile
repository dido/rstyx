# -*- Ruby -*-
#
# Author:: Rafael R. Sevilla (mailto:dido@imperium.ph)
# Copyright:: Copyright (c) 2005-2007 Rafael R. Sevilla
# Homepage:: http://rstyx.rubyforge.org/
# License:: GNU Lesser General Public License / Ruby License
#
# $Id: Rakefile 286 2007-09-19 07:33:59Z dido $
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
require 'rubygems'
require 'hoe'
require 'rcov/rcovtask'
require "./lib/rstyx/version"

class Hoe
  def extra_deps
    @extra_deps.reject { |x| Array(x).first == 'hoe' }
  end
end

PACKAGE_NAME = "rstyx"
PACKAGE_VERSION = RStyx::Version::STRING
TEST_GLOBS = "tests/**/tc_*.rb"

Hoe.new(PACKAGE_NAME, PACKAGE_VERSION) do |p|
  p.rubyforge_name = PACKAGE_NAME
  p.test_globs = TEST_GLOBS
  p.author = "Rafael R. Sevilla"
  p.email = "dido@imperium.ph"
  p.changes = ""
  p.description = "9P2000/Styx for Ruby"
  p.summary = "RStyx is a Ruby implementation of the 9P2000/Styx distributed file protocol used on Plan 9 and Inferno."
  p.url = "http://rubyforge.org/projects/rstyx"
  p.remote_rdoc_dir = ''
  p.extra_deps = [['eventmachine']]
end

Rcov::RcovTask.new(:coverage) do |t|
  t.test_files = FileList[TEST_GLOBS]
  t.verbose = true
end

desc "Tag the current trunk with the current release version"
task :tag do
  warn "WARNING: this will tag svn+ssh://rubyforge.org/var/svn/rstyx/trunk using the tag v#{RStyx::Version::MAJOR}.#{RStyx::Version::MINOR}.#{RStyx::Version::TINY}"
  warn "If you do not wish to continue, you have 5 seconds to cancel by pressing CTRL-C..."
  5.times { |i| print "#{5-i} "; $stdout.flush; sleep 1 }
    system "svn copy svn+ssh://rubyforge.org/var/svn/rstyx/trunk svn+ssh://rubyforge.org/var/svn/rstyx/tags/v#{RStyx::Version::MAJOR}.#{RStyx::Version::MINOR}.#{RStyx::Version::TINY} -m \"Tagging the #{RStyx::Version::STRING} release\""
end

# vim: syntax=Ruby

