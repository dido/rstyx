
== Introduction

RStyx is an implementation of the Styx/9P2000 distributed filesystem
protocol used on Plan 9 and Inferno.  As of now, we've got a more full
client which supports Inferno authentication but not yet the
encryption layer used by Inferno.  The API is fairly simple at the
moment.  To open and read a file on a remote Styx server, the
following code should suffice:

  RStyx::Client::TCPConnection.new(styxserver, serverport) do |conn|
    conn.open(myfile, "r") do |fp|
      data = fp.read
    end
  end

Writing files is equally simple.

The design of this library is heavily influenced by the PyStyx Python
Styx client and JStyx itself (http://jstyx.sourceforge.net/).  The
Inferno authentication code is based on the Java styx-n-9p code
released by Vitanuova Inc.

There is a server in heavy development, that more or less works, but
is still somewhat incomplete.

== Things to Do

The client code needs far more extensive unit tests behind it.
There's probably a bit of breakage there that hasn't manifested in my
cursory tests connecting against a real Styx server.

The server code is not very well tested.  The new Inferno keyring
authentication code needs to be integrated into the Styx server.

If you wish to install this not via rubygems but manually, copy the
contents of the lib/ directory to a convenient location where Ruby
includes can find it, e.g. /usr/lib/ruby/site_ruby/1.8.  You'll also
need EventMachine (http://rubyforge.org/projects/eventmachine) to use
it.

$Id: README.txt 268 2007-09-18 05:32:57Z dido $
