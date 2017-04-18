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
# Styx Client
#

require 'thread'
require 'timeout'

module RStyx

  module Client

    ##
    # Message receiving module for the Styx client.  The client will
    # assemble all inbound messages. 
    #
    module StyxClient
      include EventMachine::Deferrable
      ##
      # Pending messages sent awaiting replies
      attr_accessor :sentmessages
      ##
      # Authenticator object
      attr_accessor :auth
      ##
      # Message size for client
      attr_accessor :msize
      ##
      # Used FIDs for the connection
      attr_accessor :usedfids

      def post_init
        # Initial message buffer
        @msgbuffer = "".force_encoding("ASCII-8BIT")
        # Hash with sent messages indexed by tag
        @sentmessages = Hash.new
        # FIDs
        @usedfids = Hash.new
        @pendingclunks = Hash.new
        @rpendingclunks = Hash.new
        @uname = ENV['USER']
        @aname = ""
        # Begin handshaking process with remote server.
        # 1. Send a Tversion message and check the response from the
        #    remote Styx server.
        tv = send_message(Message::Tversion.new(:msize => MSIZE,
                                                :version => STYX_VERSION))
        tv.callback do
          rver = tv.response
          if rver.version != STYX_VERSION
            self.fail("Server uses unsupported Styx version #{rver.version}")
          end
          @msize = rver.msize
          @version = rver.version
          # 2. Attach to the remote server. XXX support authenticated
          #    connections. Trouble is the Inferno servers don't use the
          #    T/Rauth messages to do authentication so...
          begin
            rfid = newfid()
            ta = send_message(Message::Tattach.new(:fid => rfid,
                                                   :afid => NOFID,
                                                   :uname => @uname,
                                                   :aname => @aname))
          rescue
            self.fail($!.message)
          end
          ta.callback do
            # Connection successful
            @rootfid = rfid
            self.succeed
          end
          ta.errback { |errmsg| self.fail(errmsg) }
        end
        tv.errback { |errmsg| self.fail(errmsg) }
      end

      ##
      # Get a new FID
      def newfid
        fid = nil
        0.upto(MAX_FID) do |i|
          unless @usedfids.has_key?(i)
            fid = i
            break
          end
        end

        if fid.nil?
          raise StyxException.new("No more free fids")
        end
        @usedfids[fid] = true
        return(fid)
      end

      ##
      # Return a FID to the FID pool
      def return_fid(fid)
        @usedfids.delete(fid)
      end

      ##
      # Send a message asynchronously.
      #
      # +message+:: [StyxMessage] the message to be sent
      # return:: [StyxMessage] the message that was sent, possibly with tag
      # filled in or changed.
      #
      def send_message(message)
        # store the message and callback indexed by tag
        if message.tag.nil?
          # If a tag has not been explicitly specified, get
          # a new tag for the message. We use the message's own
          # object ID as the base and use what amounts to a
          # linear probing algorithm to determine a new tag in case
          # of collisions.
          tag = message.object_id % MAX_TAG
          while @sentmessages.has_key?(tag)
            tag = (tag + 1) % MAX_TAG
          end
          message.tag = tag
        end
        @sentmessages[message.tag] = message

        DEBUG > 0 && puts(" >> #{message.to_s}")
        DEBUG > 1 && puts(" >> #{message.to_bytes.unpack("H*").inspect}")
        # Send the message to our peer
        send_data(message.to_bytes)
        return(message)
      end

      ##
      # Receive and process a Styx protocol message
      def receive_message(styxmsg)
        # Look for its tag in the hash of sent messages.
        tmsg = @sentmessages.delete(styxmsg.tag)

        if tmsg.nil?
          # Ignore unrecognized messages.
          DEBUG > 0 && puts(" << ERR discarded unsolicited message #{message.to_s}")
          return
        end
 
        tmsg.response = styxmsg
        case styxmsg.class
        when Message::Rflush
          # If we flushed a message by sending a Tflush ourselves
          # then we should also fail the oldtag message and send
          # the Rflush as its response.
          if tmsg.is_a?(Message::Tflush)
            otmsg = @sentmessages.delete(tmsg.oldtag)
            otmsg.response = styxmsg
            otmsg.fail("flushed message")
            tmsg.succeed
          else
            # Fail the transmitted message if it was not a Tflush
            tmsg.fail("peer flushed message")
          end
        when Message::Rerror
          tmsg.fail(styxmsg.ename)
        else
          tmsg.succeed
        end
      end

      ##
      # Receive data from the network connection, called by EventMachine.
      #
      def receive_data(data)
        @msgbuffer << data
        DEBUG > 1 && puts(" << #{data.unpack("H*").inspect}")
        while @msgbuffer.length > 4
          length = @msgbuffer.unpack("V")[0]
          # Break out if there is not enough data in the message
          # buffer to construct a message.
          if @msgbuffer.length < length
            break
          end

          # Decode the received data
          message, @msgbuffer = @msgbuffer.unpack("a#{length}a*")
          styxmsg = Message::StyxMessage.from_bytes(message)
          DEBUG > 0 && puts(" << #{styxmsg.to_s}")
          receive_message(styxmsg)
          # after all this is done, there may still be enough data in
          # the message buffer for more messages so keep looping.
        end
        # If we get here, we don't have enough data in the buffer to
        # build a new message and we have to go back to the event loop.
      end

      ##
      # Disconnect from the remote server.
      #
      def disconnect
        # flush all outstanding messages before disconnect
        sentmessages.keys.each do |tag|
          tf = send_message(Message::Tflush.new(:oldtag => tag))
          tf.callback do
            if sentmessages.length == 0
              close_connection()
              self.succeed
            end
          end
        end
        if sentmessages.length == 0
          close_connection()
          self.succeed
        end
        return(self)
      end

      ##
      # Unbind handler. In this case, we manually send an Rflush
      # reply and failure to all pending messages, if any.
      def unbind
        sentmessages.each_pair do |tag,msg|
          msg.response = Message::Rflush.new
          msg.fail("remote host closed connection")
        end
      end

      ##
      # Open a file on the Styx server. Asynchronous. Returns a File
      # object, which is also a deferrable.
      def open(path, mode="r", perm=0666)
        file = File.new(self, path)
        append = false
        create = false
        numeric_mode = nil
        if mode.is_a?(Integer)
          numeric_mode = mode
        else
          case mode.to_s
          when "r"
            numeric_mode = OREAD
          when "r+"
            numeric_mode = ORDWR
          when "w"
            numeric_mode = OTRUNC | OWRITE
            create = true
          when "w+"
            numeric_mode = OTRUNC | ORDWR
            create = true
          when "a"
            numeric_mode = OWRITE
            append = true
            create = true
          when "a+"
            numeric_mode = ORDWR
            append = true
            create = true
          when "e"
            numeric_mode = OEXEC
          else
            raise StyxException.new("invalid access mode #{mode}")
          end
        end

        fp = file.open(numeric_mode, perm, create, &block)
        if append
          fp.callback do
            fp.seek(0, 2)
          end
        end
        return(fp)
      end
    end                         # module StyxClient

    class Connection
      attr_accessor :usedfids, :pendingclunks, :umask
      attr_reader :connectstate, :msize, :version
      attr_reader :rootdirectory, :rootfid, :authenticator

      def initialize(auth=DummyAuthenticator.new)
        @usedfids = []
        @pendingclunks = {}
        @rpendingclunks = {}
        @conn = nil
        @rootfid = nil
        @eventthread = nil
        @authenticator = auth
        @clunklock = Mutex.new
        @umask = ::File.umask
        @peerauth = nil
      end

      ##
      # Get a new free FID.
      #
      def get_free_fid
        found = false
        val = nil
        0.upto(MAX_FID) do |i|
          unless @usedfids.include?(i)
            val = i
            break
          end
        end

        if val.nil?
          raise StyxException.new("No more free fids")
        end
        @usedfids << val
        return(val)
      end

      ##
      # Returns a fid after we're done using it.
      #
      def return_fid(fid)
        @usedfids.delete(fid)
      end

      protected

      ##
      # This method is used to prepare the connection, and should be
      # defined by subclasses.
      #
      def prepare_connection
        raise StyxException.new("No prepare_connection method defined")
      end

      public

      ##
      # Connect to a remote Styx server.  If a block is passed, yield
      # self to the block and then do a disconnect when the block
      # finishes.
      #
      def connect(&block)
        prepare_connection()
        uname = ENV['USER']
        aname = ""

        # Set the authenticator object
        @authenticator.connection = @conn
        @conn.auth = @authenticator
        @authenticator.authenticate

        # Connection has been established.  Begin the handshaking process
        # with the remote server.
        #
        # 1. Send a Tversion message and check the response from the
        #    remote Styx server.
        #
        rver = send_message(Message::Tversion.new(:msize => 8216,
                                                  :version => "9P2000"))
        if (rver.version != "9P2000")
          raise StyxException.new("Server uses unsupported Styx version #{rver.version}")
        end
        @msize = rver.msize
        @version = rver.version
        rfid = nil
        # 2. Attach to the remote server
        if @auth.nil? || @authenticator.is_a?(Keyring::Authinfo)
          # unauthenticated connection
          rfid = get_free_fid
          rattach = send_message(Message::Tattach.new(:fid => rfid,
                                                      :afid => NOFID,
                                                      :uname => uname,
                                                      :aname => aname))
        else
          #
          # 3. Perform authentication based on the passed authenticator
          #    object.
          #
          # If we have an authenticator object, we call its authenticator
          # method.
          #
          rfid = @auth.authenticate
        end

        # If we get here, we're connected, and rfid represents the root
        # fid of the connection
        @rootfid = rfid

        if block_given?
          begin
            yield self
          ensure
            self.disconnect
          end
        else
          return(self)
        end
      end

      ##
      # Disconnect from the remote server.
      #
      def disconnect
        # Clunk all outstanding fids in reverse order so the root fid
        # gets clunked last.
        while (@usedfids.length > 0)
          begin
            rclunk = tclunk(@usedfids[-1], true)
          rescue
            # An error is most likely a no such fid error.  Return the fid
            # manually in this case.
            return_fid(@usedfids[-1])
          end
        end

        @conn.disconnect
        @eventthread.kill
      end

      ##
      # Send a message, and return the response.  Delegates to
      # @conn#send_message.  Do not use this method to send Tclunk
      # messages!
      #
      def send_message(msg, timeout=0)
        @conn.send_message(msg, timeout)
      end

      ##
      # Fire and forget a Tclunk for some fid.  When the Rclunk is
      # received, return the fid.  USE THIS METHOD, AND THIS METHOD
      # ONLY, to send Tclunk messages.
      #
      def tclunk(fid, sync=false)
        if @rpendingclunks.has_key?(fid)
          return
        end
        q = nil
        if sync
          q = Queue.new
        end
        tag = @conn.send_message_async(Message::Tclunk.new(:fid => fid)) do |tx,rx|
          # Test whether the response is an Rclunk.
          if rx.class != Message::Rclunk
            # this is an error condition, but it will only get reported
            # if Thread.abort_on_exception is set to true, or if
            # the tclunk is synchronous
            exc = StyxException.new("#{tx.to_s} received #{rx.to_s}")
            if sync
              q << exc
            else
              raise exc
            end
          end
          # return the FID
          fid = @pendingclunks.delete(tag)
          @rpendingclunks.delete(fid)
          return_fid(fid)
          if sync
            q << fid
          end
        end
        @pendingclunks[tag] = fid
        @rpendingclunks[fid] = tag
        if sync
          res = q.shift
          if res.class == StyxException
            raise res
          end
        end
      end

      ##
      # Open a file on the remote server, throwing a StyxException if the
      # file can't be found or opened in a given mode.
      #
      # +path+:: The path of the file relative to the server root.
      # +mode+:: Integer representing the mode, or one of "r", "r+",
      #          "w", "w+", "a", "a+", "e" as aliases
      # +return+:: A File object representing the opened file, or
      #          possibly a Directory object if the file was a directory.
      #
      # If a block is passed, it will yield the file object to the block
      # and close the file when the block finishes (actually it will pass
      # the block on to the StyxFile#open method, which does just that).
      #
      def open(path, mode="r", perm=0666, &block)
        file = File.new(self, path)

        append = false
        create = false
        numeric_mode = nil
        if mode.is_a?(Integer)
          numeric_mode = mode
        else
          case mode.to_s
          when "r"
            numeric_mode = OREAD
          when "r+"
            numeric_mode = ORDWR
          when "w"
            numeric_mode = OTRUNC | OWRITE
            create = true
          when "w+"
            numeric_mode = OTRUNC | ORDWR
            create = true
          when "a"
            numeric_mode = OWRITE
            append = true
            create = true
          when "a+"
            numeric_mode = ORDWR
            append = true
            create = true
          when "e"
            numeric_mode = OEXEC
          else
            raise StyxException.new("invalid access mode #{mode}")
          end
        end

        fp = file.open(numeric_mode, perm, create, &block)
        if append
          fp.seek(0, 2)
        end
        return(fp)
      end

    end                         # class Connection

    ##
    # TCP connection subclass.
    #
    class TCPConnection < Connection
      def initialize(host, port, auth=nil)
        @host = host
        @port = port
        super(auth)
      end

      protected

      ##
      # Prepare a TCP connection to the Styx server
      #
      def prepare_connection
        queue = Queue.new
        @eventthread = Thread.new do
          EventMachine::run do
            queue << EventMachine::connect(@host, @port, StyxClient)
          end
        end

        @conn = queue.shift
      end

      public

    end                         # class TCPConnection

    ##
    # A Styx client's view of a file.  This class should probably
    # never be directly instantiated, but only via Connection#open.
    # The buffering algorithm in use here is somewhat based on the
    # Buffering mix-in module in the Ruby OpenSSL module written by
    # Goto Yuuzou, but modified a bit to provide for offset
    # handling.  Note that this class isn't thread-safe.
    #
    class File
      include Enumerable

      attr_reader :conn, :path
      attr_accessor :mode, :fid, :qid, :iounit, :sync

      def initialize(conn, path)
        @conn = conn            # the connection on which the file sits
        @path = path            # pathname of the file
        @fid = -1               # the client's file identifier
        @qid = nil              # the server's unique identifier for this file
        # maximum number of bytes that can be read or written to the file at a time
        @iounit = 0
        @mode = -1              # mode under which the file is opened, -1 == not open
        @offset = 0             # File offset.  This is the same as @boffset only after a seek
        @rboffset = 0           # Read buffer offset
        @eof = false
        @rbuffer = ""
        @sync = false           # whether or not to buffer writes
      end

      ##
      # Open the file on the server.  If a block is passed to this method
      # it will pass the file to the block and close the file automatically
      # when the block terminates.
      #
      # This follows more or less the same semantics as sys-open(2)
      # on Inferno, performing an open with truncate, when a file
      # is opened that doesn't exist.
      #
      # XXX - twalk should handle the case of MAXWELEM, as well as for
      #       when the twalk message is too large to fit in the server's
      #       designated msize.
      #
      # +mode+:: Integer representing the mode - see the constants in common.rb
      # +perm+:: Permissions of the file (only used on open/create)
      # +create+:: should we create the file if it doesn't exist?
      #
      def open(mode, perm, create, &block)
        dfid = @conn.get_free_fid
        basename = ::File.basename(@path)
        dirname = ::File.dirname(@path)
        # Walk to the dirname first
        twalk = Message::Twalk.new(:fid => @conn.rootfid, :newfid => dfid)
        twalk.path = dirname
        rwalk = @conn.send_message(twalk)
        # if the rwalk has some other length than the number of path
        # elements in the original twalk, we have failed.
        if rwalk.qids.length != twalk.wnames.length
          raise StyxException.new(("#{path} no such file or directory"))
        end
        ropen = fid = nil
        begin
          # Next, walk to the basename from there, using a new fid
          fid = @conn.get_free_fid
          twalk = Message::Twalk.new(:fid => dfid, :newfid => fid)
          twalk.path = basename
          rwalk = @conn.send_message(twalk)
          # Do a Topen if this succeeds
          open_msg = Message::Topen.new(:fid => fid, :mode => mode)
          ropen = @conn.send_message(open_msg)
          @conn.tclunk(dfid)
        rescue Exception => e
          # If we are being directed to create the file if it doesn't
          # already exist, send a Tcreate message, and use the response
          # for it as the ropen (the two classes respond to exactly the
          # same messages--ah the wonders of duck typing!).  If not,
          # or if that fails, this should propagate an exception upwards.
          if create
            # Alter the submitted permissions mask according to
            # the connection's umask
            perm &= ~(@conn.umask)
            create_msg = Message::Tcreate.new(:fid => dfid, :name => basename,
                                              :perm => perm, :mode => mode)
            ropen = @conn.send_message(create_msg)
            fid = dfid
          else
            raise e
          end
        end

        # If we get here, we were able to successfully open or create
        # the file.
        @mode = mode
        @fid = fid
        @qid = ropen.qid
        @iounit = ropen.iounit
        # Determine if the file is actually a directory.  Such a file
        # would have its Qid.qtype high bit set to 1.  In this case, instead
        # of returning self, we return self wrapped in a Directory object.
        retval = self
        if twalk.wnames.length == 0 || (rwalk.qids[-1].qtype & 0x80 != 0)
          retval = Directory.new(self)
        end
        if block_given?
          begin
            yield retval
          ensure
            retval.close
          end
        else
          return(retval)
        end
      end

      ##
      # Read the Stat information for the file.
      #
      # returns: the RStyx::Message::Stat instance corresponding to
      #          the file
      #
      def stat
        rstat = @conn.send_message(Message::Tstat.new(:fid => @fid))
        return(rstat.stat)
      end

      ##
      # Close the file.  This will flush all unwritten buffered data
      # if any.
      #
      def close
        flush rescue nil
        if @fid >= 0
          # Clunk the fid
          @conn.tclunk(@fid)
        end
        @fid = -1
        @iounit = 0
        @mode = -1
      end

      def closed?
        return(@mode < 0)
      end

      private

      ##
      # Read at most +size+ bytes from +offset+
      # If the size argument is negative or omitted, read until EOF.
      # This should probably not be used directly.
      #
      # +size+:: number of bytes to read from the file
      # +offset+:: the offset to read from.
      # return:: the data followed by the new offset
      #
      def _sysread(size=-1, offset=0)
        contents = ""
        bytes_to_read = size
        loop do
          if size < 0 || bytes_to_read > @iounit
            n = @iounit
          elsif bytes_to_read <= 0
            break
          else
            n = bytes_to_read
          end
          rread =
            @conn.send_message(Message::Tread.new(:fid => @fid,
                                                  :offset => offset,
                                                  :count => n))
          if rread.data.length == 0
            break                 # EOF
          end
          offset += rread.data.length
          contents << rread.data
          if size >= 0
            bytes_to_read -= rread.data.length
          end
        end
        return([contents, offset])
      end

      ##
      #
      # Write data to the file at +offset+.  No buffering is
      # performed.  This should probably not be used directly.
      #
      # +d+:: data to be written
      # +offset+:: the offset to write at
      #
      # returns the new offset and the number of bytes written
      #
      def _syswrite(d, offset)
        str = d.to_s
        pos = 0
        count = 0
        loop do
          bytes_left = str.length - pos
          if bytes_left <= 0
            break
          elsif bytes_left > @iounit
            n = @iounit
          else
            n = bytes_left
          end
          rwrite = @conn.send_message(Message::Twrite.new(:fid => @fid,
                                                          :offset => offset,
                                                          :data => str[pos..(pos+n)]))
          pos += n
          offset += n
          count += rwrite.count
        end
        return([offset, count])
      end

      ##
      # Add up to @iounit bytes to the read buffer.
      #
      def fill_rbuff
        d, @rboffset = _sysread(@iounit, @rboffset)
        if d.empty?
          @eof = true
        end
        @rbuffer << d
      end

      ##
      # Consume +size+ bytes from the read buffer.
      #
      def consume_rbuff(size=nil)
        if @rbuffer.empty?
          nil
        else
          size ||= @rbuffer.size
          ret = @rbuffer[0, size]
          @rbuffer[0, size] = ""
          return(ret)
        end
      end

      public

      ##
      # Read at most +size+ bytes from the Styx file or to the end of
      # file if omitted.  Returns nil if called at end of file.
      #
      def read(size=-1)
        until @eof
          # Fill up the buffer until we have at least the requested
          # size, or until end of file if size is negative.
          if size > 0 && size <= @rbuffer.size
            break
          end
          fill_rbuff
        end

        # We managed to slurp the entire file!
        if size < 0
          size = @rbuffer.size
        end

        @offset += size
        retval = consume_rbuff(size) || ""
        (size && retval.empty?) ? nil : retval
      end

      ##
      # Reads the next "line" from the Styx file; lines are separated by
      # +eol+.  An +eol+ of nil reads the entire contents.  Returns nil
      # if called at end of file.
      #
      def gets(eol=$/)
        idx = @rbuffer.index(eol)
        until @eof
          if idx
            break
          end
          fill_rbuff
          idx = @rbuffer.index(eol)
        end
        if eol.is_a?(Regexp)
          size = idx ? idx+$&.size : nil
        else
          size = idx ? idx+eol.size : nil
        end
        @offset += size
        return(consume_rbuff(size))
      end

      ##
      # Executes the block for evely line in the Styx file, where lines
      # are separated by +eol+.
      #
      def each(eol=$/)
        while line = self.gets(eol)
          yield line
        end
      end

      alias each_line each

      ##
      # Reads all of the lines in the Styx file, and returns them in an
      # array.  Lines are separated by an optional separator +eol+.
      #
      def readlines(eol=$/)
        ary = []
        while line = self.gets(eol)
          ary << line
        end
        ary
      end

      ##
      # Reads a line as with gets, but 
      def readline(eol=$/)
        raise EOFError if eof?
        return(gets(eol))
      end

      def getc
        c = read(1)
        return(c ? c[0] : nil)
      end

      def readchar
        raise EOFError if eof?
        getc
      end

      def ungetc(c)
        @rbuffer[0,0] = c.chr
        @offset -= 1
      end

      def eof?
        if !@eof && @rbuffer.empty?
          fill_rbuff
        end
        return(@eof && @rbuffer.empty?)
      end

      alias eof eof?

      private

      ##
      # Write data to the buffer if the buffer is not yet full, or
      # if it has been determined (e.g. by an end of line marker) that
      # we should flush the buffer, and actually write.
      #
      def do_write(s)
        unless defined?(@wbuffer)
          @wbuffer = ""
          # we obviously start writing at the current offset
          @wboffset = @offset
        end
        @wbuffer << s
        @offset += s.length
        #
        # We flush the buffer if at least one of the following conditions
        # has been met:
        # 
        # 1. The sync flag is set to true.
        # 2. The write buffer size has equalled or exceeded the connection's
        #    iounit.
        # 3. The write buffer now contains an end of line marker, in which
        #    cas we flush only until the end of line marker.
        #
        if @sync || @wbuffer.size >= @iounit || (idx = @wbuffer.rindex($/))
          remain = idx ? idx + $/.size : @wbuffer.length
          nwritten = 0
          ofs = @wboffset
          while remain > 0
            str = @wbuffer[nwritten, remain]
            ofs, nwrote = _syswrite(str, ofs)
            remain -= nwrote
            nwritten += nwrote
          end
          @wbuffer[0, nwritten] = ""
          @wboffset += nwritten
        end
      end

      public

      def write(s)
        do_write(s)
        return(s.length)
      end

      def <<(s)
        do_write(s)
        return(self)
      end

      def puts(*args)
        s = ""
        if args.empty?
          s << "\n"
        end
        args.each do |arg|
          s << arg.to_s
          if $/ && /\n\z/ !~ s
            s << "\n"
          end
        end
        do_write(s)
        return(nil)
      end

      def print(*args)
        s = ""
        args.each{ |arg| s << arg.to_s }
        do_write(s)
        return(nil)
      end

      def printf(s, *args)
        do_write(s % args)
        return(nil)
      end

      def flush
        osync = @sync
        @sync = true
        do_write ""
        @sync = osync
      end

      ##
      # Seek in the file.  The whence values may be one of SEEK_SET
      # SEEK_CUR, or SEEK_END, as defined in rstyx/common, and they
      # result in the offset being taken from the beginning of the
      # file, relative to the current offset, or from the end of the
      # file respectively.
      #
      # XXX: A seek, no matter where it goes, will always invalidate
      #      any buffering.  This is fine for write buffers, but is
      #      somewhat wasteful for the read buffers.
      #
      def seek(offset, whence)
        # Before seeking, flush the write buffers
        flush
        s = self.stat
        case whence
        when 0
          @offset = offset
        when 1
          @offset += offset
        when 2
          # We have to obtain the stat of the file to do this kind of seek.
          @offset = s.length + offset
        else
          raise StyxException.new("Invalid seek")
        end
        # After seeking, discard the read buffers
        @rbuffer = ""
        @rboffset = @offset
        @eof = (@offset >= s.length)
        return(@offset)
      end

      def tell
        return(@offset)
      end

      def rewind
        seek(0, 0)
      end

      ##
      # Reads +size+ bytes from the Styx file and returns them as a string.
      # Do not mix with other methods that read from the Styx file or you
      # may get unpredictable results.
      #
      def sysread(size=-1)
        data, @offset = _sysread(size, @offset)
        if data.length == 0
          return(nil)
        end
        return(data)
      end

      ##
      # Writes +data+ to the Styx file.  Returns the number of bytes written.
      # do not mix with other methods that write to the Styx file or you
      # may get unpredictable results.
      def syswrite(data)
        @offset, count = _syswrite(data, @offset)
        return(count)
      end

    end                         # class File

    ##
    # Styx directory.  This obtains the entries inside a directory, and
    # works by delegating to File.
    #
    class Directory
      include Enumerable

      def initialize(fp)
        @io = fp
        # directory entry buffer
        @read_direntries = []
        # byte buffer
        @data = ""
      end

      def close
        @io.close
      end

      def fid
        @io.fid
      end

      def qid
        @io.qid
      end

      ##
      # Read the next directory entry from the dir and return the file
      # name as a string.  Returns nil at the end of stream.
      #
      def read
        # if there are directory entries left over from the previous
        # read that have not yet been returned, return them.
        if @read_direntries.length != 0
          return(@read_direntries.shift.name)
        end
        # read iounit bytes from the directory--this must be unbuffered
        d = @io.sysread
        if d.nil?
          return(nil)
        end
        @data << d

        if (@data.empty?)
          return(nil)
        end

        # decode the directory entries in the iounit
        loop do
          delen = @data.unpack("v")[0]
          if delen.nil? || delen + 1 > @data.length
            break
          end
          edirent = @data[0..(delen + 1)]
          @data = @data[(delen + 2)..-1]
          @read_direntries << Message::Stat.from_bytes(edirent)
        end
        de = @read_direntries.shift
        if (de.nil?)
          return(nil)
        end
        return(de.name)
      end

      ##
      # Call the block once for each entry in the directory, passing
      # the filename of each entry as a parameter to the block.
      #
      def each
        if !block_given?
          raise LocalJumpError.new("no block given")
        end

        self.rewind
        until (de = read).nil?
          yield de
        end
      end

    end                         # class Directory

  end                           # module Client

end                             # module RStyx
