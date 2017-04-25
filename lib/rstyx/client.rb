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
      ##
      # Root FID
      attr_accessor :rootfid

      def post_init
        # Initial message buffer
        @msgbuffer = "".force_encoding("ASCII-8BIT")
        # Hash with sent messages indexed by tag
        @sentmessages = Hash.new
        # FIDs
        @usedfids = []
        @pendingclunks = Hash.new
        @rpendingclunks = Hash.new
        @uname = ENV['USER']
        @aname = ""
        @rootfid = nil
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
          #    T/Rauth messages to do authentication so we have no samples
          #    to try to do this.
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
          unless @usedfids.include?(i)
            fid = i
            break
          end
        end

        if fid.nil?
          raise StyxException.new("No more free fids")
        end
        @usedfids << fid
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
      # DO NOT USE THIS METHOD TO SEND A TCLUNK DIRECTLY!
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
      # Receive and process a Styx protocol message.
      def receive_message(styxmsg)
        # Look for its tag in the hash of sent messages.
        tmsg = @sentmessages.delete(styxmsg.tag)

        if tmsg.nil?
          # Ignore unrecognized messages.
          DEBUG > 0 && puts(" << ERR discarded unsolicited message #{message.to_s}")
          return
        end
 
        tmsg.response = styxmsg
        if styxmsg.is_a?(Message::Rflush)
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
        elsif styxmsg.is_a?(Message::Rerror)
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
        cdf = EventMachine::DefaultDeferrable.new
        df = EventMachine::DefaultDeferrable.new
        # Clunk all outstanding fids in reverse order so the root fid
        # gets clunked last.
        @usedfids.reverse_each do |fid|
          c= tclunk(fid)
          c.errback do |err|
            # An error here is most likely a no such fid error. Return the
            # fid manually in this case.
            return_fid(c.fid)
          end
          c.callback do
            cdf.succeed if @usedfids.length == 0
          end
        end
        cdf.callback do
          # flush all outstanding messages before final disconnect
          @sentmessages.keys.clone.each do |tag|
            tf = send_message(Message::Tflush.new(:oldtag => tag))
            tf.callback do
              if @sentmessages.length == 0
                close_connection()
                df.succeed
              end
            end
          end
          if @sentmessages.length == 0
            close_connection()
            df.succeed
          end
        end
        return(df)
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
      # Clunk a fid. Use this method only to send Tclunk messages.
      def tclunk(fid)
        # If there is already a pending clunk, return the clunk message
        # that was already sent.
        if @rpendingclunks.has_key?(fid)
          return(@rpendingclunks[fid])
        end
        clunk = Message::Tclunk.new(:fid => fid)
        send_message(clunk)
        @pendingclunks[clunk.tag] = fid
        @rpendingclunks[fid] = clunk
        clunk.callback do
          # return the FID to the pool after clunk
          fid = @pendingclunks.delete(clunk.tag)
          @rpendingclunks.delete(clunk.fid)
          return_fid(clunk.fid)
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

        fp = file.aopen(numeric_mode, perm, create)
#        if append
#          fp.callback do
#            fp.seek(0, 2)
#          end
#        end
        return(fp)
      end
    end                         # module StyxClient

    ##
    # Connect to a Styx server. The parameter is a connection descriptor of
    # the form proto!host!port.
    def self.connect(server, &block)
      proto,host,port = server.split("!")
      case proto
      when 'tcp'
        return(EventMachine.connect(host, port, StyxClient, &block))
      else
        raise StyxException, "unknown protocol #{proto}"
      end
    end

    ##
    # A Styx client's view of a file.  This class should probably
    # never be directly instantiated, but only via StyxClient#open.
    # The buffering algorithm in use here is somewhat based on the
    # Buffering mix-in module in the Ruby OpenSSL module written by
    # Goto Yuuzou, but modified a bit to provide for offset
    # handling.
    #
    class File
      include Enumerable, EventMachine::Deferrable

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
      # Open the file on the server asynchronously.
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
      # Returns:: Self. Attach any callbacks/errbacks to it.
      #
      def aopen(mode, perm, create)
        dfid = @conn.newfid
        basename = ::File.basename(@path)
        dirname = ::File.dirname(@path)
        twalk = Message::Twalk.new(:fid => @conn.rootfid, :newfid => dfid)
        twalk.path = dirname
        @conn.send_message(twalk)
        twalk.errback { |err| self.fail(err) }
        twalk.callback do
          rwalk = twalk.response
          # if the rwalk has some other length than the number of path
          # elements in the original twalk, some element of the path doesn't
          # exist and the file can't be opened.
          if rwalk.qids.length != twalk.wnames.length
            self.fail("#{path} no such file or directory")
            next
          end
          ropen = fid = nil
          # Next, walk to the basename from there, using a new fid
          fid = @conn.newfid
          twalk = Message::Twalk.new(:fid => dfid, :newfid => fid)
          twalk.path = basename
          @conn.send_message(twalk)
          twalk.errback do |err|
            # XXX -- file creation
            self.fail(err)
          end
          twalk.callback do
            topen = @conn.send_message(Message::Topen.new(:fid => fid, :mode => mode))
            topen.callback do
              ropen = topen.response
              cl=@conn.tclunk(dfid)
              cl.callback do
                # If we get here, we were able to successfully open or create
                # the file.
                @mode = mode
                @fid = fid
                @qid = ropen.qid
                @iounit = ropen.iounit
                # XXX: Determine if the file is actually a directory.  Such a
                # file would have its Qid.qtype high bit set to 1. In this
                # case, instead of passing back self, we should pass a
                # Directory object.
                self.succeed(self)
              end
              cl.errback { |err| self.fail(err) }
            end

            topen.errback do |err|
              # XXX -- file creation
              self.fail(err)
            end
          end
        end
        return(self)
      end

      ##
      # Read the Stat information for the file.
      #
      # returns: self, callback returns the RStyx::Message::Stat instance
      # corresponding to the file.
      #
      def astat
        return(@conn.send_message(Message::Tstat.new(:fid => @fid)))
      end

      ##
      # Close the file.  XXX: This should flush all unwritten buffered data
      # if any. Uses self as a deferrable.
      #
      def aclose
        if @fid >= 0
          # Clunk the fid
          clunk = @conn.tclunk(@fid)
          clunk.callback do
            @fid = -1
            @iounit = 0
            @mode = -1
            self.succeed(self)
          end
          clunk.errback do |err|
            @fid = -1
            @iounit = 0
            @mode = -1
            self.fail(err)
          end
        end
        self.succeed(self)
      end

      def closed?
        return(@mode < 0)
      end

      ##
      # Read +size+ bytes from +offset+. Returns a new deferrable,
      # which succeeds and is passed the data read and the offset at which
      # the last read finished, or fails with the error message.  If the size
      # argument is negative or omitted, read until EOF. The reads
      # performed are sequential. Should probably not be used directly.
      #
      # +size+:: number of bytes to read from the file
      # +offset+:: the offset to read from.
      # return:: Deferrable
      def _sysread(size=-1, offset=0)
        srdf = EventMachine::DefaultDeferrable.new
        bytes_to_read = size
        data = "".force_encoding("ASCII-8BIT")
        asrcb = lambda do |rdata|
          unless rdata.nil?
            if rdata.length == 0
              srdf.succeed(data, offset) # EOF
              next
            end
            offset += rdata.length
            data << rdata
            if size >= 0
              bytes_to_read -= rdata.length
            end
          end
          if size < 0 || bytes_to_read > @iounit
            n = @iounit
          elsif bytes_to_read <= 0
            srdf.succeed(data, offset)
            next
          else
            n = bytes_to_read
          end
          asr = _asysread(n, offset)
          asr.callback(&asrcb)
          asr.errback { |err| srdf.fail(err) }
        end
        # initiate the loop by passing nil
        asrcb.call(nil)
        return(srdf)
      end

      private

      ##
      # Read at most +size+ bytes or up to iounit. Returns a new
      # Deferrable, which succeeds when the Rread is received, or
      # fails on an Rerror. Will return zero size responses on
      # end of file. Should probably not be used directly.
      def _asysread(size, offset)
        df = EventMachine::DefaultDeferrable.new
        if size > @iounit
          size = @iounit
        end
        tr = @conn.send_message(Message::Tread.new(:fid => @fid,
                                                   :offset => offset,
                                                   :count => size))
        tr.callback { df.succeed(tr.response.data) }
        tr.errback { |err| df.fail(err) }
        return(df)
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
