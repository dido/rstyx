#!/usr/bin/ruby
#
# Author:: Rafael R. Sevilla (mailto:dido@imperium.ph)
# Copyright:: Copyright (c) 2005-2016 Rafael R. Sevilla
# Homepage:: https://github.com/dido/rstyx
# License:: GNU Lesser General Public License / Ruby License
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2005-2016 Rafael Sevilla
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
# Styx Server
#
# To create a Styx server, one has to create an SDirectory object that
# acts as the server root, e.g.:
#
#   sd = RStyx::Server::SDirectory.new("/")
#   sf = RStyx::Server::InMemoryFile.new("test.file")
#   sf.contents = "hello"
#   sd << sf
#   serv = RStyx::Server::TCPServer.new(:bindaddr => "0.0.0.0",
#                                       :port => 9876,
#                                       :root => sd)
#   serv.run.join
#
#
require 'thread'
require 'monitor'
require 'timeout'
require 'rubygems'
require 'eventmachine'
require 'logger'
require 'socket'
require 'etc'
require 'rstyx/common'
require 'rstyx/messages'
require 'rstyx/errors'


module RStyx
  module Server
    ##
    # Message receiving module for the Styx server.  The module will
    # assemble all inbound messages and send them to a provided
    # 
    #
    module StyxServerProtocol
      ##
      # maximum message size supported
      attr_accessor :msize
      ##
      # Logger object used for logging server events
      attr_accessor :log
      ##
      # An authenticator which is sent messages received from the client.
      # Used when doing Inferno authentication.
      attr_accessor :authenticator
      ##
      # The session object corresponding to this connection
      attr_accessor :session
      ##
      # Server's authentication information
      attr_accessor :myauth
      ##
      # Connected peer's authentication information
      attr_accessor :userauth
      ##
      # Shared secret obtained during Inferno authentication
      attr_accessor :secret
      ##
      # Peer name
      attr_reader :peername

      DEFAULT_MSIZE = 8216

      def post_init
        @msize = DEFAULT_MSIZE
        # Buffer for messages received from the client
        @msgbuffer = ""
        # Session object for this session
        @session = Session.new(self)
        # Conveniences to allow the logger and root to be
        # more easily accessible from within the mixin.
        # Try to get the peername if available
        pname = get_peername()
        # XXX - We should be using unpack_sockaddr_un for
        # Unix domain sockets...
        if pname.nil?
          @peername = "(unknown peer)"
        else
          port, host = Socket.unpack_sockaddr_in(pname)
          @peername = "#{host}:#{port}"
        end
      end

      ##
      # Send a reply back to the peer
      def reply(msg, tag)
        # Check if the tag is still available.  If it has been
        # flushed, don't send the reply.
        if @session.has_tag?(tag)
          msg.tag = tag
          @log.debug("#{@peername} << #{msg.to_s}")
          send_data(msg.to_bytes)
          @session.release_tag(tag)
        end
      end

      ##
      # Process a StyxMessage.
      #
      def process_styxmsg(msg)
        begin
          tag = msg.tag
          @session.add_tag(tag)
          # call the appropriate handler method based on the name
          # of the StyxMessage subclass.  These methods should either
          # return a normal response, or raise an exception of
          # some sort that (usually) gets turned by this block into
          # an Rerror response based on the exception's message.
          pname = msg.class.name.split("::")[-1].downcase.intern
          resp = self.send(pname, msg)
          if resp.nil?
            raise StyxException.new("internal error: empty reply")
          end
          reply(resp, tag)
        rescue TagInUseException => e
          # In this case, we can't reply with an error to the client,
          # since the tag used was invalid!  If debug level is high
          # enough, simply print out an error.
          @log.error("#{@peername} #{e.class.to_s} #{msg.to_s}")
        rescue FidNotFoundException => e
          @log.error("#{@peername} unknown fid in message #{msg.to_s}")
          reply(Message::Rerror.new(:ename => "Unknown fid #{e.fid}"), tag)
        rescue StyxException => e
          @log.error("#{@peername} styx exception #{e.message} for #{msg.to_s}")
          reply(Message::Rerror.new(:ename => "Error: #{e.message}"), tag)
        rescue Exception => e
          @log.error("#{@peername} internal error #{e.message} for #{e.to_s} at #{e.backtrace}")
          reply(Message::Rerror.new(:ename => "Internal RStyx Error: #{e.message}"), tag)
        end

      end

      ##
      # Receive data from the network connection, called by EventMachine.
      #
      def receive_data(data)
        # If we are in keyring authentication mode, send
        if !(@authenticator.nil? || @authenticator.authenticated?)
          @authenticator.receive_data(self, data)
          return
        end
        @msgbuffer << data
        # self.class.log.debug(" << #{data.unpack("H*").inspect}")
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
          @log.debug("#{@peername} >> #{styxmsg.to_s}")
          process_styxmsg(styxmsg)

          # after all this is done, there may still be enough data in
          # the message buffer for more messages so keep looping.
        end
        # If we get here, we don't have enough data in the buffer to
        # build a new message, so we just have to wait until there is
        # enough.
      end
    end

    ##
    # Message receiving module for the Styx server.  The server will
    # assemble all inbound messages
    #
    module StyxServerProtocol
      ##
      # maximum message size supported
      attr_accessor :msize
      ##
      # Logger object used for logging server events
      attr_accessor :log
      ##
      # The root of the file tree for this server
      attr_accessor :root
      ##
      # An authenticator which is sent messages received from the client.
      # Used when doing Inferno authentication.
      attr_accessor :authenticator
      ##
      # The session object corresponding to this connection
      attr_accessor :session
      ##
      # Server's authentication information
      attr_accessor :myauth
      ##
      # Connected peer's authentication information
      attr_accessor :userauth
      ##
      # Shared secret obtained during Inferno authentication
      attr_accessor :secret
      ##
      # Peer name
      attr_reader :peername

      DEFAULT_MSIZE = 8216

      def post_init
        @msize = DEFAULT_MSIZE
        # Buffer for messages received from the client
        @msgbuffer = ""
        # Session object for this session
        @session = Session.new(self)
        # Conveniences to allow the logger and root to be
        # more easily accessible from within the mixin.
        # Try to get the peername if available
        pname = get_peername()
        # XXX - We should be using unpack_sockaddr_un for
        # Unix domain sockets...
        if pname.nil?
          @peername = "(unknown peer)"
        else
          port, host = Socket.unpack_sockaddr_in(pname)
          @peername = "#{host}:#{port}"
        end
      end

      def unbind
        @log.info("#{@peername} session closed")
      end

      ##
      # Handle version messages.  This handles the version negotiation.
      # At this point, the only version of the protocol supported is
      # 9P2000: all other version strings result in the server returning
      # 'unknown' in its Rversion.  A successful Tversion/Rversion
      # negotiation results in the protocol_negotiated flag in the
      # current session becoming true, and all other outstanding I/O
      # on the session (e.g. opened fids and the like) all removed.
      #--
      # External methods used:
      #
      # Session#reset_session *
      #++
      def tversion(msg)
        @cversion = msg.version
        @cmsize = msg.msize
        if @cversion != "9P2000"
          # Unsupported protocol version.  As per Inferno's version(5):
          #
          #   If the server does not understand the client's version
          #   string, it should respond with an Rversion message (not
          #   Rerror) with the _version_ string the 7 characters 'unknown'.
          #
          return(Message::Rversion.new(:version => "unknown", :msize => 0))
        end
        # Reset the session, which also causes the protocol negotiated
        # flag in the session to be set to true.
        @session.reset_session(@cmsize)
        return(Message::Rversion.new(:version => "9P2000", :msize => @msize))
      end

      ##
      # Handle auth messages.  This should be filled in later,
      # depending on the auth methods that we decide to support.
      #
      def tauth(msg)
        return(Message::Rerror.new(:ename => "Authentication methods through auth messages are not supported."))
      end

      ##
      # Handle attach messages.  Internally, this will result in the
      # fid passed by the client being associated with the root of the
      # Styx server's file system.  Possible error conditions here:
      #
      # 1. The client has not done a version negotiation yet.
      # 2. The client has provided a fid which it is already using
      #    for something else.
      #--
      # External methods used:
      #
      # Session#version_negotiated? *
      # Session#has_fid? *
      # Session#[]= *
      # SFile#qid (root) *
      #++
      def tattach(msg)
        # Do not allow attaches without version negotiation
        unless @session.version_negotiated?
          raise StyxException.new("Tversion not seen")
        end
        # Check that the supplied fid isn't already used.
        if @session.has_fid?(msg.fid)
          raise StyxException.new("fid already in use")
        end
        # Associate the fid with the root of the server.
        @session[msg.fid] = @root
        return(Message::Rattach.new(:qid => @root.qid))
      end

      ##
      # Handle flush messages.  The only result of this message
      # is it causes the server to forget about the tag passed:
      # any I/O already in progress when the flush message is
      # received is not actually aborted.  This is also the way
      # JStyx handles it.  Unfortunately, these semantics are wrong
      # from the Inferno manual, viz. flush(5):
      #
      #   If no response is received before the Rflush, the
      #   flushed transaction is considered to have been cancelled,
      #   and should be treated as though it had never been sent.
      #
      # XXX - The current implementation doesn't do this.  If a
      # Twrite is flushed, the write will still occur, but no
      # response will be sent back (except for some clients, such
      # as JStyx and RStyx which send the Rflush back to the
      # flushed transaction).  Some means, possibly a session-wide
      # global transaction lock on server internal state changes
      # may be necessary to allow flushes of this kind to work.
      #--
      # External methods used:
      #
      # Session#flush_tag *
      #++
      def tflush(msg)
        @session.flush_tag(msg.oldtag)
        return(Message::Rflush.new)
      end

      ##
      # Handle walk messages.
      #
      # Possible error conditions:
      #
      # 1. The client specified more than MAXWELEM path elements in the
      #    walk message.
      # 2. The client tried to walk to a fid that was already previously
      #    opened.
      # 3. The client used a newfid not the same as fid, where newfid
      #    is a fid already assigned to some other file on the server.
      # 4. The client tried to walk to a file which is not a directory.
      # 5. The client tried to descend the directory tree to a directory
      #    to which execute permission is not available.
      # 6. The client was unable to walk beyond the root to the file
      #    specified.
      #
      # Note that if several parts of the walk managed to succeed, this
      # method will still return an Rwalk response, but it will NOT
      # associate newfid with anything.
      #--
      # External methods used:
      #
      # Session#[] *
      # Session#[]= *
      # Session#has_fid? *
      #
      # SFile#client
      # SFile#directory?
      # SFile#name
      # SFile#atime=
      # SFile#[]
      # SFile#qid
      #++
      #
      def twalk(msg)
        if msg.wnames.length > MAXWELEM
          raise StyxException.new("Too many path elements in Twalk message")
        end
        fid = msg.fid
        # Check that the fid has not already been opened by the client
        sf = @session[fid]
        clnt = sf.client(@session, fid)
        unless clnt.nil?
          raise StyxException.new("cannot walk to an open fid")
        end
        nfid = msg.newfid
        # if the original and new fids are different, check that
        # the new fid isn't already in use.
        if nfid != fid && @session.has_fid?(nfid)
          raise StyxException.new("fid already in use")
        end

        rwalk = Message::Rwalk.new(:qids => [])
        num = 0
        msg.wnames.each do |n|
          unless sf.directory?
            raise StyxException.new("#{sf.name} is not a directory")
          end
          # Check file permissions if we're descending
          if n == ".." && !@session.execute?(sf)
            raise StyxException.new("#{sf.name}: permission denied")
          end
          sf.atime = Time.now
          sf = sf[n]
          if sf.nil?
            # Send an error response if the number of walked elements is 0
            if num == 0
              raise StyxException.new("file does not exist")
            end
            break
          end
          sf.atime = Time.now
          # This allows a client to get a fid representing the directory
          # at the end of the walk, even if the client does not have
          # execute permissions on that directory.  Therefore, in Inferno,
          # a client could cd into a directory but be unable to read
          # any of its contents.
          rwalk.qids << sf.qid
          sf.refresh
          num += 1
        end

        if rwalk.qids.length == msg.wnames.length
          # The whole walk operation was successful.  Associate
          # the new fid with the returned file.
          @session[nfid] = sf
        end

        return(rwalk)
      end

      ##
      # Handle open messages.
      #--
      # External methods used:
      #
      # Session#[]
      # Session#confirm_open
      # SFile#add_client
      # SFile#set_mtime
      # SFile#qid
      # Session#iounit
      # Session#user
      #++
      def topen(msg)
        sf = @session[msg.fid]
        mode = msg.mode
        @session.confirm_open(sf, mode)
        sf.add_client(SFileClient.new(@session, msg.fid, mode))
        if mode & OTRUNC == OTRUNC
          sf.set_mtime(Time.now, @session.user)
        end
        return(Message::Ropen.new(:qid => sf.qid, :iounit => @session.iounit))
      end

      ##
      # Handle tcreate messages
      def tcreate(msg)
        dir = @session[msg.fid]
        unless dir.directory?
          raise StyxException.new("can't create a file inside another file")
        end

        unless @session.writable?(dir)
          raise StyxException.new("permission denied, no write permissions to parent directory")
        end
        # Check the file type
        perm = msg.perm
        isdir = (perm & DMDIR) != 0
        isapponly = (perm & DMAPPEND) != 0
        isexclusive = (perm & DMEXCL) != 0
        isauth = (perm & DMAUTH) != 0

        if isauth
          # Auth files cannot be created by Styx messages
          raise StyxException.new("can't create a file of type DMAUTH")
        end

        # Get the low 9 bits of the permission number (these low 9 bits
        # are the rwxrwxrwx file permissions)
        operm = msg.perm & 01777
        # Get the real permissions of this file.  This depends on the
        # permissions of the parent directory
        realperm = operm
        if isdir
          realperm = operm & (~0777 | (dir.permissions & 0777))
          # directories must be opened with OREAD (no other bits set)
          if msg.mode != OREAD
            raise StyxException.new("when creating a directory must open with read permission only")
          end
        else
          realperm = operm & (~0666 | (dir.permissions & 0666))
        end

        # Create the file in the directory, add it to the directory tree,
        # and associate the new file with the given fid
        new_file = dir.newfile(msg.name, realperm, isdir, isapponly,
                               isexclusive)
        dir << new_file
        @session[msg.fid] = new_file
        new_file.add_client(SFileClient.new(@session, msg.fid, msg.mode))
        return(Message::Rcreate.new(:qid => new_file.qid,
                                    :iounit => @session.iounit))
      end

      ##
      # Handle reads
      #
      def tread(msg)
        sf = @session[msg.fid]
        # Check if the file is open for reading
        clnt = sf.client(@session, msg.fid)
        if clnt.nil? || !clnt.readable?
          raise StyxException.new("file is not open for reading")
        end

        if msg.count > @session.iounit
          raise StyxException.new("cannot request more than #{@session.iounit} bytes in a single read")
        end

        return(sf.read(clnt, msg.offset, msg.count))
      end

      ##
      # Handle writes
      #
      def twrite(msg)
        sf = @session[msg.fid]
        # Check that the file is open for writing
        clnt = sf.client(@session, msg.fid)
        if (clnt.nil? || !clnt.writable?)
          raise StyxException.new("file is not open for writing")
        end
        if msg.data.length > @session.iounit
          raise StyxException.new("cannot write more than #{@session.iounit} bytes in a single operation")
        end
        truncate = clnt.truncate?
        ofs = msg.offset
        # If this is an append-only file we ignore the specified offset
        # and just write to the end of the file, without truncation.
        # This relies on the SFile#length method returning an accurate
        # value.
        if sf.appendonly?
          ofs = sf.length
          truncate = false
        end

        return(sf.write(clnt, ofs, msg.data, truncate))
      end

      ##
      # Handle clunk messages.
      #
      def tclunk(msg)
        @session.clunk(msg.fid)
        return(Message::Rclunk.new)
      end

      ##
      # Handle remove messages.
      #
      def tremove(msg)
        # A remove is just like a clunk with the side effect of
        # removing the file if the permissions allow.
        sf = @session[msg.fid]
        sf.synchronize do
          @session.clunk(msg.fid)
          parent = sf.parent
          unless @session.writable?(parent)
            raise StyxException.new("permission denied")
          end

          if sf.instance_of?(SDirectory) && sf.child_count != 0
            raise StyxException.new("directory not empty")
          end
          sf.remove
          parent.set_mtime(Time.now, @session.user)
        end
        return(Message::Rremove.new)
      end

      ##
      # Handle stat messages
      #
      def tstat(msg)
        sf = @session[msg.fid]
        # Stat requests require no special permissions
        return(Message::Rstat.new(:stat => sf.stat))
      end

      ##
      # Handle wstat messages
      #
      def twstat(msg)
        nstat = msg.stat
        sf = @session[msg.fid]
        sf.synchronize do
          # Check if we are changing the file's name
          unless nstat.name.empty?
            dir = sf.parent
            unless @session.writable?(dir)
              raise StyxException.new("write permissions required on parent directory to change file name")
            end
            if dir.has_child?(nstat.name)
              raise StyxException.new("cannot rename file to the name of an existing file")
            end
            sf.can_setname?(nstat.name)
          end

          # Check if we are changing the length of a file
          if nstat.size != -1
            # Check if we have write permission on the file
            unless @session.writable?(sf)
              raise StyxException.new("write permissions required to change file length")
            end
            sf.can_setlength?(nstat.size)
          end

          # Check if we are changing the mode of a file
          if nstat.mode != MAXUINT
            # Must be the file owner to change the file mode
            if sf.uid != @session.user
              raise StyxException.new("must be owner to change file mode")
            end

            # Can't change the directory bit
            if ((nstat.mode & DMDIR == DMDIR) && !sf.directory?)
              raise StyxException.new("can't change a file to a directory")
            end
            sf.can_setmode?(nstat.mode)
          end

          # Check if we are changing the last modification time of a file
          if nstat.mtime != MAXUINT
            # Must be owner
            if sf.uid != @session.user
              raise StyxException.new("must be owner to change mtime")
            end
            sf.can_setmtime?(nstat.mtime)
          end

          # Check if we are changing the gid of a file
          unless nstat.gid.empty?
            # Disallowed for now
            raise StyxException.new("can't change gid on this server")
          end

          # No other types are possible for now
          unless nstat.dtype == 0xffff
            raise StyxException.new("can't change type")
          end

          unless nstat.dev == 0xffffffff
            raise StyxException.new("can't change dev")
          end

          unless nstat.qid == Message::Qid.new(0xff, 0xffffffff,
                                               0xffffffffffffffff)
            raise StyxException.new("can't change qid")
          end

          unless nstat.atime == 0xffffffff
            raise StyxException.new("can't change atime directly")
          end

          unless nstat.uid.empty?
            raise StyxException.new("can't change uid")
          end

          unless nstat.muid.empty?
            raise StyxException.new("can't change user who last modified file directly")
          end

          # Now, all the permissions have been checked, we can actually go
          # ahead with all the changes
          unless nstat.name.empty?
            sf.name = nstat.name
          end

          if nstat.size != -1
            sf.length = nstat.size
          end

          if nstat.mode != MAXUINT
            sf.mode = nstat.mode
          end

          if nstat.mtime != MAXUINT
            sf.mtime = nstat.mtime
          end

        end

        return(Message::Rwstat.new)
      end

      ##
      # Send a reply back to the peer
      def reply(msg, tag)
        # Check if the tag is still available.  If it has been
        # flushed, don't send the reply.
        if @session.has_tag?(tag)
          msg.tag = tag
          @log.debug("#{@peername} << #{msg.to_s}")
          send_data(msg.to_bytes)
          @session.release_tag(tag)
        end
      end

      ##
      # Process a StyxMessage.
      #
      def process_styxmsg(msg)
        begin
          tag = msg.tag
          @session.add_tag(tag)
          # call the appropriate handler method based on the name
          # of the StyxMessage subclass.  These methods should either
          # return a normal response, or raise an exception of
          # some sort that (usually) gets turned by this block into
          # an Rerror response based on the exception's message.
          pname = msg.class.name.split("::")[-1].downcase.intern
          resp = self.send(pname, msg)
          if resp.nil?
            raise StyxException.new("internal error: empty reply")
          end
          reply(resp, tag)
        rescue TagInUseException => e
          # In this case, we can't reply with an error to the client,
          # since the tag used was invalid!  If debug level is high
          # enough, simply print out an error.
          @log.error("#{@peername} #{e.class.to_s} #{msg.to_s}")
        rescue FidNotFoundException => e
          @log.error("#{@peername} unknown fid in message #{msg.to_s}")
          reply(Message::Rerror.new(:ename => "Unknown fid #{e.fid}"), tag)
        rescue StyxException => e
          @log.error("#{@peername} styx exception #{e.message} for #{msg.to_s}")
          reply(Message::Rerror.new(:ename => "Error: #{e.message}"), tag)
        rescue Exception => e
          @log.error("#{@peername} internal error #{e.message} for #{e.to_s} at #{e.backtrace}")
          reply(Message::Rerror.new(:ename => "Internal RStyx Error: #{e.message}"), tag)
        end

      end


      ##
      # Receive data from the network connection, called by EventMachine.
      #
      def receive_data(data)
        # If we are in keyring authentication mode, write any data received
        # into the @auth's buffer, and simply return.
        unless @authenticator.nil?
          @authenticator << data
          return
        end
        @msgbuffer << data
        # self.class.log.debug(" << #{data.unpack("H*").inspect}")
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
          @log.debug("#{@peername} >> #{styxmsg.to_s}")
          process_styxmsg(styxmsg)

          # after all this is done, there may still be enough data in
          # the message buffer for more messages so keep looping.
        end
        # If we get here, we don't have enough data in the buffer to
        # build a new message, so we just have to wait until there is
        # enough.
      end

    end

    ##
    # Session state of a Styx connection.
    #
    class Session < Monitor
      ##
      # Maximum message size to be used by this session, based on
      # the lesser of the server's and the client's msize.
      #
      attr_accessor :msize
      ##
      # Authenticated flag
      attr_accessor :auth
      ##
      # List of active fids on this session
      attr_accessor :fids
      ##
      # List of active tags on this session
      attr_accessor :tags
      ##
      # Flag which is true if version negotiation has been performed
      # on this session
      attr_accessor :version_negotiated
      ##
      # User this connection has authenticated against
      #
      attr_accessor :user
      ##
      # Active iounit for this connection
      #
      attr_accessor :iounit
      ##
      # Group table
      #
      attr_accessor :groups

      ##
      # Create a new session.
      #
      # _conn_:: The connection object (Server mixin)
      #
      def initialize(conn)
        @conn = conn
        @version_negotiated = false
        @msize = 0
        @user = nil
        @auth = false
        @fids = {}
        @tags = []
      end

      ##
      # Return true if the session peer has completed version negotiation
      #
      def version_negotiated?
        return(@version_negotiated)
      end

      ##
      # Reset the session, setting version negotiation flag and 
      # iounit.
      #
      #--
      # FIXME: should clunk all outstanding fids and release all outstanding
      # tags on this connection
      #++
      #
      # _msize_:: the maximum message size for this connection
      #
      def reset_session(msize)
        # XXX: clunk all outstanding fids and release all outstanding tags
        @version_negotiated = true
        @iounit = msize
      end

      ##
      # Associates a FID with a file.  The FID passed must be checked before
      # using this or the old FID will be forgotten.
      #
      # _fid_:: the fid to be associated
      # _file_:: the SFile to associate with _fid_
      #
      def []=(fid, file)
        @fids.delete(fid)
        @fids[fid] = file
      end

      ##
      # Gets the file associated with the indexed FID.  Raises a
      # FidNotFoundException if the fid is not present.
      #
      # _fid_:: the fid to obtain the associated SFile instance of
      #
      def [](fid)
        unless has_fid?(fid)
          raise FidNotFoundException.new(fid)
        end
        return(@fids[fid])
      end

      ##
      # Returns true if _fid_ is associated with some file on this
      # session.
      #
      def has_fid?(fid)
        return(@fids.has_key?(fid))
      end

      ##
      # Clunk _fid_, i.e. make the server forget about the fid assignment
      # for this connection.
      #
      def clunk(fid)
        unless @fids.has_key?(fid)
          raise FidNotFoundException.new(fid)
        end
        sf = self[fid]
        sf.synchronize do
          # Get the client using this fid, and see whether the file
          # is requested to be deleted on clunk.
          sfc = sf.client(self, fid)
          if (!sfc.nil? && sfc.orclose?)
            begin
              sf.remove
            rescue Exception => e
              # if there was a problem removing the file, ignore it
            end
          end
          sf.remove_client(sfc)
          @fids.delete(fid)
        end
      end

      ##
      # Clunk all outstanding fids on this connection.
      #
      def clunk_all
        @fids.each_key do |k|
          begin
            clunk(k)
          rescue FidNotFoundException => e
            # ignore this as we are closing down anyway...
          end
        end
      end

      ##
      # Returns true if _tag_ is associated with some active message
      #
      def has_tag?(tag)
        return(!@tags.index(tag).nil?)
      end

      ##
      # Adds the given _tag_ to the list of tags in use, first checking to
      # see if it is already in use.  Raises a TagInUseException if _tag_
      # is already in use.
      #
      def add_tag(tag)
        if has_tag?(tag)
          raise TagInUseException.new(tag)
        end
        @tags << tag
      end

      alias << add_tag

      ##
      # Called when a message is replied to, releasing _tag_ so it can
      # be used again.
      #
      def release_tag(tag)
        @tags.delete(tag)
      end

      alias flush_tag release_tag

      ##
      # Flush all outstanding tags on this session.
      #
      def flush_all
        @tags.each do |f|
          flush_tag(t)
        end
      end

      # These constants are used by Session#permission? and should NOT
      # be changed.  The algorithm used depends on it!
      EXECUTE = 0
      WRITE = 1
      READ = 2

      ##
      # Check the permissions for a given mode
      #
      # _sf_:: the file to check against
      # _mode_:: the mode to check (EXEC, WRITE, or READ)
      #
      def permission?(sf, mode)
        if mode < 0 || mode > 2
          raise "Internal error: mode should be 0, 1, or 2"
        end
        # We bit shift the permissions value so that the mode is
        # represented by the last bit (all) the fourth to last bit
        # (group), and the seventh-to-last bit (user).  For example,
        # if we started with a mode of 0755 (binary 111101101,
        # rwxrwxrwx), and we want to check write permissions, we
        # shift by one bit so that the value of perms is 1110110, or
        # (rwxrwxrw).
        perms = sf.permissions >> mode
        # Check permissions for 'all' -- the low-order bit
        unless perms & 0b000_000_001 == 0
          return(true)
        end

        # Group permissions
        unless (perms & 0b000_001_000) == 0
          # The group has the correct permissions; now we have to find if
          # the user is a member of the group in question.
          ug = @groups[@user]
          unless ug.index(sf.gid).nil?
            return(true)
          end
        end

        # Owner permissions.  This is the final fallback.
        return(((perms & 0b001_000_000) != 0) && (@user == sf.uid))
      end

      ##
      # Check for executable permission for the SFile _sf_.
      #
      def execute?(sf)
        return(permission?(sf, EXECUTE))
      end

      ##
      # Check for write permission for the SFile _sf_.
      def writable?(sf)
        return(permission?(sf, WRITE))
      end

      ##
      # Checks that the given file can be opened with the given mode.
      # Raises a StyxException if this is not possible.
      #
      # _sf_:: the SFile to be opened
      # _mode_:: the open mode
      #
      def confirm_open(sf, mode)
        if sf.exclusive? && sf.num_clients != 0
          raise StyxException.new("can't open locked file")
        end
        openmode = mode & 0x03
        case openmode
        when OREAD
          unless permission?(sf, READ)
            raise StyxException.new("read permission denied")
          end
        when OWRITE
          unless permission?(sf, WRITE)
            raise StyxException.new("write permission denied")
          end
        when ORDWR
          unless permission?(sf, READ)
            raise StyxException.new("read permission denied")
          end
          unless permission?(sf, WRITE)
            raise StyxException.new("write permission denied")
          end
        when OEXEC
          unless permission?(sf, EXECUTE)
            raise StyxException.new("execute permission denied")
          end
        else
          # shouldn't happen
          raise StyxException.new("internal Styx error openmode = #{openmode}: should be between 0 and 3")
        end

        # Execute permission is required for a directory in order to
        # do anything with it
        if sf.directory? && !execute?(sf)
          raise StyxException("directory execute permission denied")
        end

        if (mode & OTRUNC) != 0
          # can't truncate a directory
          if sf.directory?
            raise StyxException.new("cannot truncate a directory")
          end
          unless permission?(sf, WRITE)
            raise StyxException.new("need write permissions to truncate a file")
          end
        end

        if (mode & ORCLOSE) != 0
          # can't delete a directory on closing
          if sf.directory?
            raise StyxException.new("cannot automatically delete a directory")
          end
          # we must have write permissions on the parent directory and the file
          # itself to delete the file on clunking its fid
          unless permission?(sf.parent, WRITE)
            raise StyxException.new("need write permissions on the parent directory to delete the file when the fid is clunked")
          end
          # TODO: do we need write permissions on the file itself?
        end
      end

    end                         # class Session

    ##
    # Base server class.  This does nothing really useful, instantiate
    # subclasses such as TCPServer instead.
    #
    class Server
      ##
      # Create a new server.  The _config_ hash contains the server
      # configuration.  The configuration options recognized by all
      # Styx server subclasses are:
      #
      # _:root_:: The root directory of the filesystem you want to
      #           serve (typically an SDirectory instance)
      # _:log_:: A Logger object where server-generated log messages
      #          are stored.
      # _:auth_:: An authentication object.  If this is a
      #           Keyring::Authinfo instance, it will use the Inferno
      #           authentication protocol to authenticate clients who
      #           connect, and only allow connections from clients with
      #           certificates signed by the same CA that signed its
      #           own certificate.  If this is nil, no authentication
      #           will be required for connections.
      # _:groups_:: A hash table, indexed by user names, that returns
      #             an array of groups of which a particular user is
      #             member of.  If not specified, it defaults to an
      #             empty group table (which sets the group of everyone
      #             to 'nogroup')
      # _:debug_:: Debug level, which is assigned to the logger's level
      #            Set this to Logger::DEBUG if you want full debugging
      #            messages to appear.
      #
      def initialize(config)
        @root = config[:root]
        @auth = config[:auth]
        @groups = config[:groups]
        @groups ||= Hash.new(["nogroup"])
        @log = config[:log] || Logger.new(STDERR)
        @log.level = config[:debug] || Logger::WARN
      end

      protected

      ##
      # Start a new server.  This is overriden by subclasses.
      #
      def start_server
      end

      public

      ##
      # Start the Styx server, returning the thread of the
      # running Styx server instance.
      #
      def run
        t = Thread.new do
          @log.info("starting")
          start_server
        end
        return(t)
      end

    end                         # class Server

    class TCPServer < Server
      ##
      # Create a new TCP-based server.  In addition to the options described
      # in the Server superclass, the following further options are also
      # available:
      #
      # _:bindaddr_:: The address that the Styx server should listen on
      # _:port_:: The port that the Styx server should listen on
      #
      def initialize(config)
        @bindaddr = config[:bindaddr]
        @port = config[:port]
        super(config)
      end

      protected
 
      ##
      # Start a TCP-based server using EventMachine.
      #
      def start_server
        EventMachine::run do
          @log.info("TCP server on #{@bindaddr}:#{@port}")
          EventMachine::start_server(@bindaddr, @port,
                                     StyxServerProtocol) do |conn|
            conn.root = @root
            conn.log = @log
            if @auth.is_a?(Keyring::Authinfo)
              # Perform Inferno authentication protocol
              conn.myauth = @auth
              conn.authenticator = Keyring::FileWrapper.new(conn)
              Thread.new do
                begin
                  conn.userauth, conn.secret = Keyring.auth(conn.authenticator,
                                                            :server, @auth,
                                                            ["none"])
                rescue Exception => e
                  # You fail. Get outta my face!
                  @log.info("client authentication error #{e.class.to_s}: #{e.message}")
                  conn.close_connection
                else
                  # Successful authentication.  Set the session.auth flag to
                  # true and the user to the owner of the public key that
                  # was used to authenticate
                  conn.session.user = conn.userauth.mypk.owner
                  conn.session.auth = true
                  @log.info("authenticated connection for #{conn.session.user}")
                  # Stop using the authenticator after the protocol is done.
                  # The authenticator might have received some data meant
                  # to be Styx protocol messages so we do receive_data to
                  # make sure that the data does get received.
                  a = conn.authenticator
                  conn.authenticator = nil
                  if a.data.length > 0
                    conn.receive_data(a.data)
                  end
                end
              end
            else
              # Either we're using some other non-Inferno authentication
              # method, in which case auth files are used and the peer
              # authentication information is filled in later, or we're
              # not bothering to do any authentication.  We fill in
              # userauth with nil (the connection is unauthenticated)
              # and we put "nobody" in the username (the anonymous user).
              conn.userauth = nil
              conn.session.user = "nobody"
              conn.session.auth = false
              conn.authenticator = nil
              @log.info("unauthenticated connection for #{conn.peername}")
            end
            conn.session.groups = @groups
          end
        end
      end
    end


    ##
    # Server's representation of the client of an SFile, created when
    # a client opens a file.
    #
    class SFileClient
      ##
      # The session for which this SFileClient was created
      attr_reader :session
      ##
      # The fid which the client used to open the file in question
      attr_reader :fid
      ##
      # The mode under which the client opened the file in question
      attr_reader :mode
      ##
      # When a client reads from or writes to file, this records the
      # new offset
      attr_accessor :offset
      ##
      # Used when reading a directory: stores the index of the next
      # child of an SFile to include in an RreadMessage.
      attr_accessor :next_file_to_read
 
      ##
      # Create a new SFileClient.
      #
      # _session_:: The session object associated with the client.
      # _fid_:: The client's handle to the file.  Note that clients may
      #       use many fids opened representing the same file.
      # _mode_:: The mode field as received from the client's Topen
      #       message (including the OTRUNC and ORCLOSE bits)
      #
      def initialize(session, fid, mode)
        @session = session
        @fid = fid
        @truncate = ((mode & OTRUNC) == OTRUNC)
        @orclose = ((mode & ORCLOSE) == ORCLOSE)
        @mode = mode & 0x03     # mask off all but the last two bits
        @offset = 0
        @next_file_to_read = 0
      end

      ##
      # Returns true if the Styx file was opened by the client in the
      # OTRUNC mode.
      #
      def truncate?
        return(@truncate)
      end

      ##
      # Returns true if the Styx file was opened by the client in the
      # ORCLOSE mode (i.e. the client wants the file deleted on clunk).
      #
      def orclose?
        return(@orclose)
      end

      alias delete_on_clunk? orclose?

      ##
      # Check to see if the client can read the file (i.e. the client
      # opened it with read access mode).
      #
      def readable?
        return(@mode == OREAD || @mode == ORDWR)
      end

      ##
      # Check to see if the client can write to the file (i.e. the client
      # opened it with write access).
      #
      def writable?
        return(@mode == OWRITE || @mode == ORDWR)
      end

    end

    ##
    # Class representing a file (or directory) on a Styx server.  There
    # may be different types of file: a file might map directly to a file
    # on disk, or it may be a synthetic file representing a program
    # interface.  This class creates a Styx file which does nothing useful:
    # returning errors when reading from or writing to it.  Subclasses
    # should override the SFile#read, SFile#write and SFile#length methods
    # to implement the desired behavior.  Each Styx file has exactly one
    # parent, the directory which contains it, thus symbolic links on the
    # underlying operating system cannot be represented.
    #
    class SFile < Monitor
      ##
      # File name; must be / if the file is the root directory of the server
      #
      attr_reader :name
      ##
      # Owner name
      attr_reader :uid
      ##
      # Group name
      #
      attr_reader :gid
      ##
      # Name of the user who last modified the file
      #
      attr_reader :muid
      ##
      # Last modification time
      attr_reader :mtime
      ##
      # Permissions and flags
      attr_accessor :permissions
      ##
      # Last access time
      attr_accessor :atime
      ##
      # Parent directory which contains this file
      #
      attr_accessor :parent
      ##
      # Version number for the given path
      attr_accessor :version

      ##
      # Create a new file object with name _name_. This accepts a hash
      # _argv_ for the file's other parameters with the following keys:
      #
      # _:permissions_:: The permissions of the file (e.g. 0755 in octal).
      #                  the default is 0666.
      # _:apponly_:: true if the file is append only.  Default is false.
      # _:excl_:: true if the file is for exclusive use, i.e. only one
      #        client at a time may open.  Default is false.
      # _:user_:: the username of the owner of the file.  If not specified
      #        gets the value from the environment variable USER.
      # _:group_:: the group name of the owner of the file.  If not specified
      #         gets the value from the environment variable GROUP.
      #
      #
      def initialize(name, argv={ :permissions => 0666, :apponly => false,
                       :excl => false, :uid => ENV["USER"],
                       :gid => ENV["GROUP"] })
        super()
        if name == "" || name == "." || name == ".."
          raise StyxException.new("Illegal file name")
        end
        # The parent directory of the file.
        @parent = nil
        # The name of the file.
        @name = name
        # True if this is a directory
        @directory = false
        # True if this is an append-only file
        @appendonly = argv[:apponly]
        # True if this file may be opened by only one client at a time
        @exclusive = argv[:excl]
        # True if this is a file to be used by the authentication mechanism (normally false)
        @auth = false
        # Permissions represented as a number, e.g. 0755 in octal
        @permissions = argv[:permissions]
        # Version number of the file, incremented whenever the file is
        # modified
        @version = 0
        # Time of creation
        @ctime = Time.now
        # Last access time
        @atime = Time.now
        # Last modification time
        @mtime = Time.now
        # Owner name
        @uid = argv[:user]
        # Group name
        @gid = argv[:group]
        # User who last modified the file
        @muid = ""
        # The clients who have a connection to the file
        @clients = []
        @clients.extend(MonitorMixin)
        # Change listeners
        @changelisteners = []
      end

      ##
      # Check if the name may be changed.  Raises a StyxException
      # if this is not possible.
      #
      def can_setname?(name)
      end

      ##
      # Check if the File is a directory (should always be the same as
      # Object#instance_of?(Directory).
      #
      def directory?
        return(@directory)
      end

      ##
      # Check if the file is append-only
      #
      def appendonly?
        return(@appendonly)
      end

      ##
      # Check if the file is marked as exclusive use
      #
      def exclusive?
        return(@exclusive)
      end

      ##
      # Check if the file is an authenticator
      #
      def auth?
        return(@auth)
      end

      ##
      # Get the full path relative to the root of the filesystem.
      #
      def full_path
        if auth? || @parent.nil?
          return(@name)
        end
        return(@parent.full_path + @name)
      end

      ##
      # Get the length of the file.  This default implementation returns
      # zero: subclasses must override this method.
      #
      def length
        return(0)
      end

      ##
      # Gets the type of the file as a number representing the OR of DMDIR,
      # DMAPPEND, DMEXCL, and DMAUTH as appropriate, used to create the Qid.
      #
      def filetype
        type = 0
        if @directory
          type |= DMDIR
        end

        if @appendonly
          type |= DMAPPEND
        end

        if @exclusive
          type |= DMEXCL
        end

        if @auth
          type |= DMAUTH
        end

        return(type)
      end

      ##
      # Gets the mode of the file (permissions and flags)
      #
      def mode
        return(self.filetype | @permissions)
      end

      ##
      # Checks to see if this file allows the mode (permissions and flags)
      # of the file to be changed.  This is called when the server receives
      # a Twstat message.  This default implementation does nothing.
      #
      # _newmode_: the new mode of the file (permissions plus any other flags
      #            such as DMDIR, etc.)
      #
      def can_setmode?(newmode)
      end

      ##
      # Sets the mode of the file (permissions plus other flags).  Must check
      # all the relevant permissions and call SFile#can_setmode? before
      # calling this method, as the assumption is that this method will
      # always succeed.
      def mode=(newmode)
        @appendonly = (newmode & DMAPPEND == DMAPPEND)
        @exclusive = (newmode & DMEXCL == DMEXCL)
        @auth = (newmode & DMAUTH == DMAUTH)
        @permissions = newmode & 0x03fff
        return(newmode)
      end

      ##
      # Returns the Qid of this file.
      #
      def qid
        t = filetype() >> 24 & 0xff
        q = Message::Qid.new(t, @version, self.uuid)
        return(q)
      end

      ##
      # Returns a Stat object for this file.
      #
      def stat
        s = Message::Stat.new
        s.dtype = s.dev = 0
        s.qid = self.qid
        s.mode = self.mode
        s.atime = @atime.to_i
        s.mtime = @mtime.to_i
        s.length = self.length
        s.name = @name
        s.uid = @uid
        s.gid = @gid
        s.muid = @muid
        return(s)
      end

      ##
      # Check to see if the length of this file can be changed to the
      # given value.  If this does not throw an exception then
      # SFile#length= should always succeed.  The default implementation
      # always throws an exception; subclasses should override this method
      # if they want the length of the file to be changeable.
      #
      def can_setlength?(newlength)
        raise StyxException.new("Cannot change the length of this file directly")
      end

      ##
      # Sets the length of the file.  The usual disclaimers about permissions
      # and SFile#can_setlength? apply.  Default implementation does nothing
      # and it should be overriden by subclasses.
      #
      def length=(newlength)
      end

      ##
      # Check to see if the modification time of this file can be changed
      # to the given value.  If this does not throw an exception then
      # set_mtime should always succeed.
      def can_setmtime?(nmtime)
        return(true)
      end

      ##
      # Sets the mtime of the file.  The usual disclaimers about permissions
      # and SFile#can_setmtime? apply.  Default implementation will simply
      # set the modification time to _nmtime_ and the muid to _uid_.
      #
      def set_mtime(nmtime, uid)
        @mtime = nmtime
        @muid = uid
      end

      ##
      # Rename the file to _newname_.  This will raise a StyxException if
      #
      # 1. An attempt is made to rename a file representing the root
      #    directory.
      # 2. An attempt is made to rename a file to a name of some other
      #    file already present in the same directory.
      #
      def rename(newname)
        if @parent == nil
          raise StyxException.new("Cannot change the name of the root directory")
        end
        if @parent.has_child?(newname)
          raise StyxException.new("A file with name #{newname} already exists in this directory")
        end
        @name = newname
      end

      ##
      # Gets the unique numeric ID for the path of this file (generated from
      # the low-order bytes of the creation time and the hashcode of the full
      # path).  If the file is deleted and re-created the unique ID will
      # change (except for the extremely unlikely case in which the low-order
      # bytes of the creation time happen to be the same in the new file and
      # the old file).
      def uuid
        tbytes = @ctime.to_i & 0xffffffff
        return((self.full_path.hash << 32) | tbytes)
      end

      ##
      # Reads data from this file.  This method should be overridden by
      # subclasses and should return an Rread with the data read.  This
      # default implementation simply throws a StyxException, which
      # results in an Rerror being returned to the client.  Subclasses
      # should override this to provide the desired behavior when the
      # file is read.
      #
      # _client_:: the SFileClient object representing the client reading
      #            from this file.
      # _offset_:: the offset the client wants to read from
      # _count_:: the number of bytes that the client wishes to read
      #
      def read(client, offset, count)
        raise StyxException.new("Cannot read from this file")
      end


      ##
      # Writes data to this file.  This method should be overriden by
      # subclasses to provide the desired behavior when the file is
      # written to.  It should return the number of bytes actually
      # written.
      #
      # _client_:: the SFileClient object representing the client writing
      #            to this file
      # _offset_:: the offset the client wants to write to
      # _data_:: the data that the client wishes to write
      # _truncate_:: true or false depending on whether the file is to be
      #              truncated.
      #
      def write(client, offset, data, truncate)
        raise StyxException.new("Cannot write to this file")
      end

      ##
      # Remove the file from the Styx server.  This will simply remove
      # the file from the parent directory.
      #
      def remove
        self.delete
        self.parent.remove_child(self)
      end

      ##
      # Any pre-deletion actions must be performed in this method.
      #
      def delete
      end

      ##
      # Add a client to the list of clients reading this file.
      #
      # _cl_:: an SFileClient instance representing the client reading
      #        the file
      def add_client(cl)
        @clients.synchronize { @clients << cl }
        self.client_connected(cl)
      end

      def client_connected(cl)
      end

      ##
      # Get the client connection to this file
      #
      # _sess_:: the client session in question
      # _fid_:: the fid that the client is using to access the file.
      # returns:: the SFileClient instance representing that file access,
      #           or nil if there is no such client connection.
      #
      def client(sess, fid)
        @clients.synchronize do
          @clients.each do |cl|
            if cl.session == sess && cl.fid == fid
              return(cl)
            end
          end
        end
        return(nil)
      end

      ##
      # Return the number of clients accessing this file.
      #
      def num_clients
        @clients.synchronize do
          remove_dead_clients
          return(@clients.length)
        end
      end
  
      ##
      # Remove clients which are no longer really using the file.
      # If a client session is either gone or the session is no longer
      # connected, it removes the client from the list.
      def remove_dead_clients
        @clients.synchronize do
          @clients.each do |clnt|
            if clnt.session.nil? || !clnt.session.connected?
              remove_client(clnt)
            end
          end
        end
      end

      ##
      # Remove the client _cl_ from the list of clients accessing the file.
      # 
      def remove_client(cl)
        unless cl.nil?
          @clients.delete(cl)
          client_disconnected(cl)
        end
      end

      ##
      # Add any custom behavior for the file that has to happen whenever
      # a client disconnects from the file here.
      #
      def client_disconnected(cl)
      end

      ##
      # Add a change listener to the list of change listeners of this
      # file.  The change listener will execute whenever some modification
      # is made to the file, and is passed the SFile instance to which it
      # is attached as a parameter.
      #
      # _block_:: the change listener block
      #
      def add_changelistener(&block)
        @changelisteners << block
      end

      ##
      # Method executed whenever the contents of the file change.  This
      # increments the file's version on the server, and executes any
      # change listeners active on the file.
      #
      def contents_changed
        version_incr
        @changelisteners.each do |listener|
          listener.call(self)
        end
      end

      ##
      # Increment the file's version.  This wraps after the version goes
      # above 2^64.
      #
      def version_incr
        @version = ((@version + 1) & 0xffffffffffffffff)
      end

      ##
      # Return a Message::Rwrite for a successful write of _count_ bytes
      # from _session_.  A write method for a subclass should use this
      # method (which updates mtime, atime, and calls contents_changed
      # callbacks) instead of manually returning a Message::Rwrite
      #
      def reply_write(count, session)
        @atime = Time.now
        self.set_mtime(@atime, session.user)
        self.contents_changed
        return(Message::Rwrite.new(:count => count))
      end

      ##
      # Return a Message::Rread for a successful read of _data_.  This
      # updates access time and should be used instead of manually
      # returning a Message::Rread.
      #
      def reply_read(data)
        @atime = Time.now
        return(Message::Rread.new(:data => data))
      end

      ##
      # Refreshes this file (if it represents another entity, such as a
      # file on disk, this method is used to make sure that the file
      # metadata (length, access time, etc.) are up to date. This default
      # implementation does nothing; subclasses must override this to
      # provide the correct functionality.
      #
      def refresh(update_children=false)
      end
    end                         # class SFile

    ##
    # Class representing a directory on the Styx server.
    #
    class SDirectory < SFile
      ##
      # Create a new directory with name _name_.  Permissions are obtained
      # from the _argv_ hash as with SFile.  The default permissions are
      # 0777 though.  In addition to the usual file arguments in _argv_,
      # SDirectory instances also recognize a _:filemaker_ key which
      # specifies a block that may be called whenever a file is created.
      # The block receives as parameters the SDirectory instance, the
      # name of the file to create, and the permissions of the file.  It
      # should return an SFile subclass instance, which becomes the new
      # file on success, or raise a StyxException if there is some problem.
      #
      def initialize(name, argv={ :permissions => 0777, :uid => ENV["USER"],
                       :gid => ENV["GROUP"], :filemaker => nil })
        # directories cannot be append-only, exclusive, or auth files
        argv.merge({:apponly => false, :excl => false})
        super(name, argv)
        @directory = true
        @children = []
        @children.extend(MonitorMixin)
        @filemaker = argv[:filemaker]
      end

      def child_exists?(name)
        @children.synchronize do
          @children.each do |c|
            if c.name == name
              return(true)
            end
          end
          return(false)
        end
      end

      ##
      # Add an SFile _child_ to this directory. If a file with the
      # same name already exists, throws a FileExists exception.
      #
      def <<(child)
        @children.synchronize do
          if child_exists?(child.name)
            raise FileExists("#{sf.name} already exists")
          end
          child.parent = self
          @children << child
        end
        return(child)
      end

      ##
      # Get the child with the name _name_, or nil if no such file is
      # present in this directory.
      #
      def [](name)
        if name == "."
          return(self)
        end
        if name == ".."
          return(self.parent)
        end
        @children.synchronize do
          @children.each do |c|
            if c.name == name
              return(c)
            end
          end
          return(nil)
        end
      end

      ##
      # Get the number of children this directory has
      #
      def child_count
        return(@children.length)
      end

      ##
      # Read the contents of the directory.
      #
      # _client_:: the SFileClient object representing the client reading
      #            from this directory.
      # _offset_:: the offset the client wants to read from.  Nonzero
      #            offsets are only valid if the client has read from
      #            the directory before, and may only be the values
      #            obtained from a previous read.
      # _count_:: the number of bytes that the client wishes to read.
      #           The read will always return the nearest integral
      #           number of directory entries whose length is less than
      #           the count (i.e. if five entries take 300 bytes and
      #           the sixth entry takes 40 bytes, and _count_ was
      #           set to 320, only five entries and 300 bytes will be
      #           returned).
      #
      def read(client, offset, count)
        # Check that the offset is valid; zero offsets are always valid,
        # but non-zero offsets are only valid if this client has read part
        # of the contents of the directory before.
        if (offset != 0 && offset != client.offset)
          raise StyxException.new("invalid offset when reading directory")
        end

        # Create a string to store the serialized stat representations
        # of the directory's contents.
        str = ""
        nextfile = (offset == 0) ? 0 : client.next_file_to_read
        while (nextfile < @children.length)
          sf = @children[nextfile]
          s = sf.stat.to_bytes
          if (s.length + str.length) > count
            break
          end
          # Add the serialized stat to the buffer
          str << s
          nextfile += 1
        end
        client.next_file_to_read = nextfile
        client.offset += str.length
        return(reply_read(str))
      end

      ##
      # Create a new file with name _name_ and permissions _perm_ in this
      # directory.
      #--
      # FIXME: make this method actually DO something!
      #++
      #
      def newfile(name, perm, isdir, isapponly, isexcl)
        raise StyxException.new("cannot create files in this directory")
      end

      ##
      # Remove a file from the directory
      def remove_child(child)
        @children.delete(child)
        self.contents_changed
      end

    end                         # class SDirectory

    ##
    # An SFile whose underlying data are stored as a String in memory.
    # This string may grow to arbitrary size.
    #
    class InMemoryFile < SFile
      ##
      # The contents of the file, as a string.
      #
      attr_accessor :contents

      def initialize(name, argv={ :permissions => 0666, :apponly => false,
                       :excl => false, :uid => ENV["USER"],
                       :gid => ENV["GROUP"] })
        super(name, argv)
        @contentslock = Mutex.new
      end

      ##
      # Read data from the file.
      #
      # _client_:: the SFileClient object representing the client reading
      #            from this file.
      # _offset_:: the offset the client wants to read from
      # _count_:: the number of bytes that the client wishes to read
      #
      def read(client, offset, count)
        data = @contents[offset..(offset+count)]
        data ||= ""
        return(reply_read(data))
      end

      ##
      # Writes data to this file.  Raises a StyxException if the
      # offset is past the end of the file.
      #
      # _client_:: the SFileClient object representing the client writing
      #            to this file
      # _offset_:: the offset the client wants to write to
      # _data_:: the data that the client wishes to write
      # _truncate_:: true or false depending on whether the file is to be
      #              truncated.
      #
      def write(client, offset, data, truncate)
        @contentslock.synchronize do
          # First write to the file
          if @contents.nil?
            @contents = ""
          end

          if offset > @contents.length
            raise StyxException.new("attempt to write past the end of the file")          end

          @contents[offset..(offset + data.length)] = data
          if (truncate)
            @contents = @contents[0..(offset+data.length)] = data
          end
          return(reply_write(data.length, client.session))
        end
      end

    end

    class FileOnDisk < SFile
      ##
      # Create a new FileOnDisk whose path on the local filesystem is _path_,
      # whose name as it appears on the server's namespace is _name_, whose
      # base permissions (which are ANDed with the file's real permissions
      # mask on the underlying filesystem) are _perm_.  The file must
      # already exist on the local filesystem.  If _name_ is not specified,
      # it defaults to the basename of _path_.  If _perm_ is not specified,
      # it defaults to 0666.  If the path specified is actually a directory,
      # returns a DirectoryOnDisk instance instead.
      #
      #--
      # FIXME: should create a DirectoryOnDisk instance instead if _path_
      # actually represents a directory.
      #++
      #
      def self.new(path, name=nil, perm=nil)
        unless File.exists?(path)
          raise StyxException.new("file #{path} does not exist on local filesystem")
        end

        if name.nil?
          name = File.basename(path)
        end

        if File.directory?(path)
          perm ||= 0777
          return(DirectoryOnDisk.new(path, name, perm))
        end

        perm ||= 0666
        obj = allocate
        obj.send(:initialize, path, name, perm)
        return(obj)
      end

      ##
      # Hidden initialize method.
      # See self.new for the real thing.
      #
      def initialize(path, name, perm)
        @name = name
        @path = File.expand_path(path)

        s = File.stat(@path)
        pwent = Etc.getpwuid(s.uid)
        grent = Etc.getgrgid(s.gid)
        argv = { :permissions => perm & s.mode, :apponly => false,
          :excl => false, :uid => pwent.name, :gid => grent.name }
        super(@name, argv)
      end

      ##
      # Read data from the file.
      #
      # _client_:: the SFileClient object representing the client reading
      #            from this file.
      # _offset_:: the offset the client wants to read from
      # _count_:: the number of bytes that the client wishes to read
      #
      def read(client, offset, count)
        begin
          File.open(@path, "r") do |fp|
            fp.seek(offset)
            data = fp.read(count)
            if data.nil?
              data = ""
            end
            return(reply_read(data))
          end
        rescue Exception => e
          raise StyxException.new("An error of class #{e.class} occurred when trying to read from #{@path}: #{e.message}")
        end

      end

      ##
      # Writes data to the file.
      #
      # _client_:: the SFileClient object representing the client writing
      #            to this file
      # _offset_:: the offset the client wants to write to
      # _data_:: the data that the client wishes to write
      # _truncate_:: true or false depending on whether the file is to be
      #              truncated.
      #
      def write(client, offset, data, truncate)
        unless File.exists?(@path)
          # The underlying file was removed out from under us!
          self.remove
          raise StyxException.new("The file #{@path} was removed")
        end

        begin
          File.open(@path, "r+") do |fp|
            fp.seek(offset)
            count = fp.write(data)
            if truncate
              fp.truncate(offset + data.length)
            end
            reply_write(count, client.session)
          end
        rescue Exception => e
          raise StyxException.new("An error of class #{e.class} occurred when trying to write to #{@path}: #{e.message}")
        end
      end

      ##
      # Refreshes the file's stat information based on a real stat call
      def refresh(update_children=false)
        s = File.stat(@path)
        @mtime = s.mtime
        @atime = s.atime
      end

      ##
      # Deletes the underlying file from the disk.
      #
      def delete
        if File.exists?(@path)
          File.delete(@path)
        end
      end

    end

    ##
    # Class representing a directory on the host filesystem.  While there's
    # no real problem with using this class directly, it's probably better
    # to use FileOnDisk instead (it will return a DirectoryOnDisk instance
    # when passed a directory.
    #
    class DirectoryOnDisk < SDirectory
      ##
      # Create a new DirectoryOnDisk instance.  This
      def initialize(path, name, perm)
        @name = name
        @path = File.expand_path(path)

        s = File.stat(@path)
        pwent = Etc.getpwuid(s.uid)
        grent = Etc.getgrgid(s.gid)
        argv = { :permissions => perm & s.mode, :apponly => false,
          :excl => false, :uid => pwent.name, :gid => grent.name }
        super(@name, argv)
        self.refresh(false)
      end

      ##
      # Read all metadata from the underlying directory.  If _update_children_
      # is true, all immediate children of this directory will be refreshed
      # as well.
      #--
      # TODO: check for files deleted in the host filesystem
      #++
      #
      def refresh(update_children=true)
        s = File.stat(@path)
        @mtime = s.mtime
        @atime = s.atime
        unless update_children
          return
        end
        Dir.foreach(@path) do |file|
          # do not treat . or .. as valid files
          if file == '.' || file == '..'
            next
          end
          # Check if a file with this name is already known
          sf = self[file]
          if sf.nil?
            begin
              filepath = @path + File::SEPARATOR + file
              sf = FileOnDisk.new(filepath)
              if sf.is_a?(SDirectory)
                sf.permissions = @permissions
              else
                # This is an SFile (a FileOnDisk).  Set to the same permissions
                # as the host directory without the execute flags.
                sf.permissions = @permissions & 0666
              end
              self << sf
            rescue Exception => e
              # This should be impossible
            end
          else
            # The file is already known to us.  Refresh the file metadata
            # but do not descend into subdirectories (could lead to deep
            # recursion).
            if (sf.is_a?(SDirectory))
              sf.refresh(false)
            else
              sf.refresh
            end
          end
        end
      end
    end

  end                           # module Server

end                             # module RStyx
