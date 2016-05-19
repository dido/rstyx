#!/usr/bin/ruby
#
# Author:: Rafael R. Sevilla (mailto:dido@imperium.ph)
# Copyright:: Copyright (c) 2005-2007 Rafael R. Sevilla
# Homepage:: http://rstyx.rubyforge.org/
# License:: GNU Lesser General Public License / Ruby License
#
# $Id: messages.rb 283 2007-09-19 07:28:28Z dido $
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
# Styx Message classes and utility functions
#

require 'rstyx/errors'

module RStyx

  module Message
    ##
    # Class representing the server's view of a file.
    #
    class Qid
      ##
      # The type of the file (directory, etc.) represented as a bit vector
      # corresponding to the high 8 bits of the file's mode word.
      attr_accessor :qtype
      ##
      # Version number for given path
      attr_accessor :version
      ##
      # The file server's unique identification for the file
      attr_accessor :path

      QID_LENGTH = 13           # size of a Qid

      ##
      # Create a new Qid object.
      #
      # _type_:: [Fixnum] the type of file (directory, append only file, etc.)
      # _version_:: [Fixnum] the version number of the file
      # _path_:: [Fixnum] a 64-bit integer that should be unique among all
      #          files being served
      #
      def initialize(type, version, path)
        @qtype = type
        @version = version
        @path = path
      end

      ##
      # Test if two qid's are the same.
      #
      def ==(x)
        return(self.to_bytes == x.to_bytes)
      end

      ##
      # Get the byte string representation of the Qid
      #
      # return value:: [String] the byte string representation of the Qid
      #
      def to_bytes
        pathlo = @path & 0xffffffff
        pathhi = (@path >> 32) & 0xffffffff
        return([@qtype, @version, pathlo, pathhi].pack("CVVV"))
      end

      ##
      # Decode a serialized Qid from its byte string representation
      #
      # _msgbytes_:: [String] the byte string representation of the qid
      # return value:: [Qid] the Qid represented by the byte string.
      # raises:: StyxException if the string cannot be decoded as a Qid
      #
      def self.from_bytes(msgbytes)
        qtype, version, pathlo, pathhi = msgbytes.unpack("CVVV")
        if qtype.nil? || version.nil? || pathlo.nil? || pathhi.nil?
          raise StyxException.new("QID failed decode")
        end
        # recombine in little-endian mode
        path = pathlo | (pathhi << 32)
        return(Qid.new(qtype, version, path))
      end

      ##
      # Dump a Qid
      #
      # return value:: [String] a textual representation of the Qid
      #
      def to_s
        val = sprintf("(Qid 0x%02x %d 0x%02x)", @qtype, @version, @path)
        return(val)
      end
    end

    ##
    # Class representing an entry in a directory (e.g. the result of a
    # stat message).  See Inferno man page stat(5) for more details.
    #
    class Stat
      ##
      # Total byte count of the following data
      attr_accessor :size
      ##
      # For kernel use
      attr_accessor :dtype
      ##
      # For kernel use
      attr_accessor :dev
      ##
      # The Qid of the file represented by the stat object
      attr_accessor :qid
      ##
      # Permissions and flags
      attr_accessor :mode
      ##
      # Last access time
      attr_accessor :atime
      ##
      # Last modification time
      attr_accessor :mtime
      ##
      # Length of the file in bytes
      attr_accessor :length
      ##
      # File name; must be / if the file is the root directory of the server
      attr_accessor :name
      ##
      # Owner name
      #
      attr_accessor :uid
      ##
      # Group name
      attr_accessor :gid
      ##
      # Name of the user who last modified the file
      attr_accessor :muid

      ##
      # Internal function for extrating strings
      def self.strextract(str, offset) # :nodoc:
        length = (str[offset..(offset + 1)].unpack("v"))[0]
        if length.nil?
          raise StyxException.new("invalid string, no length found")
        end

        offset += 2
        nstr = (str[offset..(offset + length - 1)])
        if (nstr.length != length)
          raise StyxException.new("invalid string")
        end
        return([nstr, offset + length])
      end

      ##
      # Serialize a Stat.  This also calculates the size of the
      # Stat in bytes.
      #
      # return value:: [String] the serialized version of the Stat
      #
      def to_bytes
        str = [@dtype, @dev].pack("vV")
        str << @qid.to_bytes
        lengthlo = @length & 0xffffffff
        lengthhi = (@length >> 32) & 0xffffffff
        str << [@mode, @atime, @mtime, lengthlo, lengthhi].pack("VVVVV")
        str << [@name.length, @name].pack("va*")
        @uid ||= ""
        @gid ||= ""
        @muid ||= ""
        str << [@uid.length, @uid].pack("va*")
        str << [@gid.length, @gid].pack("va*")
        str << [@muid.length, @muid].pack("va*")
        @size = str.length
        return([@size].pack("v") + str)
      end

      ##
      # Unserialize a Stat
      #
      # _bytes_:: [String] serialized string representation of a Stat
      # return value:: [Stat] the Stat corresponding to the
      #                passed string
      # raises:: StyxException if _bytes_ cannot be properly decoded as
      #          a Stat
      #
      def self.from_bytes(bytes)
        # From Inferno stat(5)
        #
        # 0-1 = size
        # 2-3 = type
        # 4-7 = dev
        # 8 = Qid.type
        # 9-12 = Qid.vers
        # 13-20 = Qid.path
        # 21-24 = mode
        # 25-28 = atime
        # 29-32 = mtime
        # 33-40 = length
        # 41-42 = name length
        # 43 to 42 + namelen = name
        # 43 + namelen to 44 + namelen = uid length
        # 45 + namelen to 44 + namelen + uidlen = uid
        # 45 + namelen + uidlen
        de = Stat.new
        de.size, de.dtype, de.dev = (bytes[0..7]).unpack("vvV")
        if de.size.nil? || de.dtype.nil? || de.dev.nil?
          raise RStyx::StyxException.new("failed to decode Stat")
        end
        de.qid = Qid.from_bytes(bytes[8..20])
        de.mode, de.atime, de.mtime, lengthlo, lengthhi =
          (bytes[21..40]).unpack("VVVVV")

        if de.mode.nil? || de.atime.nil? || de.mtime.nil? || 
            lengthlo.nil? || lengthhi.nil?
          raise RStyx::StyxException.new("failed to decode Stat")
        end
        # combine in little-endian
        de.length = lengthlo | (lengthhi << 32)
        de.name, offset = self.strextract(bytes, 41)
        de.uid, offset = self.strextract(bytes, offset)
        de.gid, offset = self.strextract(bytes, offset)
        de.muid, offset = self.strextract(bytes, offset)
        return(de)
      end

      ##
      # convert a Stat to a human-readable string
      #
      # return value:: a string representation of the Stat
      #
      def to_s
        s = sprintf("(Stat %d 0x%02x, 0x%04x ", @size, @dtype, @dev)
        s << sprintf("%s, 0x%04x 0x%04x 0x%04x ",
                     @qid.to_s, @mode, @atime, @mtime)
        s << sprintf("%d %s %s ", @length, @name, @uid)
        s << sprintf("%s %s)", @gid, @muid)
        return(s)
      end
    end

    ##
    # Base class of a Styx message.
    #
    class StyxMessage
      ##
      # A hash indexed by the field names giving the field values.
      #
      attr_accessor :fieldvals
      ##
      # A Hash indexed by the class of the message and its identifier
      # number.
      #
      MESSAGE_IDS = {}

      ##
      # Add a field to the StyxMessage.  Used by subclasses to define
      # the message field.  The _name_ should be a Symbol that gives
      # the name of the field (preferably the canonical name given in the
      # Inferno manual page intro(5)), and the _type_ may be:
      #
      # 1. Any valid format string used by String#unpack or Array#pack.
      # 2. Cstr, which is a UTF-8 string, which will be serialized as
      #    a two-byte unsigned length (in bytes) followed by the string's
      #    data itself, and deserialized from this representation into
      #    a standard Ruby string.
      # 3. CstrList, which deserializes into an array of Ruby strings,
      #    and is serialized into a two-byte unsigned count of strings
      #    followed by each of the strings itself, as in Cstr.
      # 3. Bstr, which is a binary string.  It will be serialized to a
      #    four-byte unsigned length (in bytes) followed by the string's
      #    data itself, and deserialized from this representation into
      #    a standard Ruby string.
      # 4. Qid, which deserializes into a Qid object instance and is
      #    serialized into a 13-byte binary representation.
      # 5. QidList, which deserializes into an array of Qid objects and is
      #    serialized into a two-byte unsigned count of Qid objects followed
      #    by the serialized representations of each of the Qid objects.
      # 6. ULongLong, which deserializes into a Ruby Fixnum and is
      #    serialized into a 64-bit little-endian value.
      # 7. Stat, which deserializes into a Stat object instance and is
      #    serialized into the stat format described in the Inferno
      #    man page stat(5).  See the Stat class for more details.
      #
      # This method will cause the (sub)class which uses it to have
      # its inherited copy of StyxMessage#fields to receive the name
      # and type declaration, and it will create attribute reader
      # and writer methods of the form _name_ and _name_= to be added
      # to the class.
      #
      def self.add_field(name, type)
        self.fields << [name, type]

        # Create accessor methods for the field
        define_method(name) do
          instance_variable_get("@fieldvals")[name]
        end

        define_method(name.to_s + "=") do |val|
          fname = instance_variable_get("@fieldvals")
          fname[name] = val
        end
      end

      ##
      # The fields of the Styx message, which consists of an array of
      # arrays consisting of the field name and the field type (see
      # StyxMessage#add_field for more details).
      #
      def self.fields
        # Default fields (excluding the size[4] field)
        @fields ||= [[:ident, 'C'], [:tag, 'v']]
      end

      ##
      # Create a new StyxMessage class.  This takes a hash of field
      # names and values, and this is put into a hash.
      #
      # _fieldvals_:: A hash of field values.  These values need not be
      #               only the values of defined, for the message,
      #               but only the values actually defined may be directly
      #               accessed and will be serialized.
      #   
      def initialize(fieldvals={})
        ident = MESSAGE_IDS[self.class]
        @fieldvals = {:ident=>ident}.merge(fieldvals)
      end

      ##
      # Return the identifier of the message (code).  This cannot
      # be changed.
      #
      def ident
        return(@fieldvals[:ident])
      end

      ##
      # Return the tag of the message.
      #
      def tag
        return(@fieldvals[:tag])
      end

      ##
      # Set the tag of the message.
      #
      def tag=(t)
        return(@fieldvals[:tag] = t)
      end

      ##
      # Deserialize a byte string into a StyxMessage subclass of some
      # kind.
      #
      # _str_:: A byte string representing a Styx message
      # return value:: The StyxMessage subclass instance represented by _str_
      # raises:: StyxException if there was some error decoding _str_
      #
      def self.from_bytes(str)
        origlength = str.length
        # get the length, identifier, and the rest of the string
        len, ident, str = str.unpack("VCa*")
        if len.nil? || len > origlength
          raise StyxException.new("message string too short: #{len} bytes expected, only #{origlength} available")
        end
        c = MESSAGE_IDS.key(ident)
        if c.nil?
          raise StyxException.new("Unknown message type identifier #{ident.inspect}")
        end
        obj = c.new
        c.fields.each do |name,type|
          if name == :ident
            next
          end
          val = nil
          case type
          when "Cstr"
            len, str = str.unpack("va*")
            val, str = str.unpack("a#{len}a*")
          when "CstrList"
            nstr, str = str.unpack("va*")
            val = []
            1.upto(nstr) do
              len, str = str.unpack("va*")
              xstr, str = str.unpack("a#{len}a*")
              val << xstr
            end
          when "Bstr"
            len, str = str.unpack("Va*")
            val, str = str.unpack("a#{len}a*")
          when "Qid"
            qid, str = str.unpack("a#{Qid::QID_LENGTH}a*")
            val = Qid.from_bytes(qid)
          when "QidList"
            nqid, str = str.unpack("va*")
            val = []
            1.upto(nqid) do
              qid,str = str.unpack("a#{Qid::QID_LENGTH}a*")
              val << Qid.from_bytes(qid)
            end
          when "Stat"
            # See the corresponding comments under to_bytes
            # (from when "Stat") for why we do it this way.
            slen1 = str.unpack("v")
            slen1, stat, str = str.unpack("va#{slen1}a*")
            val = Stat.from_bytes(stat)
          when "ULongLong"
            v1, v2, str = str.unpack("VVa*")
            # v1 - low word, v2 = high word
            val = v2 << 32 | v1
          else
            val, str = str.unpack(type + "a*")
          end
          obj.fieldvals[name] = val
        end
        return(obj)
      end

      ##
      # Serialize a Styx message subclass instance into a byte string.
      #
      # returns:: The serialized String representation of the Styx message
      #           subclass instance.
      #
      def to_bytes
        str = ""
        self.class.fields.each do |name,type|
          case type
          when "Cstr"
            str << [@fieldvals[name].length, @fieldvals[name]].pack("va*")
          when "CstrList"
            strlist = @fieldvals[name]
            str << [strlist.length].pack("v")
            strlist.each do |s|
              str << [s.length, s].pack("va*")
            end
          when "Bstr"
            str << [@fieldvals[name].length, @fieldvals[name]].pack("Va*")
          when "Qid"
            str << @fieldvals[name].to_bytes
          when "QidList"
            qlist = @fieldvals[name]
            str << [qlist.length].pack("v")
            qlist.each do |q|
              str << q.to_bytes
            end
          when "ULongLong"
            # low dword
            str << [@fieldvals[name] & 0xffffffff].pack("V")
            # high dword
            str << [(@fieldvals[name] >> 32) & 0xffffffff].pack("V")
          when "Stat"
            # From the Inferno stat(5) man page:
            #
            #   To make the contents of a directory, such as returned
            #   by read(5), easy to  parse, each directory entry
            #   begins with a size field.  For consistency, the entries
            #   in Twstat and Rstat  messages  also contain their
            #   size, which means the size appears twice.
            #
            # And so this is why we prefix the serialized version of
            # the stat message with the size here, and when deserializing
            # we do the same thing.
            #
            statstr = @fieldvals[name].to_bytes
            str << [statstr.length, statstr].pack("va*")
          else
            # format string for Array#pack
            str << [@fieldvals[name]].pack(type)
          end
        end
        # add length
        str = [str.length + 4].pack("V") + str
        return(str)
      end

      ##
      # Convert a Styx message into a human-readable string.
      #
      # returns:: The Styx message instance converted to a string.
      def to_s
        # First, start with the Styx message class name
        str = "(" + self.class.to_s.split("::")[-1]
        self.class.fields.each do |name, type|
          # Ignore ident (redundant, as it is already expressed in
          # the class name)
          if name == :ident
            next
          end
          str << " " + name.inspect + "=>" + @fieldvals[name].to_s.inspect
        end
        str << ")"
      end

    end

    ##
    # Class representing a Tversion message sent by a Styx client.
    # See Inferno's version(5) for more details.
    #
    # === Fields
    #
    # _msize_:: The client-suggested message size, that is the maximum
    #           length in bytes that it will ever generate or expect to
    #           receive in a single Styx message.
    # _version_:: The version string identifying the level of the protocol
    #             supported by the client.
    #
    class Tversion < StyxMessage
      StyxMessage::MESSAGE_IDS[Tversion] = 100
      add_field(:msize, 'V')
      add_field(:version, 'Cstr')
    end

    ##
    # Class representing an Rversion message sent by a Styx server.
    # See Inferno's version(5) for more details.
    #
    # === Fields
    #
    # _msize_:: The server's maximum message size, that is the maximum
    #           length in bytes that it will ever generate or expect to
    #           receive in a single Styx message.
    # _version_:: The version string identifying the level of the protocol
    #             supported by the server.
    #
    class Rversion < StyxMessage
      StyxMessage::MESSAGE_IDS[Rversion] = 101
      add_field(:msize, 'V')
      add_field(:version, 'Cstr')
    end

    ##
    # Class representing a Tauth message sent by a Styx client.
    # See Inferno's attach(5) for more details.
    #
    # === Fields
    #
    # _afid_:: New fid to be established for the authentication protocol
    # _uname_:: The user name to authenticate as
    # _aname_:: The file tree to access
    #
    class Tauth < StyxMessage
      StyxMessage::MESSAGE_IDS[Tauth] = 102
      add_field(:afid, 'V')
      add_field(:uname, 'Cstr')
      add_field(:aname, 'Cstr')
    end

    ##
    # Class representing an Rauth message sent by a Styx server.
    # See Inferno's attach(5) for more details.
    #
    # === Fields
    #
    # _aqid_:: a Qid defining a file of type QTAUTH that may be read and
    #          written as per the authentication protocol.
    #
    class Rauth < StyxMessage
      StyxMessage::MESSAGE_IDS[Rauth] = 103
      add_field(:aqid, 'Qid')
    end

    ##
    # Class representing a Tattach message sent by a Styx client.
    # See Inferno's attach(5) for more details.
    #
    # === Fields
    #
    # _fid_:: The fid to establish as the root of the server.
    # _afid_:: The (optional) afid established by the authentication protocol.
    # _uname_:: The user name authenticated against
    # _aname_:: The file tree to access
    #
    class Tattach < StyxMessage
      StyxMessage::MESSAGE_IDS[Tattach] = 104
      add_field(:fid, 'V')
      add_field(:afid, 'V')
      add_field(:uname, 'Cstr')
      add_field(:aname, 'Cstr')
    end

    ##
    # Class representing an Rattach message sent by a Styx server.
    # See Inferno's attach(5) for more details.
    #
    # === Fields
    #
    # _qid_:: The Qid of the root of the file server on a successful
    #         attach.
    #
    class Rattach < StyxMessage
      StyxMessage::MESSAGE_IDS[Rattach] = 105
      add_field(:qid, 'Qid')
    end

    ##
    # Class representing a Terror message.  This is not actually valid
    # and should never be used.
    #
    class Terror < StyxMessage
      StyxMessage::MESSAGE_IDS[Terror] = 106
      def initialize
        raise StyxException.new("Terror class instantiated")
      end
    end

    ##
    # Class representing an Rerror message sent by a Styx server.
    # See Inferno's error(5) for more details.
    #
    # === Fields
    #
    # _ename_:: The error string describing the failure of the transaction.
    #
    class Rerror < StyxMessage
      StyxMessage::MESSAGE_IDS[Rerror] = 107
      add_field(:ename, "Cstr")
    end

    ##
    # Class representing a Tflush message sent by a Styx client.
    # See Inferno's flush(5) for more details.
    #
    # === Fields
    #
    # _oldtag_:: the tag of the message to flush
    #
    class Tflush < StyxMessage
      StyxMessage::MESSAGE_IDS[Tflush] = 108
      add_field(:oldtag, "v")
    end

    ##
    # Class representing an Rflush message sent by a Styx server.
    # See Inferno's flush(5) for more details.
    #
    class Rflush < StyxMessage
      StyxMessage::MESSAGE_IDS[Rflush] = 109
    end

    ##
    # Class representing a Twalk message sent by a Styx client.
    # See Inferno's walk(5) for more details.
    #
    # === Fields
    #
    # _fid_:: The existing fid to start the walk from
    # _newfid_:: The new fid to assign to the file walked to
    # _wnames_:: A list of path elements to walk to
    #
    class Twalk < StyxMessage
      StyxMessage::MESSAGE_IDS[Twalk] = 110
      add_field(:fid, "V")
      add_field(:newfid, "V")
      add_field(:wnames, "CstrList")

      ##
      # Set the _wnames_ field of the Twalk message by specifying
      # a path name _str_ instead of an array of path elements.
      #
      def path=(str)
        @fieldvals[:wnames] = str.split(File::SEPARATOR)
      end

      ##
      # Return the path name representation of the Twalk message's
      # _wname_s.
      #
      def path
        return(@fieldvals[:wnames].join(File::SEPARATOR))
      end
    end

    ##
    # Class representing an Rwalk message sent by a Styx server.
    # See Inferno's walk(5) for more details.
    #
    # === Fields
    #
    # _qids_:: The qid's corresponding to the path elements walked to
    #          in response to the Twalk
    #
    class Rwalk < StyxMessage
      StyxMessage::MESSAGE_IDS[Rwalk] = 111
      add_field(:qids, "QidList")
    end

    ##
    # Class representing a Topen message sent by a Styx client.
    # See Inferno's open(5) for more details.
    #
    # === Fields
    #
    # _fid_:: The fid of the file to open
    # _mode_:: The open mode
    #
    class Topen < StyxMessage
      StyxMessage::MESSAGE_IDS[Topen] = 112
      add_field(:fid, "V")
      add_field(:mode, "C")
    end

    ##
    # Class representing an Ropen message sent by a Styx server.
    # See Inferno's open(5) for more details.
    #
    # === Fields
    #
    # _qid_:: The Qid representing the file that was opened
    # _iounit_:: The maximum number of bytes guaranteed to be read from and
    #            written to the file without breaking the transfer into
    #            multiple messages.
    #
    class Ropen < StyxMessage
      StyxMessage::MESSAGE_IDS[Ropen] = 113
      add_field(:qid, "Qid")
      add_field(:iounit, "V")
    end

    ##
    # Class representing a Tcreate message sent by a Styx client.
    # See Inferno's open(5) for more details.
    #
    # === Fields
    #
    # _fid_:: The fid of the file to open
    # _name_:: The name of the file to create
    # _perm_:: The permissions bitmask of the file to be created
    # _mode_:: The open mode after file creation
    #
    class Tcreate < StyxMessage
      StyxMessage::MESSAGE_IDS[Tcreate] = 114
      add_field(:fid, "V")
      add_field(:name, "Cstr")
      add_field(:perm, "V")
      add_field(:mode, "C")
    end

    ##
    # Class representing an Rcreate message sent by a Styx server.
    # See Inferno's open(5) for more details.
    #
    # === Fields
    #
    # _qid_:: The Qid representing the file that was created
    # _iounit_:: The maximum number of bytes guaranteed to be read from and
    #            written to the file without breaking the transfer into
    #            multiple messages.
    #
    class Rcreate < StyxMessage
      StyxMessage::MESSAGE_IDS[Rcreate] = 115
      add_field(:qid, "Qid")
      add_field(:iounit, "V")
    end

    ##
    # Class representing a Tread message sent by a Styx client.
    # See Inferno's read(5) for more details.
    #
    # === Fields
    #
    # _fid_:: The fid of the file to read from
    # _offset_:: The offset into the file to read from
    # _count_:: The number of bytes to read from the file
    #
    class Tread < StyxMessage
      StyxMessage::MESSAGE_IDS[Tread] = 116
      add_field(:fid, "V")
      add_field(:offset, "ULongLong")
      add_field(:count, "V")
    end

    ##
    # Class representing an Rread message sent by a Styx server.
    # See Inferno's read(5) for more details.
    #
    # === Fields
    #
    # _data_:: the data read from the file
    #
    class Rread < StyxMessage
      StyxMessage::MESSAGE_IDS[Rread] = 117
      add_field(:data, "Bstr")

      def count
        return(@fieldvals[:data].length)
      end
    end

    ##
    # Class representing a Twrite message sent by a Styx client.
    #
    # See Inferno's read(5) for more details.
    #
    # === Fields
    #
    # _fid_:: The fid of the file to write to
    # _offset_:: The offset into the file to write to
    # _data_:: The data to be written to that offset
    #
    class Twrite < StyxMessage
      StyxMessage::MESSAGE_IDS[Twrite] = 118
      add_field(:fid, "V")
      add_field(:offset, "ULongLong")
      add_field(:data, "Bstr")
    end

    ##
    # Class representing an Rwrite message sent by a Styx server.
    # See Inferno's read(5) for more details.
    #
    # === Fields
    #
    # _count_:: The number of bytes successfully written to the file
    #
    class Rwrite < StyxMessage
      StyxMessage::MESSAGE_IDS[Rwrite] = 119
      add_field(:count, "V")
    end

    ##
    # Class representing a Tclunk message sent by a Styx client.
    # See Inferno's clunk(5) for more details.
    #
    # === Fields
    #
    # _fid_:: The fid to clunk
    #
    class Tclunk < StyxMessage
      StyxMessage::MESSAGE_IDS[Tclunk] = 120
      add_field(:fid, "V")
    end

    ##
    # Class representing an Rclunk message sent by a Styx server.
    # See Inferno's clunk(5) for more details.
    #
    class Rclunk < StyxMessage
      StyxMessage::MESSAGE_IDS[Rclunk] = 121
    end

    ##
    # Class representing a Tremove message sent by a Styx client.
    # See Inferno's remove(5) for more details.
    #
    # === Fields
    #
    # _fid_:: The fid to remove
    #
    class Tremove < StyxMessage
      StyxMessage::MESSAGE_IDS[Tremove] = 122
      add_field(:fid, "V")
    end

    ##
    # Class representing an Rremove message sent by a Styx server.
    # See Inferno's remove(5) for more details.
    #
    class Rremove < StyxMessage
      StyxMessage::MESSAGE_IDS[Rremove] = 123
    end

    ##
    # Class representing a Tstat message sent by a Styx client.
    # See Inferno's stat(5) for more details.
    #
    # === Fields
    #
    # _fid_:: The fid to receive stat information
    #
    class Tstat < StyxMessage
      StyxMessage::MESSAGE_IDS[Tstat] = 124
      add_field(:fid, "V")
    end

    ##
    # Class representing an Rstat message sent by a Styx server.
    # See Inferno's stat(5) for more details.
    #
    # === Fields
    #
    # _stat_:: the Stat corresponding to the file queried
    #
    class Rstat < StyxMessage
      StyxMessage::MESSAGE_IDS[Rstat] = 125
      add_field(:stat, "Stat")
    end

    ##
    # Class representing a Twstat message sent by a Styx client.
    # See Inferno's stat(5) for more details.
    #
    # === Fields
    #
    # _fid_:: The fid to change stat information
    # _stat_:: the Stat information to write to the file
    #
    class Twstat < StyxMessage
      StyxMessage::MESSAGE_IDS[Twstat] = 126
      add_field(:fid, "V")
     add_field(:stat, "Stat")
    end

    ##
    # Class representing an Rwstat message sent by a Styx server.
    # See Inferno's stat(5) for more details.
    #
    class Rwstat < StyxMessage
      StyxMessage::MESSAGE_IDS[Rwstat] = 127
    end

  end                           # module Message

end                             # module RStyx


