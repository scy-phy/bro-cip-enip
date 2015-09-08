#
# Useful reference for specs: http://odva.org/
# CIP NETWORKS LIBRARY Volume I: http://www.tud.ttu.ee/im/Kristjan.Sillmann/ISP0051%20Rakenduslik%20Andmeside/CIP%20docs/CIP%20Vol1_3.3.pdf
#
# Binpac for Common Industrial Protocol analyser.
#

##############################
#         CONSTANTS          #
##############################

enum tag_types {
     BOOL = 0x00C1; # 1 byte
     SINT = 0x00C2; # 2 bytes
     INT = 0x00C3; # 4 bytes
     DINT = 0x00C4; # 4 bytes
     REAL = 0x00CA; # 4 bytes
     DWORD = 0x00D3; # 4 bytes
     LINT = 0x00C5; # 8 bytes
};

# E8B means 8-bit element
# C16B means 16-bit class
enum segment_types {
     E8B = 0x28;
     E16B = 0x29;
     E32B = 0x2A;

     C8B = 0x20;
     C16B = 0x21;

     I8B = 0x24;
     I16B = 0x25;

     A8B = 0x30;
     A16B = 0x31;

     ANSI = 0x91;
};

enum services {
     READ_TAG = 0x4C;
     READ_TAG_REPLY = 0xCC;
     READ_TAG_FRAGMENTED = 0x52;
     WRITE_TAG = 0x4D;
     WRITE_TAG_FRAGMENTED = 0x53;
     READ_MODIFY_WRITE_TAG = 0x4E;
};

##############################
#        RECORD TYPES        #
##############################

type Message_Request = record {
     srv: uint8;
     psize: uint8;
     path: uint8[psize * 2];
     data: uint16;
} &byteorder=bigendian;

type Message_Reply = record {
     srv: uint8;
     rsrvd: uint8;
     st: uint8;
     ext: uint8;
     reply: Reply_Data;
} &byteorder=bigendian;

type Reply_Data = record {
     type: uint16;
     data: case(type) of {
     	   BOOL -> uint8[1];
	   SINT -> uint8[2];
	   INT -> uint8[4];
	   DINT -> uint8[4];
	   REAL -> uint8[4];
	   DWORD -> uint8[4];
	   LINT -> uint8[8];
     };
} &byteorder=bigendian;

type CIP_PDU(is_orig: bool) = record {
	data: bytestring &restofdata;
} &byteorder=bigendian;