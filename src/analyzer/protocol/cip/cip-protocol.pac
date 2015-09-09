#
# Useful reference for specs: http://odva.org/
# CIP NETWORKS LIBRARY Volume I: http://www.tud.ttu.ee/im/Kristjan.Sillmann/ISP0051%20Rakenduslik%20Andmeside/CIP%20docs/CIP%20Vol1_3.3.pdf
#
# Binpac for Common Industrial Protocol analyser.
#

##############################
#         CONSTANTS          #
##############################

# Class ID Ranges
# 00 - 63hex CIP Common
# 64hex - C7hex Vendor Specific
# C8hex - EFhex Reserved by ODVA/CI for future use
# F0hex - 2FFhex CIP Common
# 300hex - 4FFhex Vendor Specific
# 500hex - FFFFhex Reserved by ODVA/CI for future use

# Class 02, instance 01 => Message router

# enum class_code {
#      CONNECTION_OBJECT = 0x05,
# };

# enum conn_obj_services {
#      CREATE = 0x08,
#      DELETE = 0x09,
#      RESET = 0x05,
#      FIND_NEXT_OBJECT_INSTANCE = 0x11,
#      GET_ATTRIBUTE_SINGLE = 0x0E,
#      CONNECTION_BIND = 0x4B,
#      PRODUCING_APPLICATION_LOOKUP = 0x4C,
#      SAFETYCLOSE = 0x4E,
#      SAFETYOPEN = 0x54,
# };

# enum state_attribute {
#      NON_EXISTENT = 0,
#      CONFIGURING = 1,
#      WAITING_CONN_ID = 2,
#      ESTABLISHED = 3,
#      TIMED_OUT = 4,
#      # DEFERRED_DEL = 5; # Only used in DeviceNet
#      CLOSING = 6,
# };

# enum instance_type_attribute {
#      EXPLICIT_MESSAGING = 0,
#      IO = 1,
#      CIP_BRIDGED = 2,
# };

# enum transport_class_trigger {
#      TRANSPORT_CLASS = 0b00001111,
#      PRODUCTION_TRIGGER = 0b01110000,
#      DIR = 0b10000000,
# };
# Table 3-4.9 Connection Object Instance Attributes


# Service Code Ranges
# 00 - 31hex CIP Common. These are referred to as CIP Common Services. These are
# defined in Appendix A, Explicit Messaging Services .
# 32hex - 4Ahex Vendor Specific
# 4Bhex - 63hex Object Class Specific
# 64hex - 7Fhex Reserved by ODVA/CI for future use
# 80hex - FFhex Invalid/Not used

# 00 - 63hex CIP Common
# 64hex - C7hex Vendor Specific
# C8hex - FFhex Reserved by ODVA/CI for future use
# 100hex – 2FFhex CIP Common
# 300hex – 4FFhex Vendor Specific
# 500hex – 8FFhex CIP Common
# 900hex - CFFhex Vendor Specific
# D00hex - FFFFhex Reserved by ODVA/CI for future use

# # E8B means 8-bit element
# # C16B means 16-bit class
# enum segment_types {
#      E8B = 0x28,
#      E16B = 0x29,
#      E32B = 0x2A,

#      C8B = 0x20,
#      C16B = 0x21,

#      I8B = 0x24,
#      I16B = 0x25,

#      A8B = 0x30,
#      A16B = 0x31,

#      ANSI = 0x91,
# };

enum services {
     # Reply = request + 0x80
     READ_TAG = 0x4C,
     READ_TAG_REPLY = 0xCC,
     READ_TAG_FRAGMENTED = 0x52,
     READ_TAG_FRAGMENTED_REPLY = 0xD2,
     WRITE_TAG = 0x4D,
     WRITE_TAG_REPLY = 0xCD,
     WRITE_TAG_FRAGMENTED = 0x53,
     WRITE_TAG_FRAGMENTED_REPLY = 0xD3,
     READ_MODIFY_WRITE_TAG = 0x4E,
     READ_MODIFY_WRITE_TAG_REPLY = 0xCE,
     GET_INSTANCE_ATTRIBUTE_LIST = 0x55,
     GET_INSTANCE_ATTRIBUTE_LIST_REPLY = 0xD5,
     GET_ATTRIBUTES_ALL = 0x01,
     GET_ATTRIBUTES_ALL_REPLY = 0x81,
     MULTIPLE_SERVICE_PACKET = 0x0A,
     MULTIPLE_SERVICE_PACKET_REPLY = 0x8A,
     # 83, 8E, 03, 0E
};

enum tag_types {
     BOOL = 0x00C1,
     SINT = 0x00C2,
     INT = 0x00C3,
     DINT = 0x00C4,
     REAL = 0x00CA,
     DWORD = 0x00D3,
     LINT = 0x00C5,
};

enum tag_err {
     BAD_PARAMETER = 0x03,
     SYNTAX_ERROR = 0x04,
     # Extended error 0x0000
     DESTINATION_UNKOWN = 0x05,
     # Extended error 0x0000
     INSUFICIENT_SPACE = 0x06,
     STATE_CONFLICT = 0x10,
     # Extended error 0x2101 attempting to change force information in HARD RUN mode
     # Extended error 0x2802 state in which Safety Memory cannot be modified
     INSUFICIENT_DATA = 0x13,
     WRONG_PATH_SIZE = 0x26,
     GENERAL_ERROR = 0xFF,
     # Extented error 0x2104 Offset is beyond end of the requested tag.
     # Extended error 0x2105 Number of Elements extends beyond the end of the requested tag
     # Extended error 0x2107 Tag type used n request does not match the target tag’s data type
};

##############################
#        RECORD TYPES        #
##############################

# Multi-byte data values are transmitted low-byte first

type Epath(size: uint8) = record {
	path: uint8[size];
} &byteorder=bigendian;

type Type_Data(type: uint16) = record{
     data: case(type) of {
     	   BOOL -> boolean: uint8;
	   SINT -> sint: uint16;
	   INT -> integer: uint32;
	   DINT -> dint: uint32;
	   REAL -> real: uint32;
	   DWORD -> dword: uint32;
	   LINT -> lint: uint64;
     };
};

type Read_Tag = record {
     number: uint16;
} &byteorder=bigendian;

type Read_Tag_Reply = record {
     type: uint16;
     data: Type_Data(type);
} &byteorder=bigendian;

type Read_Tag_Fragmented = record {
     number: uint16;
     offset: uint32;
};

type Read_Tag_Fragmented_Reply = record {
     type: uint16;
     data: bytestring &restofdata; # Maximum 490 bytes
};

type Write_Tag = record {
     type: uint16;
     number: uint16;
     data: Type_Data(type);
};

type Write_Tag_Fragmented = record {
     type: uint16;
     number: uint32;
     offset: uint32;
     data: bytestring &restofdata; # Maximum 474 bytes
};

type Read_Modify_Write_Tag = record {
     size: uint16;
     or_mask: bytestring &length = size;
     and_mask: bytestring &length = size;
};

type Multiple_Service_Packet(is_orig: bool) = record {
     number: uint16;
     offsets: uint16[number];
     service_packets: CIP_PDU(is_orig)[number];
};

type Get_Attribute_List = record {
     number: uint16;
     attributes: uint16[number];
};

type Attribute = record {
     instance_id: uint32;
     symbol_name_len: uint16;
     name: bytestring &length = symbol_name_len;
     symbol_type: bytestring &length = 2;
};

type Get_Attribute_List_Reply = record {
     attributes: Attribute[] &until($input.length() == 0);
};

type Message_Request(is_orig: bool) = record {
     service: uint8;
     path_size: uint8;
     path: Epath(path_size * 2);
     data: case(service) of {
            READ_TAG -> read_tag: Read_Tag_Reply;
            READ_TAG_FRAGMENTED -> read_tag_fragmented: Read_Tag_Fragmented_Reply;
            WRITE_TAG -> write_tag: bytestring &length = 0;
            WRITE_TAG_FRAGMENTED -> write_tag_fragmented: Write_Tag_Fragmented;
            READ_MODIFY_WRITE_TAG -> read_modify: bytestring &length = 0;
            GET_ATTRIBUTES_ALL -> get_attributes_all: Get_Attribute_List_Reply;
            GET_INSTANCE_ATTRIBUTE_LIST -> get_instance_attribute: Get_Attribute_List;
            MULTIPLE_SERVICE_PACKET -> multiple_service_packet: Multiple_Service_Packet(is_orig);

     };
} &byteorder=bigendian;

type Message_Reply(is_orig: bool) = record {
     service: uint8;
     reserved: uint8;
     status: uint8;
     extented_status: uint8;
     data: case(service) of {
            READ_TAG_REPLY -> read_tag: Read_Tag_Reply;
            READ_TAG_FRAGMENTED_REPLY -> read_tag_fragmented: Read_Tag_Fragmented_Reply;
            WRITE_TAG_REPLY -> write_tag: bytestring &length = 0;
            WRITE_TAG_FRAGMENTED_REPLY -> write_tag_fragmented: Write_Tag_Fragmented;
            READ_MODIFY_WRITE_TAG_REPLY -> read_modify: bytestring &length = 0;
            GET_ATTRIBUTES_ALL_REPLY -> get_attributes_all: Get_Attribute_List_Reply;
	    GET_INSTANCE_ATTRIBUTE_LIST_REPLY -> get_instance_attribute: bytestring &length = 0;
            MULTIPLE_SERVICE_PACKET_REPLY -> multiple_service_packet: Multiple_Service_Packet(is_orig);
     };
} &byteorder=bigendian;

type CIP_PDU(is_orig: bool) = record {
	data: bytestring &restofdata;
} &byteorder=bigendian;

# # Table 3-4.5 Connection Bind Service Status Codes
# type Connexion_Bind = record {
#      status: uint8;
#      ext_status: uint8;
# } &byteorder=bigendian;

# # Table 3-4.8 Producing Application Lookup Service Status Codes
# type Application_Lookup_Service_Response = record {
# 	instance_count: uint8;
# 	list: uint8[instance_count];
# } &byteorder=bigendian;