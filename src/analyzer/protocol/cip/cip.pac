# Analyzer for Common Industrial Protocol
#  - cip-protocol.pac: describes the cip protocol messages
#  - cip-analyzer.pac: describes the cip analyzer code

%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"
%}

analyzer CIP withcontext {
	connection: CIP_Conn;
	flow:       CIP_Flow;
};

%include cip-protocol.pac
%include cip-analyzer.pac