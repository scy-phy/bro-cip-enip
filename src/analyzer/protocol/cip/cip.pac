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

# Our connection consists of two flows, one in each direction.
connection CIP_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = CIP_Flow(true);
	downflow = CIP_Flow(false);
};

%include cip-protocol.pac

# Now we define the flow:
flow CIP_Flow(is_orig: bool) {

	# ## TODO: Determine if you want flowunit or datagram parsing:

	# Using flowunit will cause the anlayzer to buffer incremental input.
	# This is needed for &oneline and &length. If you don't need this, you'll
	# get better performance with datagram.

	# flowunit = CIP_PDU(is_orig) withcontext(connection, this);
	datagram = CIP_PDU(is_orig) withcontext(connection, this);

};

%include cip-analyzer.pac