#ifndef ANALYZER_PROTOCOL_CIP_CIP_H
#define ANALYZER_PROTOCOL_CIP_CIP_H

#include "events.bif.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "cip_pac.h"

namespace analyzer { namespace cip {

class CIP_Analyzer

: public tcp::TCP_ApplicationAnalyzer {

public:
	CIP_Analyzer(Connection* conn);
	virtual ~CIP_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new CIP_Analyzer(conn); }

protected:
	binpac::CIP::CIP_Conn* interp;
	bool had_gap;
};

} } // namespace analyzer::*

#endif
