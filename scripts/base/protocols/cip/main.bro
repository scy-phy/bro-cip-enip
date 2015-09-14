##! Implements base functionality for Common Industrial Protocol analysis.
##! Generates the cip.log file.

module Cip;

# @load ./consts

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:     time    &log;
		## Unique ID for the connection.
		uid:    string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     conn_id &log;

		service: count &log &optional;
		path_size: count &log &optional;
		path: index_vec &log &optional;
	};

	## Event that can be handled to access the cip record as it is sent on
	## to the loggin framework.
	global log_cip: event(rec: Info);
}

const ports = { 44818/tcp, 44818/udp, 2222/udp };

redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(Cip::LOG, [$columns=Info, $ev=log_cip, $path="cip"]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_CIP, ports);
	}

event cip_message_request(c: connection, is_orig: bool, service: count, path_size: count, path: index_vec){
	if(!c?$cip){
		c$cip = [$ts=network_time(), $uid=c$uid, $id=c$id];
	}

        c$cip$ts = network_time();
        c$cip$service = service;
	c$cip$path_size = path_size;
	c$cip$path = path;

	Log::write(LOG, c$cip);
}

event connection_state_remove(c: connection) &priority=-5{
	if(!c?$cip)
		return;

	delete c$cip;
}