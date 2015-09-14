connection CIP_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = CIP_Flow(true);
	downflow = CIP_Flow(false);
};

%header{
	#define 
%}

flow CIP_Flow(is_orig: bool) {
	# flowunit = CIP_PDU(is_orig) withcontext(connection, this);
	datagram = CIP_PDU(is_orig) withcontext(connection, this);


	function cip_message_request(service: uint8, path_size: uint8, path: uint8[]): bool%{
		if(::cip_message_request){
			if(service != READ_TAG &&
			service != READ_TAG_FRAGMENTED &&
			service != WRITE_TAG &&
			service != WRITE_TAG_FRAGMENTED &&
			service != READ_MODIFY_WRITE_TAG &&
			service != GET_INSTANCE_ATTRIBUTE_LIST &&
			service != GET_ATTRIBUTES_ALL &&
			service != MULTIPLE_SERVICE_PACKET){
				connection()->bro_analyzer()->ProtocolViolation(fmt("invalid CIP service (%d)", service));
				return false;
			}

			if(((*path)[0] != 8B_CLASS) && ((*path)[0] != ANSI) && ((*path)[0] != 16B_CLASS)){
				connection()->bro_analyzer()->ProtocolViolation(fmt("invalid CIP path[0] (%d)", (*path)[0]));
				return false;
			}

			if(((*path)[0] == 8B_CLASS) || ((*path)[0] == 16B_CLASS) || ((*path)[2] != 8B_ATTRIBUTE) || ((*path)[2] != 16B_ATTRIBUTE)){
				connection()->bro_analyzer()->ProtocolViolation(fmt("invalid CIP path[2] (%d)", (*path)[1]));
				return false;
			}

			connection()->bro_analyzer()->ProtocolConfirmation();

			VectorVal* path_val = new VectorVal(internal_type("index_vec")->AsVectorType());

			if(path){
				for(unsigned int i = 0; i < path_size; ++i)
					path_val->Assign(i, new Val((*path)[i], TYPE_COUNT));
			}

			BifEvent::generate_cip_message_request(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), service, path_size, path_val);
		}

		return true;
	%}

	function proc_cip_message(msg: CIP_PDU): bool
		%{
		BifEvent::generate_cip_event(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
		return true;
		%}

};

refine typeattr CIP_PDU += &let {
	proc: bool = $context.flow.proc_cip_message(this);
};

refine typeattr Message_Request += &let {
        proc: bool = $context.flow.cip_message_request(service, path_size, path.path);
};