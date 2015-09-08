refine flow CIP_Flow += {
	function proc_cip_message(msg: CIP_PDU): bool
		%{
		BifEvent::generate_cip_event(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
		return true;
		%}
};

refine typeattr CIP_PDU += &let {
	proc: bool = $context.flow.proc_cip_message(this);
};