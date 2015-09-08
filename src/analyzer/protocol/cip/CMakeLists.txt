include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro CIP)
	bro_plugin_cc(CIP.cc Plugin.cc)
	bro_plugin_bif(events.bif)
	bro_plugin_pac(cip.pac cip-analyzer.pac cip-protocol.pac)
bro_plugin_end()