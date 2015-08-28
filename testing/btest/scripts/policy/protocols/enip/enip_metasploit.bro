#
# @TEST-EXEC: bro -C -r $TRACES/enip/enip_metasploit.pcapng %DIR/../../../../../../scripts/policy/protocols/enip/detect-metasploit.bro
# @TEST-EXEC: btest-diff enip.log
# @TEST-EXEC: btest-diff notice.log
#