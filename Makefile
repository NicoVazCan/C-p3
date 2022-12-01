all: break_md5.beam break_md5_v1.beam

break_md5.beam: break_md5.erl
	erlc +debug_info break_md5.erl

break_md5_v1.beam: break_md5_v1.erl
	erlc +debug_info break_md5_v1.erl

clean:
	rm -f break_md5.beam break_md5_v1.beam
