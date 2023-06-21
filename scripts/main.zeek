module iec104;


global type_i_counter = 0;
global type_s_counter = 0;
global type_u_counter = 0;
global apduLen = 0;
global apci_type = "";
# global apci_tx: count &log;
# global apci_rx: count &log;
global begin_time: time;
global total_time: interval;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	type cause_tx_code : enum {
		per_cyc = 1,
		back = 2,
		spont = 3,
		inti  = 4, 
		req = 5,
		act = 6,
		actcon = 7,
		deact = 8,
		deactcon = 9,
		actterm = 10,
		retrem = 11,
		retloc = 12,
		file_data_trans = 13, # Using this convention since "file" is already reserved
		# The 14–19 are reserved for future compatible definitions
		inrogen = 20,
		inro1 = 21,
		inro2 = 22,
		inro3 = 23,
		inro4 = 24,
		inro5 = 25,
		inro6 = 26,
		inro7 = 27,
		inro8 = 28,
		inro9 = 29,
		inro10 = 30,
		inro11 = 31,
		inro12 = 32,
		inro13 = 33,
		inro14 = 34,
		inro15 = 35,
		inro16 = 36,
		reqcogen = 37,
		reqco1 = 38,
		reqco2 = 39,
		reqco3 = 40,
		reqco4 = 41,
		reqco5 = 42,
		reqco6 = 43,
		uknown_type = 44,
		uknown_cause = 45,
		unknown_asdu_address = 46,
		unknown_object_address = 47
	};

	type Asdu: record {
		info_obj_type : count &log &optional;
		seq :  count &log &optional;
		num_ix :  count &log &optional;
		# cause_tx :  count &log &optional;
		cause_tx :  cause_tx_code &log &optional;
		negative :  count &log &optional;
		test :  count &log &optional;
		originator_address : count &log &optional;
		common_address :  count &log &optional;
	};

	## Record type containing the column fields of the iec104 log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		# TODO: Adapt subsequent fields as needed.

		apduLen: count &log;
		# apduLen : count &optional;

		# apci_type : count &log;
		# apci_type : count &optional;
		apci_type: string &log;

		apci_tx: count &log &optional;
		apci_rx: count &log &optional;

		# TODO: Should that be an array of ASDUs?
		asdu: Asdu &log &optional;
		# asdu: count &log &optional;

		# Counters can be for statistics but also serve good indicator for correct parsing.
		# type_i_counter: count &log;
		type_i_counter: count &optional;
		# type_s_counter: count &log;
		type_s_counter: count &optional;
		# type_u_counter: count &log;
		type_u_counter: count &optional;

		## Request-side payload.
		request: string &optional &log;
		## Response-side payload.
		reply: string &optional &log;
	};

	const apci_types = {
		[0] = "I",
		[1] = "S",
		[2] = "Ukn",
		[3] = "U",
		[4] = "Err",
	} &default = "unknown";


	## Default hook into iec104 logging.
	global log_iec104: event(rec: Info);
}

redef record connection += {
	iec104: Info &optional;
	iec104_ASDU: Asdu &optional;
};

const ports = {
	# TODO: Replace with actual port(s).
	2404/tcp # adapt port number in iec104.evt accordingly
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(iec104::LOG, [$columns=Info, $ev=log_iec104, $path="iec104"]);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$iec104 )
		return;

	# c$iec104 = Info($ts=network_time(), $uid=c$uid, $id=c$id, $apduLen=apduLen, $apci_type=apci_type,  $type_i_counter=type_i_counter, $type_s_counter=type_s_counter, $type_u_counter=type_u_counter);
	#c$iec104 = Info($ts=network_time(), $uid=c$uid, $id=c$id,  $type_i_counter=type_i_counter, $type_s_counter=type_s_counter, $type_u_counter=type_u_counter);
	
	c$iec104 = Info($ts=network_time(), $uid=c$uid, $id=c$id,  $apduLen=apduLen, $apci_type=apci_type);
	c$iec104$asdu = Asdu();
	
	c$iec104_ASDU = Asdu();
	}

function emit_log(c: connection)
	{
	if ( ! c?$iec104 )
		return;

	Log::write(iec104::LOG, c$iec104);
	delete c$iec104;
	}

# Example event defined in iec104.evt.
# event iec104::message(c: connection, is_orig: bool, payload: string)
# 	{
# 	hook set_session(c);

# 	local info = c$iec104;
# 	if ( is_orig )
# 		info$request = payload;
# 	else
# 		info$reply = payload;
# 	}

# event iec104::apci($conn, self.apduLen, self.ctrl.apci_type, self.ctrl.i_send_seq, self.ctrl.u_start_dt, self.ctrl.u_stop_dt, self.ctrl.u_test_fr, self.ctrl.recv_seq);
event iec104::apci(c: connection, apduLen : count, apci_type : count, apci_tx : count, u_start_dt : count, u_stop_dt : count, u_test_fr : count, apci_rx : count) &priority=4
# event iec104::apci(c: connection)
	{
		hook set_session(c);

		# local types = enum {
		# 	I = 0,
		# 	S = 1,
		# 	#Undefined = 2, # It is still I
		# 	U = 3
		# };

		# NOTE: Just for debugging, can be removed.
		local conv_type: string;

		switch (apci_type) {
            case 0:
                # print "We have an I";
				conv_type = "I";
				break;
            case 1:
                # print "We have an S";
				conv_type = "S";
				break;
            case 2:
                # print "We have something else";
				conv_type = "Ukn";
				break;
            case 3:
                # print "We have an U";
				conv_type = "U";
				break;
            default:
                # print "We have nothing";
				conv_type = "Err";
				break;
        }

		local info = c$iec104;
		info$apduLen = apduLen;
		info$apci_type = apci_types[apci_type];

		if (info$apci_type != "U") {
			info$apci_tx = apci_tx;
			info$apci_rx = apci_rx;
		}
		else {
			info$apci_tx = 0;
			info$apci_rx = 0;
		}

		# print "APCI request", c$id, info$apduLen, conv_type, i_send_seq, u_start_dt, u_stop_dt, u_test_fr, recv_seq;

		# Just messing around with that for debugging, I do not think that should be here but propably in the log.
		if (u_test_fr == 1){
			print "TESTFR act";
		}
		
		if (u_test_fr == 2){
			print "TESTFR con";
		}
		
		if (u_start_dt == 1){
			print "STARTDT act";
		}
		
		if (u_start_dt == 2){
			print "STARTDT con";
		}

		if (u_start_dt == 4){
			print "STOPDT act";
		}
		
		if (u_start_dt == 8){
			print "STOPDT con";
		}

		# Log::write(iec104::LOG, info);
	}

event iec104::i (c:connection, send_seq: count, recv_seq: count) {
	type_i_counter += 1;

	hook set_session(c);

	local info = c$iec104;
	info$type_i_counter = type_i_counter;
}

event iec104::s (c: connection, start: count, len: count, recv_seq: count) {
	type_s_counter += 1;

	hook set_session(c);

	local info = c$iec104;
	info$type_s_counter = type_s_counter;
}

event iec104::u (c: connection){
	type_u_counter += 1;

	hook set_session(c);

	local info = c$iec104;
	info$type_u_counter = type_u_counter;
}

event iec104::asdu (c: connection, info_obj_type : count, seq : count, num_ix : count, cause_tx: cause_tx_code, negative : count, test : count, originator_address : count, common_address : count) &priority=3 {

	hook set_session(c);

	local info = c$iec104;
	info$asdu$info_obj_type = info_obj_type;
	info$asdu$seq = seq;
	info$asdu$num_ix = num_ix;

	info$asdu$cause_tx = cause_tx;
	info$asdu$negative = negative;
	info$asdu$test = test;

	info$asdu$originator_address = originator_address;
	info$asdu$common_address = common_address;
	
	# print fmt("info_obj_type: %d", info_obj_type);

	print fmt("info$asdu$info_obj_type: %d", info$asdu$info_obj_type);
	
	# local info_ASDU = c$iec104_ASDU;
	# info_ASDU$info_obj_type = info_obj_type;
	# info_ASDU$seq = seq;

	# print fmt("info_ASDU$info_obj_type: %d", info_ASDU$info_obj_type);

	# Log::write(iec104::LOG, info_ASDU);

	Log::write(iec104::LOG, info);

}


# ============
# HERE WILL BE THE REST
# ============

event connection_state_remove(c: connection) &priority=-5
	{
	# TODO: For UDP protocols, you may want to do this after every request
	# and/or reply.
	#emit_log(c);
	}
