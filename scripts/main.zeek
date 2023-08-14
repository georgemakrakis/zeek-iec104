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

	type info_obj_code : enum {
		# Process information in monitoring direction:
		M_SP_NA_1 = 1,
		M_SP_TA_1 = 2,
		M_DP_NA_1 = 3,
		M_DP_TA_1 = 4,
		M_ST_NA_1 = 5,
		M_ST_TA_1 = 6,
		M_BO_NA_1 = 7,
		M_BO_TA_1 = 8,
		M_ME_NA_1 = 9,
		M_ME_TA_1 = 10,
		M_ME_NB_1 = 11,
		M_ME_TB_1 = 12,
		M_ME_NC_1 = 13,
		M_ME_TC_1 = 14,
		M_IT_NA_1 = 15,
		M_IT_TA_1 = 16,
		M_EP_TA_1 = 17,
		M_EP_TB_1 = 18,
		M_EP_TC_1 = 19, 
		M_PS_NA_1 = 20, 
		M_ME_ND_1 = 21,
		# The 22-29 do not exist or are reserved?
		# Process telegrams with long time tag
		M_SP_TB_1 = 30,
		M_DP_TB_1 = 31,
		M_ST_TB_1 = 32,
		M_BO_TB_1 = 33,
		M_ME_TD_1 = 34,
		M_ME_TE_1 = 35,
		M_ME_TF_1 = 36,
		M_IT_TB_1 = 37,
		M_EP_TD_1 = 38,
		M_EP_TE_1 = 39,
		M_EP_TF_1 = 40,
		# The 41-44 do not exist or are reserved? 
		# Process information in control direction:
		C_SC_NA_1 = 45,
		C_DC_NA_1 = 46,
		C_RC_NA_1 = 47,
		C_SE_NA_1 = 48,
		C_SE_NB_1 = 49,
		C_SE_NC_1 = 50,
		C_BO_NA_1 = 51,
		# 52-57 do not exist or are reserved?
		# Command telegrams with long time tag
		C_SC_TA_1 = 58,
		C_DC_TA_1 = 59,
		C_RC_TA_1 = 60,
		C_SE_TA_1 = 61,
		C_SE_TB_1 = 62,
		C_SE_TC_1 = 63,
		C_BO_TA_1 = 64,
		# 65-69 do not exist or are reserved?
		# System information in monitor direction:
		M_EI_NA_1 = 70,
		# The 71-99 do not exist or are reserved?
		# System information in control direction:
		C_IC_NA_1 = 100,
		C_CI_NA_1 = 101,
		C_RD_NA_1 = 102,
		C_CS_NA_1 = 103,
		C_TS_NA_1 = 104,
		C_RP_NA_1 = 105,
		C_CD_NA_1 = 106,
		C_TS_TA_1 = 107,
		# The 108-109 do not exist or are reserved? 
		# Parameter in control direction:
		P_ME_NA_1 = 110,
		P_ME_NB_1 = 111,
		P_ME_NC_1 = 112,
		P_AC_NA_1 = 113,
		# 114-119 do not exist or are reserved?
		# File transfer:
		F_FR_NA_1 = 120,
		F_SR_NA_1 = 121, 
		F_SC_NA_1 = 122,
		F_LS_NA_1 = 123,
		F_AF_NA_1 = 124,
		F_SG_NA_1 = 125,
		F_DR_TA_1 = 126,
		F_SC_NB_1 = 127
	};

	type cause_tx_code : enum {
		per_cyc = 1,
		back = 2,
		spont = 3,
		init  = 4, 
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

	type QOI : record {
    	info_obj_addr: count &log &optional;
    	qoi : count &log &optional;
	};

	type SCO_field : record {
		sco_on : count &log &optional;   
        qu : count &log &optional;
        se : count &log &optional;
	};

	type SCO : record {
    	info_obj_addr: count &log &optional;
		# This is bifield in packet/spicy
    	sco : SCO_field &log &optional;
	};

	type DCO_field : record {
		dco_on : count &log &optional;    
        qu : count &log &optional;
        se : count &log &optional;
	};

	type DCO : record {
    	info_obj_addr: count &log &optional;
		# This is bifield in packet/spicy
    	dco : DCO_field &log &optional;
	};
	
	type SIQ_field : record {
		spi : count &log &optional;
    	bl : count &log &optional;
    	sb : count &log &optional;
    	nt : count &log &optional;
    	iv : count &log &optional;
	};

	type SIQ : record {
    	info_obj_addr: count &log &optional;
		# This is bifield in packet/spicy
    	siq : SIQ_field &log &optional;
	};

	type RCO_field : record {
		up_down : count &log &optional;    
        qu : count &log &optional;
        se : count &log &optional;
	};

	type RCO : record {
    	info_obj_addr: count &log &optional;
		# This is bifield in packet/spicy
    	RCO : RCO_field &log &optional;
	};


	type BSI_field : record {
		value : count &log &optional;
	};

	type BSI : record {
    	info_obj_addr: count &log &optional;
		# This is bifield in packet/spicy
    	BSI : BSI_field &log &optional;
	};

	type QOS_field : record {
		ql : count &log &optional;
		se : count &log &optional;
	};

	type SVA_QOS : record {
		info_obj_addr: count &log &optional;
		SVA: count &log &optional;
		qos : QOS_field &log &optional;
	};

	type QDS_field : record {
		ov : count &log &optional;
        bl : count &log &optional;
        sb : count &log &optional;
        nt : count &log &optional;
        iv : count &log &optional;
	};

	type SVA_QDS : record {
		info_obj_addr: count &log &optional;
		SVA: count &log &optional;
		qds : QDS_field &log &optional;
	};

	type VTI_QDS : record {
		info_obj_addr: count &log &optional;
		value: string &log &optional;
		qds : QDS_field &log &optional;
	};

	type minutes : record {
		mins : count &log &optional; 
		iv : count &log &optional;
	};

	type hours : record {
		hours : count &log &optional; 
		su : count &log &optional;
	};

	type day_dows : record {
		day : count &log &optional; 
		day_of_week : count &log &optional;
	};

	type CP24TIME2A : record {
		milli : count &log &optional;
		min : minutes &log &optional;
	};

	type CP56TIME2A : record {
		milli : count &log &optional; 
		minute : minutes &log &optional;
		hour : hours &log &optional;
		day_dow : day_dows &log &optional;
		mon : count &log &optional;
		year : count &log &optional;
	};

	type SIQ_CP56Time2a : record {
		info_obj_addr: count &log &optional;
		sqi : SIQ_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type SIQ_CP24Time2a : record {
		info_obj_addr: count &log &optional;
		sqi : SIQ_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type DIQ_field : record {
        dpi : count &log &optional;
        bl : count &log &optional;
        sb : count &log &optional;
        nt : count &log &optional;
        iv : count &log &optional;
	};

	type DIQ_CP56Time2a : record {
		info_obj_type: count &log &optional;
		info_obj_addr: count &log &optional;
		diq : DIQ_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type DIQ_CP24Time2a : record {
		info_obj_addr: count &log &optional;
		dqi : DIQ_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type VTI_QDS_CP56Time2a : record {
		info_obj_addr: count &log &optional;
		value : string &log &optional;
		qds : QDS_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	
	type VTI_QDS_CP24Time2a : record {
		info_obj_addr: count &log &optional;
		value : string &log &optional;
		qds : QDS_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type BSI_QDS_CP56Time2a : record {
		info_obj_addr: count &log &optional;
		# bsi : BSI_field &log &optional;
		bsi : count &log &optional;
		qds : QDS_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type BSI_QDS_CP24Time2a : record {
		info_obj_addr: count &log &optional;
		# bsi : BSI_field &log &optional;
		bsi : count &log &optional;
		qds : QDS_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type COI_field : record {
		r: count &log &optional;
		i: count &log &optional;
	};

	type COI : record {
		info_obj_addr: count &log &optional;
    	coi : COI_field &log &optional;
	};

	type NVA_QDS_CP56Time2a : record {
		info_obj_addr: count &log &optional;
		NVA : count &log &optional;
		qds : QDS_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type NVA_QDS_CP24Time2a : record {
		info_obj_addr: count &log &optional;
		NVA : count &log &optional;
		qds : QDS_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type SVA_QDS_CP56Time2a : record {
		info_obj_addr: count &log &optional;
		SVA : count &log &optional;
		qds : QDS_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type SVA_QDS_CP24Time2a : record {
		info_obj_addr: count &log &optional;
		SVA : count &log &optional;
		qds : QDS_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type IEEE_754_QDS_CP56Time2a : record {
		info_obj_addr: count &log &optional;
		value : count &log &optional;
		qds : QDS_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type IEEE_754_QDS_CP24Time2a : record {
		info_obj_addr: count &log &optional;
		value : count &log &optional;
		qds : QDS_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type Read_Command_client : record {
		info_obj_addr: count &log &optional;
		raw_data : count &log &optional;
	};

	type Read_Command_server : record {
		info_obj_addr: count &log &optional;
	};

	type QRP_client : record {
		info_obj_addr: count &log &optional;
		raw_data : count &log &optional;
	};

	type QRP_server : record {
		info_obj_addr: count &log &optional;
	};

	type Asdu: record {
		# info_obj_type : count &log &optional;
		info_obj_type : info_obj_code &log &optional;
		seq :  count &log &optional;
		num_ix :  count &log &optional;
		# cause_tx :  count &log &optional;
		cause_tx :  cause_tx_code &log &optional;
		negative :  count &log &optional;
		test :  count &log &optional;
		originator_address : count &log &optional;
		common_address :  count &log &optional;

		interrogation_command : QOI &log &optional;
		single_point_information : SIQ &log &optional;
		single_command : SCO &log &optional;
		double_command : DCO &log &optional;
		regulating_step_command : RCO &log &optional;
		bit_string_32_bit : BSI &log &optional;
		setpoint_command_scaled_value : SVA_QOS &log &optional;
		measured_value_scaled_value : SVA_QDS &log &optional;

		step_position_information : VTI_QDS &log &optional;
		# single_point_information_CP56Time2a : SIQ_CP56Time2a &log &optional;
		# single_point_information_CP56Time2a : vector of SIQ_CP56Time2a &optional;
		single_point_information_CP56Time2a : set[SIQ_CP56Time2a] &optional;
		single_point_information_CP24Time2a : SIQ_CP24Time2a &log &optional;
		# double_point_information_CP56Time2a : DIQ_CP56Time2a &log &optional;
		double_point_information_CP56Time2a : vector of DIQ_CP56Time2a &optional;
		double_point_information_CP24Time2a : DIQ_CP24Time2a &log &optional;

		step_position_information_CP56Time2a : VTI_QDS_CP56Time2a &log &optional;
		step_position_information_CP24Time2a : VTI_QDS_CP24Time2a &log &optional;
		bit_string_32_bit_CP56Time2a : BSI_QDS_CP56Time2a &log &optional;
		bit_string_32_bit_CP24Time2a : BSI_QDS_CP24Time2a &log &optional;
		end_of_initialization : COI &log &optional;
		measured_value_normalized_CP56Time2a : NVA_QDS_CP56Time2a &log &optional;
		measured_value_normalized_CP24Time2a : NVA_QDS_CP24Time2a &log &optional;
		measured_value_scaled_CP24Time2a : SVA_QDS_CP24Time2a &log &optional;
		measured_value_scaled_CP56Time2a : SVA_QDS_CP56Time2a &log &optional;
		measured_value_short_floating_point_CP56Time2a : IEEE_754_QDS_CP56Time2a &log &optional;
		measured_value_short_floating_point_CP24Time2a : IEEE_754_QDS_CP24Time2a &log &optional;
		read_Command_client : Read_Command_client &log &optional;
		read_Command_server : Read_Command_server &log &optional;
		qrp_client : QRP_client &log &optional;
		qrp_server : QRP_server &log &optional;

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

	type siq_CP56Time2a_w_info_obj_type : record {
		info_obj_type_b : count &optional;
		info_obj_addr: count &log;
		sqi : SIQ_field &log;
		CP56Time2a : CP56TIME2A &log;
	};


	## Default hook into iec104 logging.
	global log_iec104: event(rec: Info);
}

global single_point_information_CP56Time2a_set : set[SIQ_CP56Time2a];

redef record connection += {
	iec104: Info &optional;
	# iec104_ASDU: Asdu &optional;
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
	
	# c$iec104_ASDU = Asdu();
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

event iec104::apci(c: connection, is_orig : bool, apduLen : count, not_i_type : count, apci_type : count, apci_tx : count, u_start_dt : count, u_stop_dt : count, u_test_fr : count, apci_rx : count) &priority=4
# event iec104::apci(c: connection)	
	{
		hook set_session(c);

		local info = c$iec104;

		# if ( is_orig ) {
		# 	info$request = "ORIGINATOR";
		# 	info$reply = "";
		# }
		# else {
		# 	info$request = "";
		# 	info$reply = "RESPONDER";
		# }

		# local types = enum {
		# 	I = 0,
		# 	S = 1,
		# 	#Undefined = 2, # It is still I
		# 	U = 3
		# };

		info$apduLen = apduLen;
		if (not_i_type == 0) {
			info$apci_type = apci_types[0];
		}
		else {
			info$apci_type = apci_types[apci_type];
		}
		

		if (info$apci_type != "U") {
			info$apci_tx = apci_tx;
			info$apci_rx = apci_rx;
		}
		else {
			info$apci_tx = 0;
			info$apci_rx = 0;
		}

		if (info$apci_type == "U" || info$apci_type == "S") {
			info$asdu = Asdu();
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

		Log::write(iec104::LOG, info);
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

event iec104::asdu (c: connection, info_obj_type : info_obj_code, seq : count, num_ix : count, cause_tx: cause_tx_code, 
					negative : count, test : count, originator_address : count, common_address : count){
					# , interrogation_command : vector of QOI, single_command : vector of SCO, double_command : vector of DCO) &priority=3 {
					# , interrogation_command : vector of QOI) &priority=3 {

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

	# if (info$asdu$info_obj_type == 100) {
	# 	iec104::QOI_evt(c: connection, qoi: info$asdu);
	# }

	# print fmt("info$asdu$interrogation_command vector: %s", info$asdu$interrogation_command);
	
	# info$asdu$interrogation_command = interrogation_command;

	# if (|interrogation_command| > 0) {
	# 	info$asdu$interrogation_command = vector();
	# 	info$asdu$interrogation_command = interrogation_command;
	# 	# for (pair in interrogation_command) {
	# 	# 	message$payload += fmt("%d=%d", payload[pair]$address, payload[pair]$data);
	# 	# }
	# }

	# info$asdu$single_command = single_command;
	# info$asdu$double_command = double_command;

	# print fmt("info_obj_type: %d", info_obj_type);

	print fmt("info$asdu$info_obj_type: %d", info$asdu$info_obj_type);
	
	# local info_ASDU = c$iec104_ASDU;
	# info_ASDU$info_obj_type = info_obj_type;
	# info_ASDU$seq = seq;

	# print fmt("info_ASDU$info_obj_type: %d", info_ASDU$info_obj_type);

	# Log::write(iec104::LOG, info_ASDU);

	# Log::write(iec104::LOG, info);

}


event iec104::QOI_evt(c: connection, qoi: QOI) {
	
	local info = c$iec104;
	# print fmt("QOI");
	# print (qoi);

	info$asdu$interrogation_command = qoi;

	print fmt("info$asdu$interrogation_command: %s", info$asdu$interrogation_command);

	# if (info$asdu$info_obj_type == 100) {

	# 	# print fmt("info$asdu$interrogation_command vector: %s", info$asdu$interrogation_command);
	# 	print fmt("info$asdu$interrogation_command vector: ");
	# }
}



event iec104::SIQ_evt(c: connection, siq: SIQ) {
	
	local info = c$iec104;
	info$asdu$single_point_information = siq;

	print fmt("info$asdu$single_point_information: %s", info$asdu$single_point_information);
}

event iec104::SCO_evt(c: connection, sco: SCO) {
	
	local info = c$iec104;
	info$asdu$single_command = sco;

	print fmt("info$asdu$single_command: %s", info$asdu$single_command);
}

event iec104::DCO_evt(c: connection, dco: DCO) {
	
	local info = c$iec104;
	info$asdu$double_command = dco;

	print fmt("info$asdu$double_command: %s", info$asdu$double_command);
}

event iec104::RCO_evt(c: connection, rco: RCO) {
	
	local info = c$iec104;
	info$asdu$regulating_step_command = rco;

	print fmt("info$asdu$regulating_step_command: %s", info$asdu$regulating_step_command);
}

event iec104::BSI_evt(c: connection, bsi: BSI) {
	
	local info = c$iec104;
	info$asdu$bit_string_32_bit = bsi;

	print fmt("info$asdu$bit_string_32_bit: %s", info$asdu$bit_string_32_bit);
}


event iec104::SVA_QOS_evt(c: connection, sva_qos: SVA_QOS) {
	
	local info = c$iec104;
	info$asdu$setpoint_command_scaled_value = sva_qos;

	print fmt("info$asdu$setpoint_command_scaled_value: %s", info$asdu$setpoint_command_scaled_value);
}

event iec104::SVA_QDS_evt(c: connection, sva_qds: SVA_QDS) {
	
	local info = c$iec104;
	info$asdu$measured_value_scaled_value = sva_qds;

	print fmt("info$asdu$measured_value_scaled_value: %s", info$asdu$measured_value_scaled_value);
}

event iec104::VTI_QDS_evt(c: connection, vti_qds: VTI_QDS) {
	
	local info = c$iec104;
	info$asdu$step_position_information = vti_qds;

	print fmt("info$asdu$step_position_information: %s", info$asdu$step_position_information);
}

# event iec104::SIQ_CP56Time2a_evt(c: connection, asdu_b: Asdu, siq_CP56Time2a: SIQ_CP56Time2a) {
# event iec104::SIQ_CP56Time2a_evt(c: connection, siq_CP56Time2a: SIQ_CP56Time2a) {
event iec104::SIQ_CP56Time2a_evt(c: connection, final: siq_CP56Time2a_w_info_obj_type) {
	
	hook set_session(c);
	
	local info = c$iec104;

	# print fmt("FINAL!!!!: %s", final);


	# local info_obj_type_loc = info$asdu$info_obj_type;
	# print fmt("info_obj_type_loc: %s", info_obj_type_loc);

	# local asdu_loc = info$asdu;
	# print fmt("asdu!!!!: %s", asdu_loc);
	# print fmt("asdu!!!!: %s", asdu_loc$info_obj_type);

	# Trying to "zero out" those fields
	# info$asdu$interrogation_command = QOI();

	info$asdu = Asdu();
	
	if (final$info_obj_type_b == 30) {
		# info$asdu$single_point_information_CP56Time2a = SIQ_CP56Time2a();
		# local v1: vector of SIQ_CP56Time2a;
		local v1: set[SIQ_CP56Time2a];
		info$asdu$single_point_information_CP56Time2a = v1;
		
		local new_SIQ_CP56Time2a = SIQ_CP56Time2a();
		new_SIQ_CP56Time2a$info_obj_addr = final$info_obj_addr;
		new_SIQ_CP56Time2a$sqi = final$sqi;
		new_SIQ_CP56Time2a$CP56Time2a = final$CP56Time2a;

		# print fmt("NEW!!! %s", new_SIQ_CP56Time2a);

		add single_point_information_CP56Time2a_set[new_SIQ_CP56Time2a];

		info$asdu$single_point_information_CP56Time2a = single_point_information_CP56Time2a_set;

		print fmt("info$asdu$single_point_information_CP56Time2a: %s", info$asdu$single_point_information_CP56Time2a);
	}

	# TODO: We do not have the info_obj_type yet here, needs to figure this out.
	# if (info$asdu$info_obj_type == iec104::M_SP_TB_1) {
	# 	info$asdu$single_point_information_CP56Time2a = siq_CP56Time2a;
	# 	print fmt("info$asdu$single_point_information_CP56Time2a: %s", info$asdu$single_point_information_CP56Time2a);
	# }

	# info$asdu$single_point_information_CP56Time2a = siq_CP56Time2a;

	
}

event iec104::SIQ_CP24Time2a_evt(c: connection, siq_CP24Time2a: SIQ_CP24Time2a) {
	
	local info = c$iec104;
	info$asdu$single_point_information_CP24Time2a = siq_CP24Time2a;

	print fmt("info$asdu$single_point_information_CP24Time2a: %s", info$asdu$single_point_information_CP24Time2a);
}

event iec104::DIQ_CP56Time2a_evt(c: connection, diq_CP56Time2a: DIQ_CP56Time2a) {
	
	hook set_session(c);

	local info = c$iec104;

	info$asdu = Asdu();

	local asdu_loc = info$asdu;

	if (diq_CP56Time2a$info_obj_type == 31) {
		# info$asdu$double_point_information_CP56Time2a = DIQ_CP56Time2a();
		# info$asdu$double_point_information_CP56Time2a$info_obj_addr = diq_CP56Time2a$info_obj_addr;
		# info$asdu$double_point_information_CP56Time2a$diq = diq_CP56Time2a$diq;
		# info$asdu$double_point_information_CP56Time2a$CP56Time2a = diq_CP56Time2a$CP56Time2a;

		local new_DIQ_CP56Time2a = DIQ_CP56Time2a();
		new_DIQ_CP56Time2a$info_obj_addr = diq_CP56Time2a$info_obj_addr;
		new_DIQ_CP56Time2a$diq = diq_CP56Time2a$diq;
		new_DIQ_CP56Time2a$CP56Time2a = diq_CP56Time2a$CP56Time2a;

		# info$asdu$double_point_information_CP56Time2a += new_DIQ_CP56Time2a;

		# print fmt("info$asdu$double_point_information_CP56Time2a: %s", info$asdu$double_point_information_CP56Time2a);
	}
	
	# if (asdu_loc$info_obj_type == iec104::M_DP_TB_1) {
	# 	info$asdu$double_point_information_CP56Time2a = diq_CP56Time2a;

	# 	print fmt("info$asdu$double_point_information_CP24Time2a: %s", info$asdu$double_point_information_CP56Time2a);
	# }
}

event iec104::DIQ_CP24Time2a_evt(c: connection, diq_CP24Time2a: DIQ_CP24Time2a) {
	
	local info = c$iec104;
	info$asdu$double_point_information_CP24Time2a = diq_CP24Time2a;

	print fmt("info$asdu$double_point_information_CP24Time2a: %s", info$asdu$double_point_information_CP24Time2a);
}

event iec104::VTI_QDS_CP56Time2a_evt(c: connection, vti_QDS_CP56Time2a: VTI_QDS_CP56Time2a) {
	
	local info = c$iec104;
	info$asdu$step_position_information_CP56Time2a = vti_QDS_CP56Time2a;

	print fmt("info$asdu$step_position_information_CP56Time2a: %s", info$asdu$step_position_information_CP56Time2a);
}

event iec104::VTI_QDS_CP24Time2a_evt(c: connection, vti_QDS_CP24Time2a: VTI_QDS_CP24Time2a) {
	
	local info = c$iec104;
	info$asdu$step_position_information_CP24Time2a = vti_QDS_CP24Time2a;

	print fmt("info$asdu$step_position_information_CP24Time2a: %s", info$asdu$step_position_information_CP24Time2a);
}

event iec104::BSI_QDS_CP56Time2a_evt(c: connection, bsi_QDS_CP56Time2a: BSI_QDS_CP56Time2a) {
	
	local info = c$iec104;
	info$asdu$bit_string_32_bit_CP56Time2a = bsi_QDS_CP56Time2a;

	print fmt("info$asdu$bit_string_32_bit_CP56Time2a: %s", info$asdu$bit_string_32_bit_CP56Time2a);
}


event iec104::BSI_QDS_CP24Time2a_evt(c: connection, bsi_QDS_CP24Time2a: BSI_QDS_CP24Time2a) {
	
	local info = c$iec104;
	info$asdu$bit_string_32_bit_CP24Time2a = bsi_QDS_CP24Time2a;

	print fmt("info$asdu$bit_string_32_bit_CP24Time2a: %s", info$asdu$bit_string_32_bit_CP24Time2a);
}

event iec104::COI_evt(c: connection, coi: COI) {
	
	local info = c$iec104;
	info$asdu$end_of_initialization = coi;

	print fmt("info$asdu$end_of_initialization: %s", info$asdu$end_of_initialization);
}

event iec104::NVA_QDS_CP56Time2a_evt(c: connection, nva_QDS_CP56Time2a: NVA_QDS_CP56Time2a) {
	
	local info = c$iec104;
	info$asdu$measured_value_normalized_CP56Time2a = nva_QDS_CP56Time2a;

	print fmt("info$asdu$measured_value_normalized_CP56Time2a: %s", info$asdu$measured_value_normalized_CP56Time2a);
}

event iec104::NVA_QDS_CP24Time2a_evt(c: connection, nva_QDS_CP24Time2a: NVA_QDS_CP24Time2a) {
	
	local info = c$iec104;
	info$asdu$measured_value_normalized_CP24Time2a = nva_QDS_CP24Time2a;

	print fmt("info$asdu$measured_value_normalized_CP24Time2a: %s", info$asdu$measured_value_normalized_CP24Time2a);
}

event iec104::SVA_QDS_CP24Time2a_evt(c: connection, sva_QDS_CP24Time2a: SVA_QDS_CP24Time2a) {
	
	local info = c$iec104;
	info$asdu$measured_value_scaled_CP24Time2a = sva_QDS_CP24Time2a;

	print fmt("info$asdu$measured_value_scaled_CP24Time2a: %s", info$asdu$measured_value_scaled_CP24Time2a);
}

event iec104::SVA_QDS_CP56Time2a_evt(c: connection, sva_QDS_CP56Time2a: SVA_QDS_CP56Time2a) {
	
	local info = c$iec104;
	info$asdu$measured_value_scaled_CP56Time2a = sva_QDS_CP56Time2a;

	print fmt("info$asdu$measured_value_scaled_CP56Time2a: %s", info$asdu$measured_value_scaled_CP56Time2a);
}

event iec104::IEEE_754_QDS_CP56Time2a_evt(c: connection, ieee_754_QDS_CP56Time2a: IEEE_754_QDS_CP56Time2a) {
	
	local info = c$iec104;
	info$asdu$measured_value_short_floating_point_CP56Time2a = ieee_754_QDS_CP56Time2a;

	print fmt("info$asdu$measured_value_short_floating_point_CP56Time2a: %s", info$asdu$measured_value_short_floating_point_CP56Time2a);
}

event iec104::IEEE_754_QDS_CP24Time2a_evt(c: connection, ieee_754_QDS_CP24Time2a: IEEE_754_QDS_CP24Time2a) {
	
	local info = c$iec104;
	info$asdu$measured_value_short_floating_point_CP24Time2a = ieee_754_QDS_CP24Time2a;

	print fmt("info$asdu$measured_value_short_floating_point_CP24Time2a: %s", info$asdu$measured_value_short_floating_point_CP24Time2a);
}

event iec104::Read_Command_client_evt(c: connection, read_Command_client: Read_Command_client) {
	
	local info = c$iec104;
	info$asdu$read_Command_client = read_Command_client;

	print fmt("info$asdu$read_Command_client: %s", info$asdu$read_Command_client);
}


event iec104::Read_Command_server_evt(c: connection, read_Command_server: Read_Command_server) {
	
	local info = c$iec104;
	info$asdu$read_Command_server = read_Command_server;

	print fmt("info$asdu$read_Command_server: %s", info$asdu$read_Command_server);
}


event iec104::QRP_client_evt(c: connection, qrp_client: QRP_client) {
	
	local info = c$iec104;
	info$asdu$qrp_client = qrp_client;

	print fmt("info$asdu$qrp_client: %s", info$asdu$qrp_client);
}


event iec104::QRP_server_evt(c: connection, qrp_server: QRP_server) {
	
	local info = c$iec104;
	info$asdu$qrp_server = qrp_server;

	print fmt("info$asdu$qrp_server: %s", info$asdu$qrp_server);
}




event connection_state_remove(c: connection) &priority=-5
	{
	# TODO: For UDP protocols, you may want to do this after every request
	# and/or reply.
	#emit_log(c);
	}
