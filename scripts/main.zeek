module iec104;


global type_i_counter = 0;
global type_s_counter = 0;
global type_u_counter = 0;
global apdu_len = 0;
global apci_type = "";
# global apci_tx: count &log;
# global apci_rx: count &log;
global begin_time: time;
global total_time: interval;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG,
		LOG_COI,
		LOG_QOI,
		LOG_SCO,
		LOG_DCO,
		LOG_SIQ,
		LOG_RCO,
		LOG_BSI,
		LOG_SVA_QOS,
		LOG_SVA_QDS,
		LOG_VTI_QDS,
		LOG_SIQ_CP56Time2a,
		LOG_SIQ_CP24Time2a,
		LOG_DIQ_CP56Time2a,
		LOG_DIQ_CP24Time2a,
		LOG_VTI_QDS_CP56Time2a,
		LOG_VTI_QDS_CP24Time2a,
		LOG_BSI_QDS,
		LOG_BSI_QDS_CP56Time2a,
		LOG_BSI_QDS_CP24Time2a,
		LOG_NVA_QDS_CP56Time2a,
		LOG_NVA_QDS_CP24Time2a,
		LOG_SVA_QDS_CP56Time2a,
		LOG_SVA_QDS_CP24Time2a,
		LOG_IEEE_754_QDS_CP56Time2a,
		LOG_IEEE_754_QDS_CP24Time2a,
		LOG_Read_Command_client,
		LOG_Read_Command_server,
		LOG_QRP_client,
		LOG_QRP_server,
	};

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
		C_RP_NC_1 = 105,
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

	type QOI  : record {
		Asdu_num : count &log &optional; 
    	info_obj_addr: count &log &optional;
    	qoi : count &log &optional;
	};

	type SCO_field : record {
		sco_on : count &log &optional;   
        qu : count &log &optional;
        se : count &log &optional;
	};

	type SCO  : record {
		Asdu_num : count &log; 
    	info_obj_addr: count &log &optional;
		# This is bifield in packet/spicy
    	sco : SCO_field &log &optional;
	};

	type DCO_field : record {
		dco_on : count &log &optional;    
        qu : count &log &optional;
        se : count &log &optional;
	};

	type DCO  : record {
		Asdu_num : count &log; 
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

	type SIQ  : record {
		Asdu_num : count &log; 
    	info_obj_addr: count &log &optional;
		# This is bifield in packet/spicy
    	siq : SIQ_field &log &optional;
	};

	type RCO_field : record {
		up_down : count &log &optional;    
        qu : count &log &optional;
        se : count &log &optional;
	};

	type RCO  : record {
		Asdu_num : count &log; 
    	info_obj_addr: count &log &optional;
		# This is bifield in packet/spicy
    	RCO : RCO_field &log &optional;
	};


	type BSI_field : record {
		value : count &log &optional;
	};

	type BSI  : record {
		Asdu_num : count &log; 
    	info_obj_addr: count &log &optional;
		# This is bifield in packet/spicy
    	# BSI : BSI_field &log &optional;
    	BSI : count &log &optional;
	};

	type QOS_field : record {
		ql : count &log &optional;
		se : count &log &optional;
	};

	type SVA_QOS  : record {
		Asdu_num : count &log; 
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

	type SVA_QDS  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		SVA: count &log &optional;
		qds : QDS_field &log &optional;
	};

	type VTI_QDS  : record {
		Asdu_num : count &log; 
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
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		siq : SIQ_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type SIQ_CP24Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		siq : SIQ_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type DIQ_field : record {
        dpi : count &log &optional;
        bl : count &log &optional;
        sb : count &log &optional;
        nt : count &log &optional;
        iv : count &log &optional;
	};

	type DIQ_CP56Time2a  : record {
		Asdu_num : count &log; 
		info_obj_type: count &log &optional;
		info_obj_addr: count &log &optional;
		diq : DIQ_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type DIQ_CP24Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		diq : DIQ_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type VTI_QDS_CP56Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		value : string &log &optional;
		qds : QDS_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	
	type VTI_QDS_CP24Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		value : string &log &optional;
		qds : QDS_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type BSI_QDS  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		# bsi : BSI_field &log &optional;
		bsi : count &log &optional;
		qds : QDS_field &log &optional;
	};

	type BSI_QDS_CP56Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		# bsi : BSI_field &log &optional;
		bsi : count &log &optional;
		qds : QDS_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type BSI_QDS_CP24Time2a  : record {
		Asdu_num : count &log; 
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

	type COI  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
    	coi : COI_field &log &optional;
	};

	type NVA_QDS_CP56Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		NVA : count &log &optional;
		qds : QDS_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type NVA_QDS_CP24Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		NVA : count &log &optional;
		qds : QDS_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type SVA_QDS_CP56Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		SVA : count &log &optional;
		qds : QDS_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type SVA_QDS_CP24Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		SVA : count &log &optional;
		qds : QDS_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type IEEE_754_QDS_CP56Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		value : count &log &optional;
		qds : QDS_field &log &optional;
		CP56Time2a : CP56TIME2A &log &optional;
	};

	type IEEE_754_QDS_CP24Time2a  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		value : count &log &optional;
		qds : QDS_field &log &optional;
		CP24Time2a : CP24TIME2A &log &optional;
	};

	type Read_Command_client  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		raw_data : string &log &optional;
	};

	type Read_Command_server  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
	};

	type QRP_client  : record {
		Asdu_num : count &log; 
		info_obj_addr: count &log &optional;
		raw_data : string &log &optional;
	};

	type QRP_server  : record {
		Asdu_num : count &log; 
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

		# interrogation_command : QOI &log &optional;
		interrogation_command : vector of count &log &optional;

		# single_point_information : SIQ &log &optional;
		single_point_information : vector of count &log &optional;

		single_command :  vector of count &log &optional;	

		double_command : vector of count &log &optional;
		
		regulating_step_command : vector of count &log &optional;
		bit_string_32_bit : vector of count &log &optional;
		setpoint_command_scaled_value : vector of count &log &optional;
		measured_value_scaled_value : vector of count &log &optional;

		step_position_information : vector of count &log &optional;
		
		single_point_information_CP56Time2a : vector of count &log &optional;
		single_point_information_CP24Time2a : vector of count &log &optional;
		# double_point_information_CP56Time2a : DIQ_CP56Time2a &log &optional;
		double_point_information_CP56Time2a : vector of count &log &optional;
		double_point_information_CP24Time2a : vector of count &log &optional;

		step_position_information_CP56Time2a : vector of count &log &optional;
		step_position_information_CP24Time2a : vector of count &log &optional;
		bit_string_32_bit_CP56Time2a : vector of count &log &optional;
		bit_string_32_bit_CP24Time2a : vector of count &log &optional;
		end_of_initialization : vector of count &log &optional;
		measured_value_normalized_CP56Time2a : vector of count &log &optional;
		measured_value_normalized_CP24Time2a : vector of count &log &optional;
		measured_value_scaled_CP24Time2a : vector of count &log &optional;
		measured_value_scaled_CP56Time2a : vector of count &log &optional;
		measured_value_short_floating_point_CP56Time2a : vector of count &log &optional;
		measured_value_short_floating_point_CP24Time2a : vector of count &log &optional;
		read_Command_client : vector of count &log &optional;
		read_Command_server : vector of count &log &optional;
		qrp_client : vector of count &log &optional;
		qrp_server : vector of count &log &optional;

	};

	## Record type containing the column fields of the iec104 log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log &optional;

		# TODO: Adapt subsequent fields as needed.

		apdu_len: count &log &optional;
		# apdu_len : count &optional;

		# apci_type : count &log;
		# apci_type : count &optional;
		apci_type: string &log &optional;

		apci_tx: count &log &optional;
		apci_rx: count &log &optional;

		# TODO: Should that be an array of ASDUs?
		asdu: Asdu &log &optional;
		# asdu: count &log &optional;

		asdu_uid: string &log &optional;


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
		siq : SIQ_field &log;
		CP56Time2a : CP56TIME2A &log;
	};


	## Default hook into iec104 logging.
	global log_iec104: event(rec: Info);
}

global COI_vec : vector of count;
global COI_temp : vector of count;

global QOI_vec : vector of count;
global QOI_temp : vector of count;

global SCO_vec : vector of count;
global SCO_temp : vector of count;
global DCO_vec : vector of count;
global DCO_temp : vector of count;

global SIQ_vec : vector of count;
global SIQ_temp : vector of count;
global RCO_vec : vector of count;
global RCO_temp : vector of count;
global BSI_vec : vector of count;
global BSI_temp : vector of count;
global SVA_QOS_vec : vector of count;
global SVA_QOS_temp : vector of count;
global SVA_QDS_vec : vector of count;
global SVA_QDS_temp : vector of count;
global VTI_QDS_vec : vector of count;
global VTI_QDS_temp : vector of count;

global SIQ_CP56Time2a_vec : vector of count;
global SIQ_CP56Time2a_temp : vector of count;
global SIQ_CP24Time2a_vec : vector of count;
global SIQ_CP24Time2a_temp : vector of count;
global DIQ_CP56Time2a_vec : vector of count;
global DIQ_CP56Time2a_temp : vector of count;
global DIQ_CP24Time2a_vec : vector of count;
global DIQ_CP24Time2a_temp : vector of count;
global VTI_QDS_CP56Time2a_vec : vector of count;
global VTI_QDS_CP56Time2a_temp : vector of count;
global VTI_QDS_CP24Time2a_vec : vector of count;
global VTI_QDS_CP24Time2a_temp : vector of count;
global BSI_QDS_vec : vector of count;
global BSI_QDS_temp : vector of count;
global BSI_QDS_CP56Time2a_vec : vector of count;
global BSI_QDS_CP56Time2a_temp : vector of count;
global BSI_QDS_CP24Time2a_vec : vector of count;
global BSI_QDS_CP24Time2a_temp : vector of count;
global NVA_QDS_CP56Time2a_vec : vector of count;
global NVA_QDS_CP56Time2a_temp : vector of count;
global NVA_QDS_CP24Time2a_vec : vector of count;
global NVA_QDS_CP24Time2a_temp : vector of count;
global SVA_QDS_CP56Time2a_vec : vector of count;
global SVA_QDS_CP56Time2a_temp : vector of count;
global SVA_QDS_CP24Time2a_vec : vector of count;
global SVA_QDS_CP24Time2a_temp : vector of count;
global IEEE_754_QDS_CP56Time2a_vec : vector of count;
global IEEE_754_QDS_CP56Time2a_temp : vector of count;
global IEEE_754_QDS_CP24Time2a_vec : vector of count;
global IEEE_754_QDS_CP24Time2a_temp : vector of count;
global Read_Command_client_vec : vector of count;
global Read_Command_client_temp : vector of count;
global Read_Command_server_vec : vector of count;
global Read_Command_server_temp : vector of count;
global QRP_client_vec : vector of count;
global QRP_client_temp : vector of count;
global QRP_server_vec : vector of count;
global QRP_server_temp : vector of count;

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
	# TODO: Shall we create another log stream here that we correlate it to have multiple records for the
	# num_ix ASDUs that we might have? Correllated with an ASDU_UUID?
	# Log::create_stream(iec104::LOG_SIQ_CP56Time2a, [$columns=SIQ_CP56Time2a, $path="iec104-SIQ"]);
		Log::create_stream(iec104::LOG_COI, [$columns=COI, $path="iec104-COI"]);
		Log::create_stream(iec104::LOG_QOI, [$columns=QOI, $path="iec104-QOI"]);
		Log::create_stream(iec104::LOG_SCO, [$columns=SCO, $path="iec104-SCO"]);
		Log::create_stream(iec104::LOG_DCO, [$columns=DCO, $path="iec104-DCO"]);
		Log::create_stream(iec104::LOG_SIQ, [$columns=SIQ, $path="iec104-SIQ"]);
		Log::create_stream(iec104::LOG_RCO, [$columns=RCO, $path="iec104-RCO"]);
		Log::create_stream(iec104::LOG_BSI, [$columns=BSI, $path="iec104-BSI"]);
		Log::create_stream(iec104::LOG_SVA_QOS, [$columns=SVA_QOS, $path="iec104-SVA_QOS"]);
		Log::create_stream(iec104::LOG_SVA_QDS, [$columns=SVA_QDS, $path="iec104-SVA_QDS"]);
		Log::create_stream(iec104::LOG_VTI_QDS, [$columns=VTI_QDS, $path="iec104-VTI_QDS"]);
		Log::create_stream(iec104::LOG_SIQ_CP56Time2a, [$columns=SIQ_CP56Time2a, $path="iec104-SIQ_CP56Time2a"]);
		Log::create_stream(iec104::LOG_SIQ_CP24Time2a, [$columns=SIQ_CP24Time2a, $path="iec104-SIQ_CP24Time2a"]);
		Log::create_stream(iec104::LOG_DIQ_CP56Time2a, [$columns=DIQ_CP56Time2a, $path="iec104-DIQ_CP56Time2a"]);
		Log::create_stream(iec104::LOG_DIQ_CP24Time2a, [$columns=DIQ_CP24Time2a, $path="iec104-DIQ_CP24Time2a"]);
		Log::create_stream(iec104::LOG_VTI_QDS_CP56Time2a, [$columns=VTI_QDS_CP56Time2a, $path="iec104-VTI_QDS_CP56Time2a"]);
		Log::create_stream(iec104::LOG_VTI_QDS_CP24Time2a, [$columns=VTI_QDS_CP24Time2a, $path="iec104-VTI_QDS_CP24Time2a"]);
		Log::create_stream(iec104::LOG_BSI_QDS, [$columns=BSI_QDS, $path="iec104-BSI_QDS"]);
		Log::create_stream(iec104::LOG_BSI_QDS_CP56Time2a, [$columns=BSI_QDS_CP56Time2a, $path="iec104-BSI_QDS_CP56Time2a"]);
		Log::create_stream(iec104::LOG_BSI_QDS_CP24Time2a, [$columns=BSI_QDS_CP24Time2a, $path="iec104-BSI_QDS_CP24Time2a"]);
		Log::create_stream(iec104::LOG_NVA_QDS_CP56Time2a, [$columns=NVA_QDS_CP56Time2a, $path="iec104-NVA_QDS_CP56Time2a"]);
		Log::create_stream(iec104::LOG_NVA_QDS_CP24Time2a, [$columns=NVA_QDS_CP24Time2a, $path="iec104-NVA_QDS_CP24Time2a"]);
		Log::create_stream(iec104::LOG_SVA_QDS_CP56Time2a, [$columns=SVA_QDS_CP56Time2a, $path="iec104-SVA_QDS_CP56Time2a"]);
		Log::create_stream(iec104::LOG_SVA_QDS_CP24Time2a, [$columns=SVA_QDS_CP24Time2a, $path="iec104-SVA_QDS_CP24Time2a"]);
		Log::create_stream(iec104::LOG_IEEE_754_QDS_CP56Time2a, [$columns=IEEE_754_QDS_CP56Time2a, $path="iec104-IEEE_754_QDS_CP56Time2a"]);
		Log::create_stream(iec104::LOG_IEEE_754_QDS_CP24Time2a, [$columns=IEEE_754_QDS_CP24Time2a, $path="iec104-IEEE_754_QDS_CP24Time2a"]);
		Log::create_stream(iec104::LOG_Read_Command_client, [$columns=Read_Command_client, $path="iec104-Read_Command_client"]);
		Log::create_stream(iec104::LOG_Read_Command_server, [$columns=Read_Command_server, $path="iec104-Read_Command_server"]);
		Log::create_stream(iec104::LOG_QRP_client, [$columns=QRP_client, $path="iec104-QRP_client"]);
		Log::create_stream(iec104::LOG_QRP_server, [$columns=QRP_server, $path="iec104-QRP_server"]);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$iec104 )
		return;

	# c$iec104 = Info($ts=network_time(), $uid=c$uid, $id=c$id, $apdu_len=apdu_len, $apci_type=apci_type,  $type_i_counter=type_i_counter, $type_s_counter=type_s_counter, $type_u_counter=type_u_counter);
	#c$iec104 = Info($ts=network_time(), $uid=c$uid, $id=c$id,  $type_i_counter=type_i_counter, $type_s_counter=type_s_counter, $type_u_counter=type_u_counter);
	
	c$iec104 = Info($ts=network_time(), $uid=c$uid, $id=c$id,  $apdu_len=apdu_len, $apci_type=apci_type);
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
# 
#	local info = c$iec104;
# 	if ( is_orig )
# 		info$request = payload;
# 	else
# 		info$reply = payload;
# 	}

event iec104::apci(c: connection, is_orig : bool, apdu_len : count, not_i_type : count, apci_type : count, apci_tx : count, u_start_dt : count, u_stop_dt : count, u_test_fr : count, apci_rx : count) &priority=4
# event iec104::apci(c: connection)	
	{
		hook set_session(c);

		if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

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

		info$apdu_len = apdu_len;
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

		# print "APCI request", c$id, info$apdu_len, conv_type, i_send_seq, u_start_dt, u_stop_dt, u_test_fr, recv_seq;

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

		# TODO: Neews for the rest as well
		if( |COI_temp| != 0)
			info$asdu$end_of_initialization = COI_temp;
		
		if( |QOI_temp| != 0)
			info$asdu$interrogation_command = QOI_temp;
		
		if( |SIQ_temp| != 0)
			info$asdu$single_point_information = SIQ_temp;
		
		if( |SCO_temp| != 0)
			info$asdu$single_command = SCO_temp;
		
		if( |DCO_temp| != 0)
			info$asdu$double_command = DCO_temp;
		
		if( |RCO_temp| != 0)
			info$asdu$regulating_step_command = RCO_temp;
		
		if( |BSI_temp| != 0)
			info$asdu$bit_string_32_bit = BSI_temp;
		
		if( |SVA_QOS_temp| != 0)
			info$asdu$setpoint_command_scaled_value = SVA_QOS_temp;
		
		if( |SVA_QDS_temp| != 0)
			info$asdu$measured_value_scaled_value = SVA_QDS_temp;
		
		if( |VTI_QDS_temp| != 0)
			info$asdu$step_position_information = VTI_QDS_temp;
		
		if( |SIQ_CP56Time2a_temp| != 0)
			info$asdu$single_point_information_CP56Time2a = SIQ_CP56Time2a_temp;
		
		if( |SIQ_CP24Time2a_temp| != 0)
			info$asdu$single_point_information_CP24Time2a = SIQ_CP24Time2a_temp;
		
		if( |DIQ_CP56Time2a_temp| != 0)
			info$asdu$double_point_information_CP56Time2a = DIQ_CP56Time2a_temp;
		
		if( |DIQ_CP24Time2a_temp| != 0)
			info$asdu$double_point_information_CP24Time2a = DIQ_CP24Time2a_temp;
		
		if( |VTI_QDS_CP56Time2a_temp| != 0)
			info$asdu$step_position_information_CP56Time2a = VTI_QDS_CP56Time2a_temp;
		
		if( |VTI_QDS_CP24Time2a_temp| != 0)
			info$asdu$step_position_information_CP24Time2a = VTI_QDS_CP24Time2a_temp;
		
		if( |BSI_QDS_temp| != 0)
			info$asdu$bit_string_32_bit = BSI_QDS_temp;

		if( |BSI_QDS_CP56Time2a_temp| != 0)
			info$asdu$bit_string_32_bit_CP56Time2a = BSI_QDS_CP56Time2a_temp;
		
		if( |BSI_QDS_CP24Time2a_temp| != 0)
			info$asdu$bit_string_32_bit_CP24Time2a = BSI_QDS_CP24Time2a_temp;
		
		if( |NVA_QDS_CP56Time2a_temp| != 0)
			info$asdu$measured_value_normalized_CP56Time2a = NVA_QDS_CP56Time2a_temp;
		
		if( |NVA_QDS_CP24Time2a_temp| != 0)
			info$asdu$measured_value_normalized_CP24Time2a = NVA_QDS_CP24Time2a_temp;
		
		if( |SVA_QDS_CP24Time2a_temp| != 0)
			info$asdu$measured_value_scaled_CP24Time2a = SVA_QDS_CP24Time2a_temp;
		
		if( |SVA_QDS_CP56Time2a_temp| != 0)
			info$asdu$measured_value_scaled_CP56Time2a = SVA_QDS_CP56Time2a_temp;
		
		if( |IEEE_754_QDS_CP56Time2a_temp| != 0)
			info$asdu$measured_value_short_floating_point_CP56Time2a = IEEE_754_QDS_CP56Time2a_temp;
		
		if( |IEEE_754_QDS_CP24Time2a_temp| != 0)
			info$asdu$measured_value_short_floating_point_CP24Time2a = IEEE_754_QDS_CP24Time2a_temp;
		
		if( |Read_Command_client_temp| != 0)
			info$asdu$read_Command_client = Read_Command_client_temp;
		
		if( |Read_Command_server_temp| != 0)
			info$asdu$read_Command_server = Read_Command_server_temp;
		
		if( |QRP_client_temp| != 0)
			info$asdu$qrp_client = QRP_client_temp;
		
		if( |QRP_server_temp| != 0)
			info$asdu$qrp_server = QRP_server_temp;
		
		
		# print fmt("info$asdu$single_point_information_CP56Time2a: %s", info$asdu$single_point_information_CP56Time2a);
		# print fmt("info$asdu$interrogation_command: %s", info$asdu$interrogation_command);

		Log::write(iec104::LOG, info);

		# for ( entry in info$asdu$single_point_information_CP56Time2a)
		
		# for ( entry in single_point_information_CP56Time2a_set)
		# 	Log::write(iec104::LOG_SIQ_CP56Time2a, entry);
		# 	print fmt("  single_point_information_CP56Time2a ENTRY: %s", entry);
			
		# single_point_information_CP56Time2a_set = set();
		
		local empty_COI_temp : vector of count;
		COI_temp = empty_COI_temp;

		local empty_QOI_temp: vector of count;
		QOI_temp = empty_QOI_temp;

		local empty_SCO_temp : vector of count;
		SCO_temp = empty_SCO_temp;
		local empty_DCO_temp : vector of count;
		DCO_temp = empty_DCO_temp;

		local empty_SIQ_temp : vector of count;
		SIQ_temp = empty_SIQ_temp;
		local empty_RCO_temp : vector of count;
		RCO_temp = empty_RCO_temp;
		local empty_BSI_temp : vector of count;
		BSI_temp = empty_BSI_temp;
		local empty_SVA_QOS_temp : vector of count;
		SVA_QOS_temp =  empty_SVA_QOS_temp;
		local empty_SVA_QDS_temp : vector of count;
		SVA_QDS_temp = empty_SVA_QDS_temp;
		local empty_VTI_QDS_temp : vector of count;
		VTI_QDS_temp = empty_VTI_QDS_temp;

		local empty_SIQ_CP56Time2a_temp : vector of count;
		SIQ_CP56Time2a_temp = empty_SIQ_CP56Time2a_temp;
		local empty_SIQ_CP24Time2a_temp : vector of count;
		SIQ_CP24Time2a_temp = empty_SIQ_CP24Time2a_temp;
		local empty_DIQ_CP56Time2a_temp : vector of count;
		DIQ_CP56Time2a_temp = empty_DIQ_CP56Time2a_temp;
		local empty_DIQ_CP24Time2a_temp : vector of count;
		DIQ_CP24Time2a_temp = empty_DIQ_CP24Time2a_temp;
		local empty_VTI_QDS_CP56Time2a_temp : vector of count;
		VTI_QDS_CP56Time2a_temp = empty_VTI_QDS_CP56Time2a_temp;
		local empty_VTI_QDS_CP24Time2a_temp : vector of count;
		VTI_QDS_CP24Time2a_temp = empty_VTI_QDS_CP24Time2a_temp;
		local empty_BSI_QDS_temp : vector of count;
		BSI_QDS_temp = empty_BSI_QDS_temp;
		local empty_BSI_QDS_CP56Time2a_temp : vector of count;
		BSI_QDS_CP56Time2a_temp = empty_BSI_QDS_CP56Time2a_temp;
		local empty_BSI_QDS_CP24Time2a_temp : vector of count;
		BSI_QDS_CP24Time2a_temp = empty_BSI_QDS_CP24Time2a_temp;
		local empty_NVA_QDS_CP56Time2a_temp : vector of count;
		NVA_QDS_CP56Time2a_temp = empty_NVA_QDS_CP56Time2a_temp;
		local empty_NVA_QDS_CP24Time2a_temp : vector of count;
		NVA_QDS_CP24Time2a_temp = empty_NVA_QDS_CP24Time2a_temp;
		local empty_SVA_QDS_CP56Time2a_temp : vector of count;
		SVA_QDS_CP56Time2a_temp = empty_SVA_QDS_CP56Time2a_temp;
		local empty_SVA_QDS_CP24Time2a_temp : vector of count;
		SVA_QDS_CP24Time2a_temp = empty_SVA_QDS_CP24Time2a_temp;
		local empty_IEEE_754_QDS_CP56Time2a_temp : vector of count;
		IEEE_754_QDS_CP56Time2a_temp = empty_IEEE_754_QDS_CP56Time2a_temp;
		local empty_IEEE_754_QDS_CP24Time2a_temp : vector of count;
		IEEE_754_QDS_CP24Time2a_temp = empty_IEEE_754_QDS_CP24Time2a_temp;
		local empty_Read_Command_client_temp : vector of count;
		Read_Command_client_temp = empty_Read_Command_client_temp;
		local empty_Read_Command_server_temp : vector of count;
		Read_Command_server_temp = empty_Read_Command_server_temp;
		local empty_QRP_client_temp : vector of count;
		QRP_client_temp = empty_QRP_client_temp;
		local empty_QRP_server_temp : vector of count;
		QRP_server_temp = empty_QRP_server_temp;
	}

event iec104::i (c:connection, send_seq: count, recv_seq: count) {
	type_i_counter += 1;

	hook set_session(c);

	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$type_i_counter = type_i_counter;
}

event iec104::s (c: connection, start: count, len: count, recv_seq: count) {
	type_s_counter += 1;

	hook set_session(c);

	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$type_s_counter = type_s_counter;
}

event iec104::u (c: connection){
	type_u_counter += 1;

	hook set_session(c);

	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$type_u_counter = type_u_counter;
}

event iec104::asdu (c: connection, info_obj_type : info_obj_code, seq : count, num_ix : count, cause_tx: cause_tx_code, 
					negative : count, test : count, originator_address : count, common_address : count) &priority=3{
					# , interrogation_command : vector of QOI, single_command : vector of SCO, double_command : vector of DCO) &priority=3 {
					# , interrogation_command : vector of QOI) &priority=3 {

	hook set_session(c);

	if (! c?$iec104 ) {
		# print fmt("!!!!!!ISSUE!!!!!!");
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];

		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu$info_obj_type = info_obj_type;
	info$asdu$seq = seq;
	info$asdu$num_ix = num_ix;

	info$asdu$cause_tx = cause_tx;
	info$asdu$negative = negative;
	info$asdu$test = test;

	info$asdu$originator_address = originator_address;
	info$asdu$common_address = common_address;
}


event iec104::QOI_evt(c: connection, qoi: QOI) {

	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	# print fmt("QOI");
	# print (qoi);

	info$asdu = Asdu();

	local next_num: count;
	next_num = |QOI_vec| + 1;
	
	QOI_temp += next_num;
	QOI_vec += next_num;
	
	local new_QOI = QOI($Asdu_num=next_num);
	# local new_QOI = QOI();
	new_QOI$info_obj_addr = qoi$info_obj_addr;
	new_QOI$qoi = qoi$qoi;
	
	Log::write(iec104::LOG_QOI, new_QOI);
}



event iec104::SIQ_evt(c: connection, siq: SIQ) {

	if (! c?$iec104 ) {
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	# Infinity loop for testing the log ouputs
	# local iter = 0;

	# while ( iter < 5 )
	# {
	# 	print ++iter;
	# 	if( iter == 5)
	# 		iter = 0;
	# }

	local info = c$iec104;
	
	info$asdu = Asdu();

	local next_num: count;
	next_num = |SIQ_vec| + 1;
	
	SIQ_temp += next_num;
	SIQ_vec += next_num;
	
	local new_SIQ = SIQ($Asdu_num=next_num);
	new_SIQ$info_obj_addr = siq$info_obj_addr;
	new_SIQ$siq = siq$siq;
	
	Log::write(iec104::LOG_SIQ, new_SIQ);
}

event iec104::SCO_evt(c: connection, sco: SCO) {

	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	
	info$asdu = Asdu();

	local next_num: count;
	next_num = |SCO_vec| + 1;
	
	SCO_temp += next_num;
	SCO_vec += next_num;
	
	local new_SCO = SCO($Asdu_num=next_num);
	new_SCO$info_obj_addr = sco$info_obj_addr;
	new_SCO$sco = sco$sco;
	
	Log::write(iec104::LOG_SCO, new_SCO);
}

event iec104::DCO_evt(c: connection, dco: DCO) {

	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	
	info$asdu = Asdu();

	local next_num: count;
	next_num = |DCO_vec| + 1;
	
	DCO_temp += next_num;
	DCO_vec += next_num;
	
	local new_DCO = DCO($Asdu_num=next_num);
	new_DCO$info_obj_addr = dco$info_obj_addr;
	new_DCO$dco = dco$dco;
	
	Log::write(iec104::LOG_DCO, new_DCO);
}

event iec104::RCO_evt(c: connection, rco: RCO) {

	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |RCO_vec| + 1;
	
	RCO_temp += next_num;
	RCO_vec += next_num;
	
	local new_RCO = RCO($Asdu_num=next_num);
	new_RCO$info_obj_addr = rco$info_obj_addr;
	new_RCO$RCO = rco$RCO;
	
	Log::write(iec104::LOG_RCO, new_RCO);	
}

event iec104::BSI_evt(c: connection, bsi: BSI) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |BSI_vec| + 1;
	
	BSI_temp += next_num;
	BSI_vec += next_num;

	local new_BSI = BSI($Asdu_num=next_num);
	new_BSI$info_obj_addr = bsi$info_obj_addr;
	new_BSI$BSI = bsi$BSI;
	
	Log::write(iec104::LOG_BSI, new_BSI);	
}


event iec104::SVA_QOS_evt(c: connection, sva_qos: SVA_QOS) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |SVA_QOS_vec| + 1;
	
	SVA_QOS_temp += next_num;
	SVA_QOS_vec += next_num;
	
	local new_SVA_QOS = SVA_QOS($Asdu_num=next_num);
	new_SVA_QOS$info_obj_addr = sva_qos$info_obj_addr;
	new_SVA_QOS$SVA = sva_qos$SVA;
	new_SVA_QOS$qos = sva_qos$qos;
	
	Log::write(iec104::LOG_SVA_QOS, new_SVA_QOS);	
}

event iec104::SVA_QDS_evt(c: connection, sva_qds: SVA_QDS) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |SVA_QDS_vec| + 1;
	
	SVA_QDS_temp += next_num;
	SVA_QDS_vec += next_num;
	
	local new_SVA_QDS = SVA_QDS($Asdu_num=next_num);
	new_SVA_QDS$info_obj_addr = sva_qds$info_obj_addr;
	new_SVA_QDS$SVA = sva_qds$SVA;
	new_SVA_QDS$qds = sva_qds$qds;
	
	Log::write(iec104::LOG_SVA_QDS, new_SVA_QDS);
}

event iec104::VTI_QDS_evt(c: connection, vti_qds: VTI_QDS) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |VTI_QDS_vec| + 1;
	
	VTI_QDS_temp += next_num;
	VTI_QDS_vec += next_num;
	
	local new_VTI_QDS = VTI_QDS($Asdu_num=next_num);
	new_VTI_QDS$info_obj_addr = vti_qds$info_obj_addr;
	new_VTI_QDS$value = vti_qds$value;
	new_VTI_QDS$qds = vti_qds$qds;
	
	Log::write(iec104::LOG_VTI_QDS, new_VTI_QDS);
}

# event iec104::SIQ_CP56Time2a_evt(c: connection, asdu_b: Asdu, siq_CP56Time2a: SIQ_CP56Time2a) {
event iec104::SIQ_CP56Time2a_evt(c: connection, siq_CP56Time2a: SIQ_CP56Time2a) {
# event iec104::SIQ_CP56Time2a_evt(c: connection, final: siq_CP56Time2a_w_info_obj_type) &priority=2 {
	
	hook set_session(c);
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;

	info$asdu = Asdu();

	local next_num: count;
	next_num = |SIQ_CP56Time2a_vec| + 1;
	
	SIQ_CP56Time2a_temp += next_num;
	SIQ_CP56Time2a_vec += next_num;
	
	# print fmt("info$asdu$single_point_information_CP56Time2a: %s", info$asdu$single_point_information_CP56Time2a);
	
	local new_SIQ_CP56Time2a = SIQ_CP56Time2a($Asdu_num=next_num);
	new_SIQ_CP56Time2a$info_obj_addr = siq_CP56Time2a$info_obj_addr;
	new_SIQ_CP56Time2a$siq = siq_CP56Time2a$siq;
	new_SIQ_CP56Time2a$CP56Time2a = siq_CP56Time2a$CP56Time2a;
	
	Log::write(iec104::LOG_SIQ_CP56Time2a, new_SIQ_CP56Time2a);
	
	
}

event iec104::SIQ_CP24Time2a_evt(c: connection, siq_CP24Time2a: SIQ_CP24Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |SIQ_CP24Time2a_vec| + 1;
	
	SIQ_CP24Time2a_temp += next_num;
	SIQ_CP24Time2a_vec += next_num;
	
	local new_SIQ_CP24Time2a = SIQ_CP24Time2a($Asdu_num=next_num);
	new_SIQ_CP24Time2a$info_obj_addr = siq_CP24Time2a$info_obj_addr;
	new_SIQ_CP24Time2a$siq = siq_CP24Time2a$siq;
	new_SIQ_CP24Time2a$CP24Time2a = siq_CP24Time2a$CP24Time2a;
	
	Log::write(iec104::LOG_SIQ_CP24Time2a, new_SIQ_CP24Time2a);
}

event iec104::DIQ_CP56Time2a_evt(c: connection, diq_CP56Time2a: DIQ_CP56Time2a) {
	
	hook set_session(c);

	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |DIQ_CP56Time2a_vec| + 1;
	
	DIQ_CP56Time2a_temp += next_num;
	DIQ_CP56Time2a_vec += next_num;
	
	local new_DIQ_CP56Time2a = DIQ_CP56Time2a($Asdu_num=next_num);
	new_DIQ_CP56Time2a$info_obj_addr = diq_CP56Time2a$info_obj_addr;
	new_DIQ_CP56Time2a$diq = diq_CP56Time2a$diq;
	new_DIQ_CP56Time2a$CP56Time2a = diq_CP56Time2a$CP56Time2a;
	
	Log::write(iec104::LOG_DIQ_CP56Time2a, new_DIQ_CP56Time2a);
}

event iec104::DIQ_CP24Time2a_evt(c: connection, diq_CP24Time2a: DIQ_CP24Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |DIQ_CP24Time2a_vec| + 1;
	
	DIQ_CP24Time2a_temp += next_num;
	DIQ_CP24Time2a_vec += next_num;
	
	local new_DIQ_CP24Time2a = DIQ_CP24Time2a($Asdu_num=next_num);
	new_DIQ_CP24Time2a$info_obj_addr = diq_CP24Time2a$info_obj_addr;
	new_DIQ_CP24Time2a$diq = diq_CP24Time2a$diq;
	new_DIQ_CP24Time2a$CP24Time2a = diq_CP24Time2a$CP24Time2a;
	
	Log::write(iec104::LOG_DIQ_CP24Time2a, new_DIQ_CP24Time2a);
}

event iec104::VTI_QDS_CP56Time2a_evt(c: connection, vti_QDS_CP56Time2a: VTI_QDS_CP56Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |VTI_QDS_CP56Time2a_vec| + 1;
	
	VTI_QDS_CP56Time2a_temp += next_num;
	VTI_QDS_CP56Time2a_vec += next_num;
	
	local new_VTI_QDS_CP56Time2a = VTI_QDS_CP56Time2a($Asdu_num=next_num);
	new_VTI_QDS_CP56Time2a$info_obj_addr = vti_QDS_CP56Time2a$info_obj_addr;
	new_VTI_QDS_CP56Time2a$value = vti_QDS_CP56Time2a$value;
	new_VTI_QDS_CP56Time2a$qds = vti_QDS_CP56Time2a$qds;
	new_VTI_QDS_CP56Time2a$CP56Time2a = vti_QDS_CP56Time2a$CP56Time2a;
	
	Log::write(iec104::LOG_VTI_QDS_CP56Time2a, new_VTI_QDS_CP56Time2a);
}

event iec104::VTI_QDS_CP24Time2a_evt(c: connection, vti_QDS_CP24Time2a: VTI_QDS_CP24Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |VTI_QDS_CP24Time2a_vec| + 1;
	
	VTI_QDS_CP24Time2a_temp += next_num;
	VTI_QDS_CP24Time2a_vec += next_num;
	
	local new_VTI_QDS_CP24Time2a = VTI_QDS_CP24Time2a($Asdu_num=next_num);
	new_VTI_QDS_CP24Time2a$info_obj_addr = vti_QDS_CP24Time2a$info_obj_addr;
	new_VTI_QDS_CP24Time2a$value = vti_QDS_CP24Time2a$value;
	new_VTI_QDS_CP24Time2a$qds = vti_QDS_CP24Time2a$qds;
	new_VTI_QDS_CP24Time2a$CP24Time2a = vti_QDS_CP24Time2a$CP24Time2a;
	
	Log::write(iec104::LOG_VTI_QDS_CP24Time2a, new_VTI_QDS_CP24Time2a);
}

event iec104::BSI_QDS_evt(c: connection, bsi_QDS: BSI_QDS) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |BSI_QDS_vec| + 1;
	
	BSI_QDS_temp += next_num;
	BSI_QDS_vec += next_num;
	
	local new_BSI_QDS = BSI_QDS($Asdu_num=next_num);
	new_BSI_QDS$info_obj_addr = bsi_QDS$info_obj_addr;
	new_BSI_QDS$bsi = bsi_QDS$bsi;
	new_BSI_QDS$qds = bsi_QDS$qds;
	
	Log::write(iec104::LOG_BSI_QDS, new_BSI_QDS);
}

event iec104::BSI_QDS_CP56Time2a_evt(c: connection, bsi_QDS_CP56Time2a: BSI_QDS_CP56Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |BSI_QDS_CP56Time2a_vec| + 1;
	
	BSI_QDS_CP56Time2a_temp += next_num;
	BSI_QDS_CP56Time2a_vec += next_num;
	
	local new_BSI_QDS_CP56Time2a = BSI_QDS_CP56Time2a($Asdu_num=next_num);
	new_BSI_QDS_CP56Time2a$info_obj_addr = bsi_QDS_CP56Time2a$info_obj_addr;
	new_BSI_QDS_CP56Time2a$bsi = bsi_QDS_CP56Time2a$bsi;
	new_BSI_QDS_CP56Time2a$qds = bsi_QDS_CP56Time2a$qds;
	new_BSI_QDS_CP56Time2a$CP56Time2a = bsi_QDS_CP56Time2a$CP56Time2a;
	
	Log::write(iec104::LOG_BSI_QDS_CP56Time2a, new_BSI_QDS_CP56Time2a);
}


event iec104::BSI_QDS_CP24Time2a_evt(c: connection, bsi_QDS_CP24Time2a: BSI_QDS_CP24Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |BSI_QDS_CP24Time2a_vec| + 1;
	
	BSI_QDS_CP24Time2a_temp += next_num;
	BSI_QDS_CP24Time2a_vec += next_num;
	
	local new_BSI_QDS_CP24Time2a = BSI_QDS_CP24Time2a($Asdu_num=next_num);
	new_BSI_QDS_CP24Time2a$info_obj_addr = bsi_QDS_CP24Time2a$info_obj_addr;
	new_BSI_QDS_CP24Time2a$bsi = bsi_QDS_CP24Time2a$bsi;
	new_BSI_QDS_CP24Time2a$qds = bsi_QDS_CP24Time2a$qds;
	new_BSI_QDS_CP24Time2a$CP24Time2a = bsi_QDS_CP24Time2a$CP24Time2a;
	
	Log::write(iec104::LOG_BSI_QDS_CP24Time2a, new_BSI_QDS_CP24Time2a);
}

event iec104::COI_evt(c: connection, coi: COI) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |COI_vec| + 1;
	
	COI_temp += next_num;
	COI_vec += next_num;
	
	local new_coi = COI($Asdu_num=next_num);
	new_coi$info_obj_addr = coi$info_obj_addr;
	new_coi$coi = coi$coi;
	
	Log::write(iec104::LOG_COI, new_coi);
}

event iec104::NVA_QDS_CP56Time2a_evt(c: connection, nva_QDS_CP56Time2a: NVA_QDS_CP56Time2a) {
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |NVA_QDS_CP56Time2a_vec| + 1;
	
	NVA_QDS_CP56Time2a_temp += next_num;
	NVA_QDS_CP56Time2a_vec += next_num;
	
	local new_NVA_QDS_CP56Time2a = NVA_QDS_CP56Time2a($Asdu_num=next_num);
	new_NVA_QDS_CP56Time2a$info_obj_addr = nva_QDS_CP56Time2a$info_obj_addr;
	new_NVA_QDS_CP56Time2a$NVA = nva_QDS_CP56Time2a$NVA;
	new_NVA_QDS_CP56Time2a$qds = nva_QDS_CP56Time2a$qds;
	new_NVA_QDS_CP56Time2a$CP56Time2a = nva_QDS_CP56Time2a$CP56Time2a;
	
	Log::write(iec104::LOG_NVA_QDS_CP56Time2a, new_NVA_QDS_CP56Time2a);	
}

event iec104::NVA_QDS_CP24Time2a_evt(c: connection, nva_QDS_CP24Time2a: NVA_QDS_CP24Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |NVA_QDS_CP24Time2a_vec| + 1;
	
	NVA_QDS_CP24Time2a_temp += next_num;
	NVA_QDS_CP24Time2a_vec += next_num;
	
	local new_NVA_QDS_CP24Time2a = NVA_QDS_CP24Time2a($Asdu_num=next_num);
	new_NVA_QDS_CP24Time2a$info_obj_addr = nva_QDS_CP24Time2a$info_obj_addr;
	new_NVA_QDS_CP24Time2a$NVA = nva_QDS_CP24Time2a$NVA;
	new_NVA_QDS_CP24Time2a$qds = nva_QDS_CP24Time2a$qds;
	new_NVA_QDS_CP24Time2a$CP24Time2a = nva_QDS_CP24Time2a$CP24Time2a;
	
	Log::write(iec104::LOG_NVA_QDS_CP24Time2a, new_NVA_QDS_CP24Time2a);	
}

event iec104::SVA_QDS_CP24Time2a_evt(c: connection, sva_QDS_CP24Time2a: SVA_QDS_CP24Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |SVA_QDS_CP24Time2a_vec| + 1;
	
	SVA_QDS_CP24Time2a_temp += next_num;
	SVA_QDS_CP24Time2a_vec += next_num;
	
	local new_SVA_QDS_CP24Time2a = SVA_QDS_CP24Time2a($Asdu_num=next_num);
	new_SVA_QDS_CP24Time2a$info_obj_addr = sva_QDS_CP24Time2a$info_obj_addr;
	new_SVA_QDS_CP24Time2a$SVA = sva_QDS_CP24Time2a$SVA;
	new_SVA_QDS_CP24Time2a$qds = sva_QDS_CP24Time2a$qds;
	new_SVA_QDS_CP24Time2a$CP24Time2a = sva_QDS_CP24Time2a$CP24Time2a;
	
	Log::write(iec104::LOG_SVA_QDS_CP24Time2a, new_SVA_QDS_CP24Time2a);	
}

event iec104::SVA_QDS_CP56Time2a_evt(c: connection, sva_QDS_CP56Time2a: SVA_QDS_CP56Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |SVA_QDS_CP56Time2a_vec| + 1;
	
	SVA_QDS_CP56Time2a_temp += next_num;
	SVA_QDS_CP56Time2a_vec += next_num;
	
	local new_SVA_QDS_CP56Time2a = SVA_QDS_CP56Time2a($Asdu_num=next_num);
	new_SVA_QDS_CP56Time2a$info_obj_addr = sva_QDS_CP56Time2a$info_obj_addr;
	new_SVA_QDS_CP56Time2a$SVA = sva_QDS_CP56Time2a$SVA;
	new_SVA_QDS_CP56Time2a$qds = sva_QDS_CP56Time2a$qds;
	new_SVA_QDS_CP56Time2a$CP56Time2a = sva_QDS_CP56Time2a$CP56Time2a;
	
	Log::write(iec104::LOG_SVA_QDS_CP56Time2a, new_SVA_QDS_CP56Time2a);
}

event iec104::IEEE_754_QDS_CP56Time2a_evt(c: connection, ieee_754_QDS_CP56Time2a: IEEE_754_QDS_CP56Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |IEEE_754_QDS_CP56Time2a_vec| + 1;
	
	IEEE_754_QDS_CP56Time2a_temp += next_num;
	IEEE_754_QDS_CP56Time2a_vec += next_num;
	
	local new_IEEE_754_QDS_CP56Time2a = IEEE_754_QDS_CP56Time2a($Asdu_num=next_num);
	new_IEEE_754_QDS_CP56Time2a$info_obj_addr = ieee_754_QDS_CP56Time2a$info_obj_addr;
	new_IEEE_754_QDS_CP56Time2a$value = ieee_754_QDS_CP56Time2a$value;
	new_IEEE_754_QDS_CP56Time2a$qds = ieee_754_QDS_CP56Time2a$qds;
	new_IEEE_754_QDS_CP56Time2a$CP56Time2a = ieee_754_QDS_CP56Time2a$CP56Time2a;
	
	Log::write(iec104::LOG_IEEE_754_QDS_CP56Time2a, new_IEEE_754_QDS_CP56Time2a);
}

event iec104::IEEE_754_QDS_CP24Time2a_evt(c: connection, ieee_754_QDS_CP24Time2a: IEEE_754_QDS_CP24Time2a) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |IEEE_754_QDS_CP24Time2a_vec| + 1;
	
	IEEE_754_QDS_CP24Time2a_temp += next_num;
	IEEE_754_QDS_CP24Time2a_vec += next_num;
	
	local new_IEEE_754_QDS_CP24Time2a = IEEE_754_QDS_CP24Time2a($Asdu_num=next_num);
	new_IEEE_754_QDS_CP24Time2a$info_obj_addr = ieee_754_QDS_CP24Time2a$info_obj_addr;
	new_IEEE_754_QDS_CP24Time2a$value = ieee_754_QDS_CP24Time2a$value;
	new_IEEE_754_QDS_CP24Time2a$qds = ieee_754_QDS_CP24Time2a$qds;
	new_IEEE_754_QDS_CP24Time2a$CP24Time2a = ieee_754_QDS_CP24Time2a$CP24Time2a;
	
	Log::write(iec104::LOG_IEEE_754_QDS_CP24Time2a, new_IEEE_754_QDS_CP24Time2a);
}

event iec104::Read_Command_client_evt(c: connection, read_Command_client: Read_Command_client) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |Read_Command_client_vec| + 1;
	
	Read_Command_client_temp += next_num;
	Read_Command_client_vec += next_num;
	
	local new_Read_Command_client = Read_Command_client($Asdu_num=next_num);
	new_Read_Command_client$info_obj_addr = read_Command_client$info_obj_addr;
	new_Read_Command_client$raw_data = read_Command_client$raw_data;
	
	Log::write(iec104::LOG_Read_Command_client, new_Read_Command_client);
}


event iec104::Read_Command_server_evt(c: connection, read_Command_server: Read_Command_server) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |Read_Command_server_vec| + 1;
	
	Read_Command_server_temp += next_num;
	Read_Command_server_vec += next_num;
	
	local new_Read_Command_server = Read_Command_server($Asdu_num=next_num);
	new_Read_Command_server$info_obj_addr = read_Command_server$info_obj_addr;
	
	Log::write(iec104::LOG_Read_Command_server, new_Read_Command_server);
}


event iec104::QRP_client_evt(c: connection, qrp_client: QRP_client) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |QRP_client_vec| + 1;
	
	QRP_client_temp += next_num;
	QRP_client_vec += next_num;
	
	local new_QRP_client = QRP_client($Asdu_num=next_num);
	new_QRP_client$info_obj_addr = qrp_client$info_obj_addr;
	new_QRP_client$raw_data = qrp_client$raw_data;
	
	Log::write(iec104::LOG_QRP_client, new_QRP_client);
}


event iec104::QRP_server_evt(c: connection, qrp_server: QRP_server) {
	
	if (! c?$iec104 ) {
		
		local cur_time  = current_time();
		local default_iec104: Info = [$ts=cur_time, $uid=""];
		
		c$iec104 = default_iec104;
	}

	local info = c$iec104;
	info$asdu = Asdu();

	local next_num: count;
	next_num = |QRP_server_vec| + 1;
	
	QRP_server_temp += next_num;
	QRP_server_vec += next_num;
	
	local new_QRP_server = QRP_server($Asdu_num=next_num);
	new_QRP_server$info_obj_addr = qrp_server$info_obj_addr;
	
	Log::write(iec104::LOG_QRP_server, new_QRP_server);
}




event connection_state_remove(c: connection) &priority=-5
	{
	# TODO: For UDP protocols, you may want to do this after every request
	# and/or reply.
	#emit_log(c);
	}