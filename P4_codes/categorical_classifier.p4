#include <core.p4>
#include <dpdk/pna.p4>

typedef bit<9>  egressSpec_t; 
typedef bit<48> macAddr_t; 
typedef bit<32> ip4Addr_t; 
typedef bit<32> diff_len_t;          
typedef bit<16> packet_len_t;             
typedef bit<32> timestamp_t;    
typedef bit<16> packet_count_t; 
typedef bit<32> inference_result_t;    // Final classification

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<32> MAXIMUM_REGISTER_ENTRIES = 65536;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/* UDP header */
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header extracted_features_t {
    diff_len_t  min_diff_length;
    diff_len_t  max_diff_length;
    packet_len_t min_packet_length;
    packet_len_t max_packet_length;

    packet_len_t packet_length_range;
    timestamp_t flow_duration;

    packet_len_t first4_len_sum;
    packet_len_t last4_len_sum;

    timestamp_t min_IAT;
    timestamp_t max_IAT;
    timestamp_t IAT_range;
    packet_len_t  packet_length_total;
    bit<16>     original_dst_port;
    bit<16>     flow_id;
    timestamp_t last_timestamp;
    timestamp_t current_timestamp;
}

header classification_result_t {
    inference_result_t ml_result;
    inference_result_t app_result;
}

struct metadata {
    inference_result_t ml_result;
    bit<3> class0;
    bit<3> class1;
    bit<3> class2;

    //-------------------------- Codeword 0
    bit<1> codeword0_1_0;
    bit<4> codeword0_1_1;
    bit<4> codeword0_1_2;
    bit<3> codeword0_1_4;
    bit<1> codeword0_1_5;
    bit<5> codeword0_1_6;
    bit<1> codeword0_1_7;

    //-------------------------- Codeword 1
    bit<3> codeword1_1_1;
    bit<4> codeword1_1_2;
    bit<2> codeword1_1_3;
    bit<6> codeword1_1_4;
    bit<2> codeword1_1_6;
    bit<2> codeword1_1_7;

    //-------------------------- Codeword 2
    bit<4> codeword2_1_1;
    bit<4> codeword2_1_2;
    bit<1> codeword2_1_3;
    bit<2> codeword2_1_4;
    bit<3> codeword2_1_5;
    bit<3> codeword2_1_6;
    bit<2> codeword2_1_7;

    bit<3> final_class;

    timestamp_t interarrival_value;
    timestamp_t last_timestamp;
    timestamp_t current_timestamp;
    timestamp_t intermediate_min_IAT;
    timestamp_t intermediate_max_IAT;
    timestamp_t min_IAT;
    timestamp_t max_IAT;

    bit<5> codeword0_1;
    bit<9> codeword0_2;
    bit<12> codeword0_3;
    bit<13> codeword0_5;
    bit<18> codeword0_6;
    bit<19> codeword0_7;

    bit<7> codeword1_2;
    bit<9> codeword1_3;
    bit<15> codeword1_4;
    bit<17> codeword1_6;
    bit<19> codeword1_7;

    bit<8> codeword2_2;
    bit<9> codeword2_3;
    bit<11> codeword2_4;
    bit<14> codeword2_5;
    bit<17> codeword2_6;
    bit<19> codeword2_7;

    timestamp_t ts_1;
    timestamp_t ts_2;
    bit<3> key;
    bit<16> flow_id;
}


struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    extracted_features_t extracted_features;
    classification_result_t   classification_result;
}

control PreControlImpl(
    in    headers_t  hdr,
    inout metadata meta,
    in    pna_pre_input_metadata_t  istd,
    inout pna_pre_output_metadata_t ostd)
{
        apply {}
}

parser MainParserImpl(
    packet_in pkt,
    out   headers_t       hdr,
    inout metadata meta,
    in    pna_main_parser_input_metadata_t istd)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    
    } 
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort) {
           9999: parse_extracted_features;
           default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
           9999: parse_extracted_features;
           default: accept;
        }
    }

    state parse_extracted_features {
       pkt.extract(hdr.extracted_features);
       transition accept;
    }
}

control MainControlImpl(
    inout headers_t       hdr,           // from main parser
    inout metadata meta,     // from main parser, to "next block"
    in    pna_main_input_metadata_t  istd,
    inout pna_main_output_metadata_t ostd)
{   
    action drop() {
        drop_packet();
    }

    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_ts_c_1;
    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_ts_c_2;
    Register<bit<3>, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_key_c;

    Register<bit<16>, bit<16>>(65535) reg_final_class;
    Register<bit<16>, bit<16>>(65535) reg_flow_id;

    action SetCode0(bit<1> code0) {
        meta.codeword0_1_0  = code0;
    }

    table min_diffLen_table{
        key = {
            hdr.extracted_features.min_diff_length: ternary;
        }
        actions = {
            SetCode0;
            NoAction;
        }
       size = 2048;
    }
    action SetCode1(bit<4> code0, bit<3> code1, bit<4> code2) {
        meta.codeword0_1_1  = code0;
        meta.codeword1_1_1  = code1;
        meta.codeword2_1_1  = code2;
    }

    table min_packetLen_table{
        key = {
            hdr.extracted_features.min_packet_length: ternary;
        }
        actions = {
            SetCode1;
            NoAction;
        }
       size = 2048;
    }

    action SetCode2(bit<4> code0, bit<4> code1, bit<4> code2) {
        meta.codeword0_1_2  = code0;
        meta.codeword1_1_2  = code1;
        meta.codeword2_1_2  = code2;
    }

    table max_packetLen_table{
        key = {
            hdr.extracted_features.max_packet_length: ternary;
        }
        actions = {
            SetCode2;
            NoAction;
        }
       size = 2048;
    }

    action SetCode3(bit<2> code1, bit<1> code2) {
        meta.codeword1_1_3  = code1;
        meta.codeword2_1_3  = code2;
    }

    table flow_duration_table{
        key = {
            hdr.extracted_features.flow_duration: ternary;
        }
        actions = {
            SetCode3;
            NoAction;
        }
       size = 2048;
    }

    action SetCode4(bit<3> code0, bit<6> code1, bit<2> code2) {
        meta.codeword0_1_4  = code0;
        meta.codeword1_1_4  = code1;
        meta.codeword2_1_4  = code2;
    }

    table IAT_range_table{
        key = {
            hdr.extracted_features.IAT_range: ternary;
        }
        actions = {
            SetCode4;
            NoAction;
        }
       size = 2048;
    }

    action SetCode5(bit<1> code0, bit<3> code2) {
        meta.codeword0_1_5  = code0;
        meta.codeword2_1_5  = code2;
    }

    table packet_length_range_table{
        key = {
            hdr.extracted_features.packet_length_range: ternary;
        }
        actions = {
            SetCode5;
            NoAction;
        }
       size = 2048;
    }

    action SetCode6(bit<5> code0, bit<2> code1, bit<3> code2) {
        meta.codeword0_1_6  = code0;
        meta.codeword1_1_6  = code1;
        meta.codeword2_1_6  = code2;
    }

    table first4sum_table{
        key = {
            hdr.extracted_features.first4_len_sum: ternary;
        }
        actions = {
            SetCode6;
            NoAction;
        }
       size = 2048;
    }

    action SetCode7(bit<1> code0, bit<2> code1, bit<2> code2) {
        meta.codeword0_1_7  = code0;
        meta.codeword1_1_7  = code1;
        meta.codeword2_1_7  = code2;
    }

    table last4sum_table{
        key = {
            hdr.extracted_features.last4_len_sum: ternary;
        }
        actions = {
            SetCode7;
            NoAction;
        }
       size = 2048;
    }
    action concat_codeword0_1() {
        meta.codeword0_1 = meta.codeword0_1_0 ++ meta.codeword0_1_1; 
    }

    action concat_codeword0_2() {
        meta.codeword0_2 = meta.codeword0_1 ++ meta.codeword0_1_2;
    }

    action concat_codeword0_3() {
        meta.codeword0_3 = meta.codeword0_2 ++ meta.codeword0_1_4;
    }

    action concat_codeword0_5() {
        meta.codeword0_5 = meta.codeword0_3 ++ meta.codeword0_1_5;
    }

    action concat_codeword0_6() {
        meta.codeword0_6 = meta.codeword0_5 ++ meta.codeword0_1_6;
    }

    action concat_codeword0_7() {
        meta.codeword0_7 = meta.codeword0_6++ meta.codeword0_1_7;
    }

    action concat_codeword1_2() {
        meta.codeword1_2 = meta.codeword1_1_1 ++ meta.codeword1_1_2; 
    }
    action concat_codeword1_3() {
        meta.codeword1_3 = meta.codeword1_2 ++ meta.codeword1_1_3;
    }
    action concat_codeword1_4() {
        meta.codeword1_4 = meta.codeword1_3 ++ meta.codeword1_1_4;

    }
    action concat_codeword1_6() {
        meta.codeword1_6 = meta.codeword1_4 ++ meta.codeword1_1_6;
    }
    action concat_codeword1_7() {
        meta.codeword1_7 = meta.codeword1_6 ++ meta.codeword1_1_7;
    }

    action concat_codeword2_2() {
        meta.codeword2_2 = meta.codeword2_1_1 ++ meta.codeword2_1_2; 
    }
    action concat_codeword2_3() {
        meta.codeword2_3 = meta.codeword2_2 ++ meta.codeword2_1_3;
    }
    action concat_codeword2_4() {
        meta.codeword2_4 = meta.codeword2_3 ++ meta.codeword2_1_4;
    }
    action concat_codeword2_5() {
        meta.codeword2_5 = meta.codeword2_4 ++ meta.codeword2_1_5;
    }
    action concat_codeword2_6() {
        meta.codeword2_6 = meta.codeword2_5 ++ meta.codeword2_1_6;
    }
    action concat_codeword2_7() {
        meta.codeword2_7 = meta.codeword2_6 ++ meta.codeword2_1_7;
    }

    action SetClass0(bit<3> class) {
        meta.class0 = class;
    }

    action SetClass1(bit<3> class) {
        meta.class1 = class;
    }

    action SetClass2(bit<3> class) {
        meta.class2 = class;
    }

    table code_table0{
            key = {
            meta.codeword0_7: ternary;
        }

            actions = {
            SetClass0;
            NoAction;
        }
            size = 600;
        }

    table code_table1{
            key = {
            meta.codeword1_7: ternary;
        }
        
            actions = {
            SetClass1;
            NoAction;
        }
            size = 600;
        }

    table code_table2{
            key = {
            meta.codeword2_7: ternary;
        }
        
            actions = {
            SetClass2;
            NoAction;
        }
            size = 600;
        }

    action set_default_result() {
        meta.final_class = meta.class0;
        hdr.classification_result.ml_result = (bit<32>) meta.final_class; 
        hdr.classification_result.setValid(); 
    }

    action set_final_class(bit<3> class_result) {
        meta.final_class = class_result;
        hdr.classification_result.ml_result = (bit<32>) meta.final_class; 
        hdr.classification_result.setValid(); 
    }

    table voting_table {
        key = {
            meta.class0: exact;
            meta.class1: exact;
            meta.class2: exact;
        }
        actions = {
            set_final_class; 
            set_default_result;
        }
        size = 300;
        default_action = set_default_result();
    }

    apply {
        if(hdr.extracted_features.isValid()) {

            meta.key = reg_key_c.read((bit<16>)hdr.extracted_features.flow_id);
            if (meta.key == 0){
                meta.ts_1 = ((bit<64>)istd.timestamp)[31:0];
                reg_ts_c_1.write((bit<16>) hdr.extracted_features.flow_id, meta.ts_1);
                meta.key = 1;
                reg_key_c.write(hdr.extracted_features.flow_id, meta.key);
            }

            min_diffLen_table.apply();
            min_packetLen_table.apply();
            max_packetLen_table.apply();
            flow_duration_table.apply();
            IAT_range_table.apply();
            packet_length_range_table.apply();
            first4sum_table.apply();
            last4sum_table.apply();
            
            concat_codeword0_1();
            concat_codeword0_2();
            concat_codeword0_3();
            concat_codeword0_5();
            concat_codeword0_6();
            concat_codeword0_7();

            concat_codeword1_2();
            concat_codeword1_3();
            concat_codeword1_4();
            concat_codeword1_6();
            concat_codeword1_7();

            concat_codeword2_2();
            concat_codeword2_3();
            concat_codeword2_4();
            concat_codeword2_5();
            concat_codeword2_6();
            concat_codeword2_7();

            // apply code tables to assign labels
            code_table0.apply();
            code_table1.apply();
            code_table2.apply();

            // decide final class
            voting_table.apply();
            
            meta.key = reg_key_c.read((bit<16>)hdr.extracted_features.flow_id);
            if(meta.key == 1) {
                meta.ts_2 = ((bit<64>)istd.timestamp)[31:0];
                reg_ts_c_2.write((bit<16>) hdr.extracted_features.flow_id, meta.ts_2);
                meta.key = 0;
                reg_key_c.write(hdr.extracted_features.flow_id, meta.key);
            }

            reg_flow_id.write((bit<16>) 0, hdr.extracted_features.flow_id);
            reg_final_class.write((bit<16>) hdr.extracted_features.flow_id, (bit<16>)meta.final_class);
        
            // hdr.extracted_features.setInvalid();

            if(meta.final_class == 1) {
                send_to_port((PortId_t) 0); 
            } else if(meta.final_class == 2) {
                send_to_port((PortId_t) 1); 
            }
        } 
    }
}

control MainDeparserImpl(
    packet_out pkt,
    inout    headers_t hdr,                // from main control
    in    metadata user_meta,    // from main control
    in    pna_main_output_metadata_t ostd)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.extracted_features);
        pkt.emit(hdr.classification_result);  
    }
}

PNA_NIC(
    MainParserImpl(),
    PreControlImpl(),
    MainControlImpl(),
    MainDeparserImpl()
    ) main;