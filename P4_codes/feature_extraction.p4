/*-----------------Main-----------------*/ 
#include <core.p4>
#include <dpdk/pna.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<32> MAXIMUM_REGISTER_ENTRIES = 66536;

/*************************************************************************
*********************** H E A D E R S ************************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> diff_len_t;         
typedef bit<16> packet_len_t;            
typedef bit<32> timestamp_t;   
typedef bit<16> packet_count_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen; 
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/* TCP header */
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
    bit<16> length;
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

struct metadata {
    bit<16> flow_id;
    diff_len_t diffLen;
    diff_len_t last_packet_len;
    diff_len_t min_diff_length;
    diff_len_t min_diff_length_tmp;
    diff_len_t max_diff_length;
    diff_len_t max_diff_length_tmp;
    packet_len_t min_packet_length;
    packet_len_t max_packet_length;
    packet_len_t packet_length_range; 
    packet_len_t packet_length_total;    
    packet_count_t pkt_count;
    timestamp_t flow_duration;

    packet_len_t first4_len_sum;
    packet_len_t last4_len_sum;

    timestamp_t interarrival_value;
    timestamp_t last_timestamp;
    timestamp_t current_timestamp;
    timestamp_t intermediate_min_IAT;
    timestamp_t intermediate_max_IAT;
    timestamp_t min_IAT;
    timestamp_t max_IAT;
    timestamp_t IAT_range;
    timestamp_t ts_1;
    timestamp_t ts_2;
    bit<3> key;
}

struct headers {
    ethernet_t                ethernet;
    ipv4_t                    ipv4;
    tcp_t                     tcp;
    udp_t                     udp;
    extracted_features_t      extracted_features;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out       headers hdr,
                inout     metadata meta,
                in        pna_main_parser_input_metadata_t istd) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default  : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*-----------------Pre-control-----------------*/
control PreControl(
    in    headers  hdr,
    inout metadata meta,
    in    pna_pre_input_metadata_t  istd,
    inout pna_pre_output_metadata_t ostd)
{
    apply { }
}

/*-----------------Control-----------------*/
control MainControl(
    inout headers hdr,
    inout metadata meta,
    in    pna_main_input_metadata_t istd,
    inout pna_main_output_metadata_t ostd){    
    
    action drop () {
        drop_packet();
    }


    Hash<bit<16>> (PNA_HashAlgorithm_t.CRC16) hash;
    Register<bit<16>, bit<1>>(1) reg_flow_index;
    Register<packet_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_min_packet_length;
    Register<packet_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_max_packet_length;
    Register<bit<16>, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_flowid_dbg; // one slot to store last computed flow_id

    Register<packet_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_packet_length_range;
    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_flow_duration;

    // 16-bit sum of packets 1..4
    Register<packet_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_first4_len_sum;

    // 16-bit sum of packets 5..8
    Register<packet_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_last4_len_sum;

    Register<diff_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_min_diff_length;
    Register<diff_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_max_diff_length;
    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_min_IAT;
    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_max_IAT;
    Register<diff_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_last_packet_len;
    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_last_timestamp;
    Register<packet_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_packet_length_total;
    Register<packet_count_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_pkt_count;
    Register<diff_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_min_diff_lgt;
    Register<diff_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_max_diff_lgt;
    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_min_IATT;
    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_max_IATT;
    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_iat_range;

    Register<packet_len_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_packet_length_ttl;
    Register<bit<1>, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_classified_flag;

    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_ts_1;
    Register<timestamp_t, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_ts_2;
    Register<bit<3>, bit<16>>(MAXIMUM_REGISTER_ENTRIES) reg_key;

    action compute_flow_id() {
        meta.flow_id = hash.get_hash((bit<16>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort}, (bit<16>)32768);
    }

    // Action to calculate the difference between current and previous packet length
    action get_diff_len_1() {
        meta.last_packet_len = reg_last_packet_len.read((bit<16>) meta.flow_id);
        if (meta.pkt_count > 1) {
            if (meta.last_packet_len > (diff_len_t)hdr.ipv4.totalLen) {
                meta.diffLen = meta.last_packet_len - (diff_len_t)hdr.ipv4.totalLen;
            } else {
                meta.diffLen = (diff_len_t)hdr.ipv4.totalLen - meta.last_packet_len;
            }
        }
    }
    
    // Store the current length into register for next diff
    action get_diff_len_2() {
        reg_last_packet_len.write((bit<16>) meta.flow_id, (diff_len_t)hdr.ipv4.totalLen);
    }
    
    // Initialize register on 1st packet
    action reset_diff_len_registers() {
        reg_min_diff_length.write((bit<16>) meta.flow_id, 0);
        reg_max_diff_length.write((bit<16>) meta.flow_id, 0);
        reg_last_packet_len.write((bit<16>) meta.flow_id, (diff_len_t)hdr.ipv4.totalLen);
    }
    
    // Track minimum packet length difference
    action get_min_diff_len() {
        meta.min_diff_length_tmp = reg_min_diff_length.read((bit<16>) meta.flow_id);
    
        if (meta.pkt_count == 2) {
            // Always set min_diff from the first difference
            reg_min_diff_length.write((bit<16>) meta.flow_id, meta.diffLen);
            meta.min_diff_length = meta.diffLen;
        } else if (meta.pkt_count > 2) {
            if (meta.diffLen < meta.min_diff_length_tmp) {
                reg_min_diff_length.write((bit<16>) meta.flow_id, meta.diffLen);
                meta.min_diff_length = meta.diffLen;
            } else {
                meta.min_diff_length = meta.min_diff_length_tmp;
            }
        }
    }
    
    // Track maximum packet length difference
    action get_max_diff_len() {
        meta.max_diff_length_tmp = reg_max_diff_length.read((bit<16>) meta.flow_id);
    
        if (meta.pkt_count == 2) {
            reg_max_diff_length.write((bit<16>) meta.flow_id, meta.diffLen);
            meta.max_diff_length = meta.diffLen;
        } else if (meta.pkt_count > 2) {
            if (meta.diffLen > meta.max_diff_length_tmp) {
                reg_max_diff_length.write((bit<16>) meta.flow_id, meta.diffLen);
                meta.max_diff_length = meta.diffLen;
            } else {
                meta.max_diff_length = meta.max_diff_length_tmp;
            }
        }
    }

    action get_min_packet_length() {
        meta.min_packet_length = reg_min_packet_length.read((bit<16>) meta.flow_id);

        if (meta.pkt_count > 1) {
            if (hdr.ipv4.totalLen < meta.min_packet_length) {
                reg_min_packet_length.write((bit<16>) meta.flow_id, (packet_len_t) hdr.ipv4.totalLen);
                meta.min_packet_length = (packet_len_t) hdr.ipv4.totalLen;
            } else {
                reg_min_packet_length.write((bit<16>) meta.flow_id, meta.min_packet_length);
            }
        }
    }

    action get_max_packet_length() {
        meta.max_packet_length = reg_max_packet_length.read((bit<16>) meta.flow_id);

        if (meta.pkt_count > 1) {
            if (hdr.ipv4.totalLen > meta.max_packet_length) {
                reg_max_packet_length.write((bit<16>) meta.flow_id, (packet_len_t) hdr.ipv4.totalLen);
                meta.max_packet_length = (packet_len_t) hdr.ipv4.totalLen;
            } else {
                reg_max_packet_length.write((bit<16>) meta.flow_id, meta.max_packet_length);
            }
        }
    }

    action get_total_len() {
        packet_len_t packet_length_total = reg_packet_length_total.read((bit<16>) meta.flow_id);
        meta.packet_length_total = packet_length_total + (bit<16>)hdr.ipv4.totalLen;
        reg_packet_length_total.write((bit<16>) meta.flow_id, meta.packet_length_total);
    }
    
    action get_last_ts() {
        meta.last_timestamp = reg_last_timestamp.read((bit<16>) meta.flow_id);        
    }
    action update_last_ts() {
        reg_last_timestamp.write((bit<16>) meta.flow_id, meta.current_timestamp);
    }
    action calc_iat() { 
        if (meta.last_timestamp != 0) {
            meta.interarrival_value = meta.current_timestamp - meta.last_timestamp;
        }
    }
    action get_last_min_iat() {
        meta.min_IAT = reg_min_IAT.read((bit<16>) meta.flow_id);
    }
    action update_min_iat() {
        if (meta.min_IAT == 0 || meta.interarrival_value < meta.min_IAT) {
            reg_min_IAT.write((bit<16>)meta.flow_id, meta.interarrival_value);
            meta.min_IAT = meta.interarrival_value;
        } 
    }
    action get_last_max_iat() {
        meta.max_IAT = reg_max_IAT.read((bit<16>) meta.flow_id);
    }
    action update_max_iat() {
        if (meta.max_IAT == 0 || meta.interarrival_value > meta.max_IAT) {
            reg_max_IAT.write((bit<16>)meta.flow_id, meta.interarrival_value);
            meta.max_IAT = meta.interarrival_value;
        } 
    }

    action get_iat_range() {
        meta.IAT_range = (timestamp_t)0;

        // if both min and max are zero -> nothing recorded; keep range = 0
        if (meta.min_IAT == 0 && meta.max_IAT == 0) {
            meta.IAT_range = (timestamp_t)0;
        } else {
            // wraparound-safe subtraction:
            if (meta.max_IAT >= meta.min_IAT) {
                meta.IAT_range = (timestamp_t)(meta.max_IAT - meta.min_IAT);
            } else {
                // assume 32-bit rollover: add 2^32 to max before subtracting min
                meta.IAT_range = (timestamp_t)((bit<64>)meta.max_IAT + ((bit<64>)1 << 32) - (bit<64>)meta.min_IAT);
            }
        }

        reg_iat_range.write((bit<16>) meta.flow_id, meta.IAT_range);
    }

    action compute_packet_length_range() {
        meta.min_packet_length = reg_min_packet_length.read((bit<16>) meta.flow_id);
        meta.max_packet_length = reg_max_packet_length.read((bit<16>) meta.flow_id);

        // If either is 0, treat range as 0 (or decide another policy)
        meta.packet_length_range = (packet_len_t)0;

        // Normal subtraction (no realistic wraparound for packet lengths)
        if (meta.max_packet_length >= meta.min_packet_length) {
            meta.packet_length_range = (packet_len_t)(meta.max_packet_length - meta.min_packet_length);
        } else {
            // Defensive: shouldn't happen, but handle it
            meta.packet_length_range = (packet_len_t)0;
        }

        reg_packet_length_range.write((bit<16>) meta.flow_id, meta.packet_length_range);
    }

    action compute_flow_duration() {
        // read persistent endpoints (32-bit timestamps)
        meta.ts_1 = reg_ts_1.read((bit<16>) meta.flow_id);
        meta.ts_2 = reg_ts_2.read((bit<16>) meta.flow_id);

        // wraparound-safe subtraction using 64-bit intermediate
        if (meta.ts_2 >= meta.ts_1) {
            meta.flow_duration = (timestamp_t)(meta.ts_2 - meta.ts_1);
        } else {
            meta.flow_duration = (timestamp_t)(
                (bit<64>)meta.ts_2 + ((bit<64>)1 << 32) - (bit<64>)meta.ts_1
            );
        }

        reg_flow_duration.write((bit<16>) meta.flow_id, meta.flow_duration);
    }

    action get_first4_len_sum() {
        meta.first4_len_sum = reg_first4_len_sum.read((bit<16>)meta.flow_id);
        // accumulate only for packets 1..4
        if (meta.pkt_count <= 4) {
            meta.first4_len_sum = (packet_len_t)(meta.first4_len_sum + (packet_len_t)hdr.ipv4.totalLen); // 16-bit wrap
            reg_first4_len_sum.write((bit<16>)meta.flow_id, meta.first4_len_sum);
        }
    }

    action get_last4_len_sum() {
        meta.last4_len_sum = reg_last4_len_sum.read((bit<16>)meta.flow_id);
        // accumulate only for packets 5..8
        if (meta.pkt_count >= 5 && meta.pkt_count <= 8) {
            meta.last4_len_sum = (packet_len_t)(meta.last4_len_sum + (packet_len_t)hdr.ipv4.totalLen); // 16-bit wrap
            reg_last4_len_sum.write((bit<16>)meta.flow_id, meta.last4_len_sum);
        }
    }

    apply {
        meta.current_timestamp = ((bit<64>)istd.timestamp)[31:0];
        if (hdr.ipv4.isValid() && hdr.udp.isValid()) {
            compute_flow_id();
    
            bit<1> already_classified = reg_classified_flag.read(meta.flow_id);
            if (already_classified == 1) {
                // Already classified: forward directly or drop
                send_to_port((PortId_t) 1); // Or drop();
                return;
            }
    
            // Retrieve and increment packet count
            meta.pkt_count = reg_pkt_count.read(meta.flow_id);
            meta.pkt_count  = meta.pkt_count  + 1;
            reg_pkt_count.write(meta.flow_id, meta.pkt_count);

            if (meta.pkt_count == 1) {
                reset_diff_len_registers(); // initialize on first packet

                reg_min_packet_length.write((bit<16>) meta.flow_id, (packet_len_t) hdr.ipv4.totalLen);                 // initialize min packet length on first packet
                reg_max_packet_length.write((bit<16>) meta.flow_id, (packet_len_t) hdr.ipv4.totalLen);                 // initialize max packet length on first packet

                reg_first4_len_sum.write((bit<16>)meta.flow_id, (packet_len_t)0);                                      // initialize first 4 sum   
                reg_last4_len_sum.write((bit<16>)meta.flow_id, (packet_len_t)0);                                       // initialize last 4 sum

                meta.key = reg_key.read((bit<16>)meta.flow_id);
                reg_packet_length_total.write(meta.flow_id, hdr.ipv4.totalLen);

                if (meta.key == 0){
                    meta.ts_1 = ((bit<64>)istd.timestamp)[31:0];
                    reg_ts_1.write((bit<16>) meta.flow_id, meta.ts_1);
                    meta.key =1;
                    reg_key.write(meta.flow_id, meta.key);
                }
            } else {
                // add subsequent packets
                get_total_len();   // reads reg, adds hdr.ipv4.totalLen, writes back
            }

            // Calculate flow features 
            get_min_packet_length();
            get_max_packet_length();

            get_first4_len_sum();
            get_diff_len_1();
            get_diff_len_2();
            get_min_diff_len();
            get_max_diff_len();
    
            get_last_ts();
            update_last_ts();
            calc_iat();
            get_last_min_iat();
            update_min_iat();
            get_last_max_iat();
            update_max_iat();
            
            // just before

            // call the function
            get_last4_len_sum();

            // just after

            if (istd.input_port == (PortId_t) 1) {
                reg_flow_index.write(0, meta.flow_id); // Debugging only
    
                if (meta.pkt_count == 8) {
                    // Store final extracted features
                    
                    meta.key = reg_key.read((bit<16>)meta.flow_id);
                    if(meta.key == 1) {
                        meta.ts_2 = ((bit<64>)istd.timestamp)[31:0];
                        reg_ts_2.write((bit<16>) meta.flow_id, meta.ts_2);
                        meta.key = 0;
                        reg_key.write(meta.flow_id, meta.key);
                    }
                    
                    get_iat_range();
                    compute_packet_length_range();
                    compute_flow_duration();

                    hdr.extracted_features.setValid();

                    hdr.extracted_features.flow_id = meta.flow_id;

                    hdr.extracted_features.min_packet_length = meta.min_packet_length;
                    hdr.extracted_features.max_packet_length = meta.max_packet_length;

                    hdr.extracted_features.first4_len_sum = meta.first4_len_sum;
                    hdr.extracted_features.last4_len_sum = meta.last4_len_sum;

                    hdr.extracted_features.packet_length_range = meta.packet_length_range;

                    hdr.extracted_features.min_diff_length = meta.min_diff_length;

                    hdr.extracted_features.min_IAT = meta.min_IAT;
                    hdr.extracted_features.max_IAT = meta.max_IAT;
                    hdr.extracted_features.IAT_range = meta.IAT_range;

                    hdr.extracted_features.flow_duration = meta.flow_duration;
                    
                    hdr.extracted_features.max_diff_length = meta.max_diff_length;
                    hdr.extracted_features.packet_length_total = meta.packet_length_total;
                    hdr.extracted_features.original_dst_port = hdr.udp.dstPort;
                    hdr.extracted_features.last_timestamp = meta.last_timestamp;
                    hdr.extracted_features.current_timestamp = meta.current_timestamp;

                    reg_classified_flag.write(meta.flow_id, 1);
    
                    hdr.udp.dstPort = 9999;
                    
                    reg_flowid_dbg.write((bit<16>)10, (bit<16>) meta.flow_id); 
                    reg_flowid_dbg.write((bit<16>)11, (bit<16>) hdr.extracted_features.flow_id);

                    send_to_port((PortId_t) 0);
                    reg_pkt_count.write(meta.flow_id, 0);
                } else {
                    send_to_port((PortId_t) 1);
                }
            } else if (istd.input_port == (PortId_t) 0) {
                bit<32> tmp_ip = hdr.ipv4.srcAddr;
                hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                hdr.ipv4.dstAddr = tmp_ip;
                
                bit<48> tmp_mac = hdr.ethernet.srcAddr;
                hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                hdr.ethernet.dstAddr = tmp_mac;
                
                send_to_port((PortId_t) 1);
            }
        } else {
            drop();
        }
    }
}

/*-----------------Deparser-----------------*/
control MyDeparser(
    packet_out packet,
    inout      headers hdr,
    in         metadata meta,
    in         pna_main_output_metadata_t ostd)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);    
        packet.emit(hdr.udp);    
        packet.emit(hdr.extracted_features);  
    }   
}

PNA_NIC(
    MyParser(),
    PreControl(),
    MainControl(),
    MyDeparser()
) main;