/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  HULAPP_PROTOCOL = 254; 
const bit<8>  HULAPP_DATA_PROTOCOL = 253;
const bit<8>  HULAPP_BACKGROUND_PROTOCOL = 252;
const bit<8>  HULAPP_TCP_DATA_PROTOCOL = 251;
const bit<8>  HULAPP_UDP_DATA_PROTOCOL = 250;
const bit<8>  TCP_PROTOCOL = 6;
const bit<8>  UDP_PROTOCOL = 17;
const bit<16> TYPE_IPV4 = 0x0021;
const bit<16> TYPE_ARP  = 0x0806;
const bit<16> TYPE_HULAPP_TCP_DATA = 0x2345;
const bit<16> TYPE_HULAPP_UDP_DATA = 0x2344;
const bit<48> FLOWLET_TIMEOUT = 60000;
const bit<48> LINK_TIMEOUT = 200000;
#define TAU_EXPONENT 17 // twice the probe frequency. if probe freq = 1024*64 microsec, the TAU should be 1024*128 microsec, and the TAU_EXPONENT would be 17
const bit<64> UTIL_RESET_TIME_THRESHOLD = 65536;

#define NUM_DSTS 4
#define MAX_NUM_PATHS 32
#define NUM_ENTRIES 1024

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ppp_t {
    bit<16>   pppType;
}

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;

const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    macAddr_t  sha;
    ip4Addr_t spa;
    macAddr_t  tha;
    ip4Addr_t tpa;
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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

//Background traffic
header hulapp_background_t {
    bit<32> port;
}

header hulapp_t {
    bit<16>  pathId;   // pathID
    bit<16>  src_tor;  // traffic src (or probe dst)
    bit<16>  dst_tor;  // traffic dst (or probe src)
    bit<64>  util;     // The path util
}

header hulapp_data_t {
    bit<16>  pathId;
}

struct metadata {
    ip4Addr_t          ipv4DstAddr;
    ip4Addr_t          ipv4SrcAddr;
    bit<9>             outbound_port;
    bit<16>            src_switch_id;
    bit<16>            dst_switch_id;

    bit<16>            pathId;
    bit<32>            hash_ecmp_index;

    bit<16>            util_exp;
    bit<64>            util_mantissa;
    bit<32>            weight_mantissa;  // number of bits required depends on maxWeight*numberOfPaths*numOfEntries

    bit<32>            w0;
    bit<32>            w1;
    bit<32>            w2;
    bit<32>            w3;
    bit<32>            s;
    bit<16>            t0;
    bit<16>            t1;
    bit<16>            t2;
    bit<16>            t3;
    bit<16>            w0_exp;
    bit<16>            w1_exp;
    bit<16>            w2_exp;
    bit<16>            w3_exp;
    bit<16>            s_exp;
    bit<16>            t0_exp;
    bit<16>            t1_exp;
    bit<16>            t2_exp;
    bit<16>            t3_exp;
    bit<32>            w0_mantissa;
    bit<32>            w1_mantissa;
    bit<32>            w2_mantissa;
    bit<32>            w3_mantissa;
    bit<32>            s_mantissa;
    bit<16>            t0_mantissa;
    bit<16>            t1_mantissa;
    bit<16>            t2_mantissa;
    bit<16>            t3_mantissa;

    bit<16>            dst_tor;
    bit<9>             debug_probe_port;
    bit<16>            debug_probe_dst_tor;
    bit<16>            debug_probe_src_tor;
    bit<16>            debug_probe_pathId;
    bit<32>            debug_probe_w;
    bit<64>            debug_probe_util;
    bit<48>            debug_probe_time;
    bit<9>             debug_pkt_ingress_port;
    bit<9>             debug_pkt_egress_port;
    bit<32>            debug_pkt_fidx;
    bool               debug_pkt_flowlet_create;
    bool               debug_pkt_flowlet_cached;
    bool               debug_pkt_flowlet_thrash;
    bit<64>            debug_pkt_util;
    bool               debug_pkt_deficit;
    bool               debug_pkt_excess;
    bit<32>            debug_pkt_s;
    bit<48>            debug_pkt_time;
    bit<32>            debug_pkt_w0;
    bit<32>            debug_pkt_w1;
    bit<32>            debug_pkt_w2;
    bit<32>            debug_pkt_w3;
    bit<32>            debug_pkt_w4;
    bit<16>            debug_pkt_i;
    bit<16>            debug_pkt_t0;
    bit<16>            debug_pkt_t1;
    bit<16>            debug_pkt_t2;
    bit<16>            debug_pkt_t3;
    bit<16>            debug_pkt_t4;
    bit<16>            debug_pkt_dst;
}

//The headers used in Hula++
struct headers {
    ethernet_t          ethernet;
    ppp_t               ppp;
    ipv4_t              ipv4;
    hulapp_background_t hulapp_background;
    hulapp_t            hulapp;
    hulapp_data_t       hulapp_data;
    arp_t               arp;
    arp_ipv4_t          arp_ipv4;
    tcp_t               tcp;
    udp_t               udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in packet,
out headers hdr,
inout metadata meta,
inout standard_metadata_t standard_metadata) {

    state start {
//        transition parse_ethernet;
        transition parse_ppp;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4            : parse_ipv4;
            TYPE_ARP             : parse_arp;
            _                    : accept;
        }
    }

    state parse_ppp {
        packet.extract(hdr.ppp);
        transition select(hdr.ppp.pppType) {
            TYPE_IPV4            : parse_ipv4;
            _                    : accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.ipv4DstAddr = hdr.arp_ipv4.tpa;
        meta.ipv4SrcAddr = hdr.arp_ipv4.spa;
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.ipv4DstAddr = hdr.ipv4.dstAddr;
        meta.ipv4SrcAddr = hdr.ipv4.srcAddr;
        transition select (hdr.ipv4.protocol) {
            HULAPP_PROTOCOL            : parse_hulapp;
            HULAPP_TCP_DATA_PROTOCOL   : parse_hulapp_data;
            HULAPP_UDP_DATA_PROTOCOL   : parse_hulapp_data;
            HULAPP_DATA_PROTOCOL       : parse_hulapp_data;
            HULAPP_BACKGROUND_PROTOCOL : parse_hulapp_background;
            TCP_PROTOCOL               : parse_tcp;
            UDP_PROTOCOL               : parse_udp;
            _                          : accept;
        }
    }

    state parse_hulapp_background {
        packet.extract(hdr.hulapp_background);
        transition accept;
    }

    state parse_hulapp_data {
        packet.extract(hdr.hulapp_data);
        transition select (hdr.ipv4.protocol) {
            HULAPP_TCP_DATA_PROTOCOL : parse_tcp;
            HULAPP_UDP_DATA_PROTOCOL : parse_udp;
            _                        : accept;
        }
    }

    state parse_hulapp {
        packet.extract(hdr.hulapp);
        transition accept;
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

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    register<bit<16>>(1) currentid;

    // weight table
    // TODO: path vector source routing instead
    register<bit<32>>(NUM_DSTS) weight0;        // mapping from pathId to weight
    register<bit<32>>(NUM_DSTS) weight1;        // mapping from pathId to weight
    register<bit<32>>(NUM_DSTS) weight2;        // mapping from pathId to weight
    register<bit<32>>(NUM_DSTS) weight3;        // mapping from pathId to weight
    register<bit<32>>(NUM_DSTS) weight4;        // mapping from pathId to weight
    register<bit<32>>(NUM_DSTS) weight5;        // mapping from pathId to weight
    register<bit<32>>(NUM_DSTS) weight6;        // mapping from pathId to weight
    register<bit<32>>(NUM_DSTS) weight7;        // mapping from pathId to weight
    register<bit<16>>(NUM_DSTS) range0;         // HashBucket range
    register<bit<16>>(NUM_DSTS) range1;         // HashBucket range
    register<bit<16>>(NUM_DSTS) range2;         // HashBucket range
    register<bit<16>>(NUM_DSTS) range3;         // HashBucket range
    register<bit<16>>(NUM_DSTS) range4;         // HashBucket range
    register<bit<16>>(NUM_DSTS) range5;         // HashBucket range
    register<bit<16>>(NUM_DSTS) range6;         // HashBucket range
    register<bit<16>>(NUM_DSTS) range7;         // HashBucket range
    register<bit<32>>(NUM_DSTS) sumWeight;

    // Flowlet routing table
    register<bit<16>>(1024) flowlet_pathId;     // Flowlet pathId
    register<bit<32>>(1024) flowlet_dst;       // Flowlet destination
    register<bit<48>>(1024) flowlet_time;      // Flowlet time of last packet

    // PathTable for Failure Detection
    register<bit<48>>(MAX_NUM_PATHS*NUM_DSTS) path_time;              // time of last probe using the path

    // Metric util
    register<bit<64>>(5) local_util;     // Local util per port.
    register<bit<48>>(5) last_packet_time;

/*----------------------------------------------------------------------*/
/*Some basic actions*/

    action drop() {
        mark_to_drop();
    }

    action add_hulapp_header() {
        hdr.hulapp.setValid();
        //An extra hop in the probe takes up 16bits, or 1 word.
        hdr.ipv4.ihl = hdr.ipv4.ihl + 1;
    }

/*----------------------------------------------------------------------*/
/*Forward traffic based on pathId*/

    action set_forward_port(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table tab_traffic_forward {
        key = {
            meta.src_switch_id    : ternary;
            meta.dst_switch_id    : exact;
            hdr.hulapp_data.pathId: exact;
        }
        actions = {
          set_forward_port;
          drop; 
          NoAction; 
        }
        default_action = drop();
    }

/*----------------------------------------------------------------------*/
/* Get path from Hash */

    action get_path_from_hash() {
        bit<16> hash_ecmp_index = (bit<16>) meta.hash_ecmp_index;
        bit<16>  pathId;
        bit<16> tmpRange0;
        bit<16> tmpRange1;
        bit<16> tmpRange2;
//        bit<16> tmpRange3;
        range0.read(tmpRange0, (bit<32>) meta.dst_switch_id);
        range1.read(tmpRange1, (bit<32>) meta.dst_switch_id);
        range2.read(tmpRange2, (bit<32>) meta.dst_switch_id);
//        range3.read(tmpRange3, (bit<32>) meta.dst_switch_id);
        if (hash_ecmp_index < tmpRange0) {
            pathId = 0;
        } else if (hash_ecmp_index < tmpRange1) {
            pathId = 1;
        } else if (hash_ecmp_index < tmpRange2) {
            pathId = 2;
//        } else if (hash_ecmp_index < tmpRange3) {
        } else {
            pathId = 3;
        }
        meta.pathId = pathId;
    }

    table tab_get_path_from_hash {
        key = {
        }
        actions = {
          get_path_from_hash;
        }
        default_action = get_path_from_hash();
    }


/*----------------------------------------------------------------------*/
/*Calculate floating point expression for util*/

    action get_exp_mantissa_0() {
        meta.util_exp = 0;
        meta.util_mantissa = hdr.hulapp.util;
    }
    action get_exp_mantissa_1() {
        meta.util_exp = 1;
        meta.util_mantissa = (hdr.hulapp.util >> 1);
    }
    action get_exp_mantissa_2() {
        meta.util_exp = 2;
        meta.util_mantissa = (hdr.hulapp.util >> 2);
    }
    action get_exp_mantissa_3() {
        meta.util_exp = 3;
        meta.util_mantissa = (hdr.hulapp.util >> 3);
    }
    action get_exp_mantissa_4() {
        meta.util_exp = 4;
        meta.util_mantissa = (hdr.hulapp.util >> 4);
    }
    action get_exp_mantissa_5() {
        meta.util_exp = 5;
        meta.util_mantissa = (hdr.hulapp.util >> 5);
    }
    action get_exp_mantissa_6() {
        meta.util_exp = 6;
        meta.util_mantissa = (hdr.hulapp.util >> 6);
    }
    action get_exp_mantissa_7() {
        meta.util_exp = 7;
        meta.util_mantissa = (hdr.hulapp.util >> 7);
    }
    action get_exp_mantissa_8() {
        meta.util_exp = 8;
        meta.util_mantissa = (hdr.hulapp.util >> 8);
    }
    action get_exp_mantissa_9() {
        meta.util_exp = 9;
        meta.util_mantissa = (hdr.hulapp.util >> 9);
    }
    action get_exp_mantissa_10() {
        meta.util_exp = 10;
        meta.util_mantissa = (hdr.hulapp.util >> 10);
    }
    action get_exp_mantissa_11() {
        meta.util_exp = 11;
        meta.util_mantissa = (hdr.hulapp.util >> 11);
    }
    action get_exp_mantissa_12() {
        meta.util_exp = 12;
        meta.util_mantissa = (hdr.hulapp.util >> 12);
    }
    action get_exp_mantissa_13() {
        meta.util_exp = 13;
        meta.util_mantissa = (hdr.hulapp.util >> 13);
    }
    action get_exp_mantissa_14() {
        meta.util_exp = 14;
        meta.util_mantissa = (hdr.hulapp.util >> 14);
    }
    action get_exp_mantissa_15() {
        meta.util_exp = 15;
        meta.util_mantissa = (hdr.hulapp.util >> 15);
    }
    action get_exp_mantissa_16() {
        meta.util_exp = 16;
        meta.util_mantissa = (hdr.hulapp.util >> 16);
    }
    action get_exp_mantissa_17() {
        meta.util_exp = 17;
        meta.util_mantissa = (hdr.hulapp.util >> 17);
    }
    action get_exp_mantissa_18() {
        meta.util_exp = 18;
        meta.util_mantissa = (hdr.hulapp.util >> 18);
    }
    action get_exp_mantissa_19() {
        meta.util_exp = 19;
        meta.util_mantissa = (hdr.hulapp.util >> 19);
    }
    action get_exp_mantissa_20() {
        meta.util_exp = 20;
        meta.util_mantissa = (hdr.hulapp.util >> 20);
    }
    action get_exp_mantissa_21() {
        meta.util_exp = 21;
        meta.util_mantissa = (hdr.hulapp.util >> 21);
    }
    action get_exp_mantissa_22() {
        meta.util_exp = 22;
        meta.util_mantissa = (hdr.hulapp.util >> 22);
    }
    action get_exp_mantissa_23() {
        meta.util_exp = 23;
        meta.util_mantissa = (hdr.hulapp.util >> 23);
    }
    action get_exp_mantissa_24() {
        meta.util_exp = 24;
        meta.util_mantissa = (hdr.hulapp.util >> 24);
    }
    action get_max() {
        meta.util_exp = 24;
        meta.util_mantissa = 15;
    }

    table tab_cal_float_util {
        key = {
            hdr.hulapp.util: lpm;
        }
        actions = {
            get_exp_mantissa_0;
            get_exp_mantissa_1;
            get_exp_mantissa_2;
            get_exp_mantissa_3;
            get_exp_mantissa_4;
            get_exp_mantissa_5;
            get_exp_mantissa_6;
            get_exp_mantissa_7;
            get_exp_mantissa_8;
            get_exp_mantissa_9;
            get_exp_mantissa_10;
            get_exp_mantissa_11;
            get_exp_mantissa_12;
            get_exp_mantissa_13;
            get_exp_mantissa_14;
            get_exp_mantissa_15;
            get_exp_mantissa_16;
            get_exp_mantissa_17;
            get_exp_mantissa_18;
            get_exp_mantissa_19;
            get_exp_mantissa_20;
            get_exp_mantissa_21;
            get_exp_mantissa_22;
            get_exp_mantissa_23;
            get_exp_mantissa_24;
            get_max;
        }
        default_action = get_max();
    }

/*----------------------------------------------------------------------*/
/*Calculate weight mantissa based on util mantissa*/

    action get_weight_mantissa(bit<32> weightMantissa) {    // newWeight = 2748779*10 / hdr.hulapp.util    // 40Gbps => util = 2748779
        meta.weight_mantissa = weightMantissa;  // 2748779*10 = 0xd1 * 2^17, weightMantissa = 0xd1/util_mantissa, if util_mantissa == 0, weightMantissa = 0xff
						// another explanation: mapping x/min_mantissa(1) = target max_weight or x/max_mantissa(15) = target min_weight => find x and get all mappings
						// the target min_weight and max_weight determine the resolution.
    }

    table tab_cal_weight_mantissa {
        key = {
            meta.util_mantissa: exact;   // 16 util_mantissa to map to weightMantissa
        }
        actions = {
            get_weight_mantissa;
            NoAction;
        }
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*Calculate floating point expression for s*/

    action get_s_exp_mantissa_0() {
        meta.s_exp = 0;
        meta.s_mantissa = meta.s;
    }
    action get_s_exp_mantissa_1() {
        meta.s_exp = 1;
        meta.s_mantissa = (meta.s >> 1);
    }
    action get_s_exp_mantissa_2() {
        meta.s_exp = 2;
        meta.s_mantissa = (meta.s >> 2);
    }
    action get_s_exp_mantissa_3() {
        meta.s_exp = 3;
        meta.s_mantissa = (meta.s >> 3);
    }
    action get_s_exp_mantissa_4() {
        meta.s_exp = 4;
        meta.s_mantissa = (meta.s >> 4);
    }
    action get_s_exp_mantissa_5() {
        meta.s_exp = 5;
        meta.s_mantissa = (meta.s >> 5);
    }
    action get_s_exp_mantissa_6() {
        meta.s_exp = 6;
        meta.s_mantissa = (meta.s >> 6);
    }
    action get_s_exp_mantissa_7() {
        meta.s_exp = 7;
        meta.s_mantissa = (meta.s >> 7);
    }
    action get_s_exp_mantissa_8() {
        meta.s_exp = 8;
        meta.s_mantissa = (meta.s >> 8);
    }
    action get_s_exp_mantissa_9() {
        meta.s_exp = 9;
        meta.s_mantissa = (meta.s >> 9);
    }
    action get_s_exp_mantissa_10() {
        meta.s_exp = 10;
        meta.s_mantissa = (meta.s >> 10);
    }
    action get_s_exp_mantissa_11() {
        meta.s_exp = 11;
        meta.s_mantissa = (meta.s >> 11);
    }
    action get_s_exp_mantissa_12() {
        meta.s_exp = 12;
        meta.s_mantissa = (meta.s >> 12);
    }
    action get_s_exp_mantissa_13() {
        meta.s_exp = 13;
        meta.s_mantissa = (meta.s >> 13);
    }
    action get_s_exp_mantissa_14() {
        meta.s_exp = 14;
        meta.s_mantissa = (meta.s >> 14);
    }
    action get_s_exp_mantissa_15() {
        meta.s_exp = 15;
        meta.s_mantissa = (meta.s >> 15);
    }
    action get_s_exp_mantissa_16() {
        meta.s_exp = 16;
        meta.s_mantissa = (meta.s >> 16);
    }
    action get_s_exp_mantissa_17() {
        meta.s_exp = 17;
        meta.s_mantissa = (meta.s >> 17);
    }
    action get_s_exp_mantissa_18() {
        meta.s_exp = 18;
        meta.s_mantissa = (meta.s >> 18);
    }
    action get_s_exp_mantissa_19() {
        meta.s_exp = 19;
        meta.s_mantissa = (meta.s >> 19);
    }
    action get_s_exp_mantissa_20() {
        meta.s_exp = 20;
        meta.s_mantissa = (meta.s >> 20);
    }
    action get_s_exp_mantissa_21() {
        meta.s_exp = 21;
        meta.s_mantissa = (meta.s >> 21);
    }
    action get_s_exp_mantissa_22() {
        meta.s_exp = 22;
        meta.s_mantissa = (meta.s >> 22);
    }
    action get_s_exp_mantissa_23() {
        meta.s_exp = 23;
        meta.s_mantissa = (meta.s >> 23);
    }
    action get_s_exp_mantissa_24() {
        meta.s_exp = 24;
        meta.s_mantissa = (meta.s >> 24);
    }
    action get_s_exp_mantissa_25() {
        meta.s_exp = 25;
        meta.s_mantissa = (meta.s >> 25);
    }
    action get_s_exp_mantissa_26() {
        meta.s_exp = 26;
        meta.s_mantissa = (meta.s >> 26);
    }
    action get_s_max() {
        meta.s_exp = 26;
        meta.s_mantissa = 15;
    }

    table tab_cal_float_s {
        key = {
            meta.s: lpm;
        }
        actions = {
            get_s_exp_mantissa_0;
            get_s_exp_mantissa_1;
            get_s_exp_mantissa_2;
            get_s_exp_mantissa_3;
            get_s_exp_mantissa_4;
            get_s_exp_mantissa_5;
            get_s_exp_mantissa_6;
            get_s_exp_mantissa_7;
            get_s_exp_mantissa_8;
            get_s_exp_mantissa_9;
            get_s_exp_mantissa_10;
            get_s_exp_mantissa_11;
            get_s_exp_mantissa_12;
            get_s_exp_mantissa_13;
            get_s_exp_mantissa_14;
            get_s_exp_mantissa_15;
            get_s_exp_mantissa_16;
            get_s_exp_mantissa_17;
            get_s_exp_mantissa_18;
            get_s_exp_mantissa_19;
            get_s_exp_mantissa_20;
            get_s_exp_mantissa_21;
            get_s_exp_mantissa_22;
            get_s_exp_mantissa_23;
            get_s_exp_mantissa_24;
            get_s_exp_mantissa_25;
            get_s_exp_mantissa_26;
            get_s_max;
        }
        default_action = get_s_max();
    }

/*----------------------------------------------------------------------*/
/*Calculate floating point expression for w on path 0*/

    action get_w0_exp_mantissa_0() {
        meta.w0_exp = 0;
        meta.w0_mantissa = meta.w0;
    }
    action get_w0_exp_mantissa_1() {
        meta.w0_exp = 1;
        meta.w0_mantissa = (meta.w0 >> 1);
    }
    action get_w0_exp_mantissa_2() {
        meta.w0_exp = 2;
        meta.w0_mantissa = (meta.w0 >> 2);
    }
    action get_w0_exp_mantissa_3() {
        meta.w0_exp = 3;
        meta.w0_mantissa = (meta.w0 >> 3);
    }
    action get_w0_exp_mantissa_4() {
        meta.w0_exp = 4;
        meta.w0_mantissa = (meta.w0 >> 4);
    }
    action get_w0_exp_mantissa_5() {
        meta.w0_exp = 5;
        meta.w0_mantissa = (meta.w0 >> 5);
    }
    action get_w0_exp_mantissa_6() {
        meta.w0_exp = 6;
        meta.w0_mantissa = (meta.w0 >> 6);
    }
    action get_w0_exp_mantissa_7() {
        meta.w0_exp = 7;
        meta.w0_mantissa = (meta.w0 >> 7);
    }
    action get_w0_exp_mantissa_8() {
        meta.w0_exp = 8;
        meta.w0_mantissa = (meta.w0 >> 8);
    }
    action get_w0_exp_mantissa_9() {
        meta.w0_exp = 9;
        meta.w0_mantissa = (meta.w0 >> 9);
    }
    action get_w0_exp_mantissa_10() {
        meta.w0_exp = 10;
        meta.w0_mantissa = (meta.w0 >> 10);
    }
    action get_w0_exp_mantissa_11() {
        meta.w0_exp = 11;
        meta.w0_mantissa = (meta.w0 >> 11);
    }
    action get_w0_exp_mantissa_12() {
        meta.w0_exp = 12;
        meta.w0_mantissa = (meta.w0 >> 12);
    }
    action get_w0_exp_mantissa_13() {
        meta.w0_exp = 13;
        meta.w0_mantissa = (meta.w0 >> 13);
    }
    action get_w0_exp_mantissa_14() {
        meta.w0_exp = 14;
        meta.w0_mantissa = (meta.w0 >> 14);
    }
    action get_w0_exp_mantissa_15() {
        meta.w0_exp = 15;
        meta.w0_mantissa = (meta.w0 >> 15);
    }
    action get_w0_exp_mantissa_16() {
        meta.w0_exp = 16;
        meta.w0_mantissa = (meta.w0 >> 16);
    }
    action get_w0_exp_mantissa_17() {
        meta.w0_exp = 17;
        meta.w0_mantissa = (meta.w0 >> 17);
    }
    action get_w0_exp_mantissa_18() {
        meta.w0_exp = 18;
        meta.w0_mantissa = (meta.w0 >> 18);
    }
    action get_w0_exp_mantissa_19() {
        meta.w0_exp = 19;
        meta.w0_mantissa = (meta.w0 >> 19);
    }
    action get_w0_exp_mantissa_20() {
        meta.w0_exp = 20;
        meta.w0_mantissa = (meta.w0 >> 20);
    }
    action get_w0_exp_mantissa_21() {
        meta.w0_exp = 21;
        meta.w0_mantissa = (meta.w0 >> 21);
    }
    action get_w0_max() {
        meta.w0_exp = 21;
        meta.w0_mantissa = 15;
    }

    table tab_cal_float_w0 {
        key = {
            meta.w0: lpm;
        }
        actions = {
            get_w0_exp_mantissa_0;
            get_w0_exp_mantissa_1;
            get_w0_exp_mantissa_2;
            get_w0_exp_mantissa_3;
            get_w0_exp_mantissa_4;
            get_w0_exp_mantissa_5;
            get_w0_exp_mantissa_6;
            get_w0_exp_mantissa_7;
            get_w0_exp_mantissa_8;
            get_w0_exp_mantissa_9;
            get_w0_exp_mantissa_10;
            get_w0_exp_mantissa_11;
            get_w0_exp_mantissa_12;
            get_w0_exp_mantissa_13;
            get_w0_exp_mantissa_14;
            get_w0_exp_mantissa_15;
            get_w0_exp_mantissa_16;
            get_w0_exp_mantissa_17;
            get_w0_exp_mantissa_18;
            get_w0_exp_mantissa_19;
            get_w0_exp_mantissa_20;
            get_w0_exp_mantissa_21;
            get_w0_max;
        }
        default_action = get_w0_max();
    }

/*----------------------------------------------------------------------*/
/*Calculate floating point expression for w on path 1*/

    action get_w1_exp_mantissa_0() {
        meta.w1_exp = 0;
        meta.w1_mantissa = meta.w1;
    }
    action get_w1_exp_mantissa_1() {
        meta.w1_exp = 1;
        meta.w1_mantissa = (meta.w1 >> 1);
    }
    action get_w1_exp_mantissa_2() {
        meta.w1_exp = 2;
        meta.w1_mantissa = (meta.w1 >> 2);
    }
    action get_w1_exp_mantissa_3() {
        meta.w1_exp = 3;
        meta.w1_mantissa = (meta.w1 >> 3);
    }
    action get_w1_exp_mantissa_4() {
        meta.w1_exp = 4;
        meta.w1_mantissa = (meta.w1 >> 4);
    }
    action get_w1_exp_mantissa_5() {
        meta.w1_exp = 5;
        meta.w1_mantissa = (meta.w1 >> 5);
    }
    action get_w1_exp_mantissa_6() {
        meta.w1_exp = 6;
        meta.w1_mantissa = (meta.w1 >> 6);
    }
    action get_w1_exp_mantissa_7() {
        meta.w1_exp = 7;
        meta.w1_mantissa = (meta.w1 >> 7);
    }
    action get_w1_exp_mantissa_8() {
        meta.w1_exp = 8;
        meta.w1_mantissa = (meta.w1 >> 8);
    }
    action get_w1_exp_mantissa_9() {
        meta.w1_exp = 9;
        meta.w1_mantissa = (meta.w1 >> 9);
    }
    action get_w1_exp_mantissa_10() {
        meta.w1_exp = 10;
        meta.w1_mantissa = (meta.w1 >> 10);
    }
    action get_w1_exp_mantissa_11() {
        meta.w1_exp = 11;
        meta.w1_mantissa = (meta.w1 >> 11);
    }
    action get_w1_exp_mantissa_12() {
        meta.w1_exp = 12;
        meta.w1_mantissa = (meta.w1 >> 12);
    }
    action get_w1_exp_mantissa_13() {
        meta.w1_exp = 13;
        meta.w1_mantissa = (meta.w1 >> 13);
    }
    action get_w1_exp_mantissa_14() {
        meta.w1_exp = 14;
        meta.w1_mantissa = (meta.w1 >> 14);
    }
    action get_w1_exp_mantissa_15() {
        meta.w1_exp = 15;
        meta.w1_mantissa = (meta.w1 >> 15);
    }
    action get_w1_exp_mantissa_16() {
        meta.w1_exp = 16;
        meta.w1_mantissa = (meta.w1 >> 16);
    }
    action get_w1_exp_mantissa_17() {
        meta.w1_exp = 17;
        meta.w1_mantissa = (meta.w1 >> 17);
    }
    action get_w1_exp_mantissa_18() {
        meta.w1_exp = 18;
        meta.w1_mantissa = (meta.w1 >> 18);
    }
    action get_w1_exp_mantissa_19() {
        meta.w1_exp = 19;
        meta.w1_mantissa = (meta.w1 >> 19);
    }
    action get_w1_exp_mantissa_20() {
        meta.w1_exp = 20;
        meta.w1_mantissa = (meta.w1 >> 20);
    }
    action get_w1_exp_mantissa_21() {
        meta.w1_exp = 21;
        meta.w1_mantissa = (meta.w1 >> 21);
    }
    action get_w1_max() {
        meta.w1_exp = 21;
        meta.w1_mantissa = 15;
    }

    table tab_cal_float_w1 {
        key = {
            meta.w1: lpm;
        }
        actions = {
            get_w1_exp_mantissa_0;
            get_w1_exp_mantissa_1;
            get_w1_exp_mantissa_2;
            get_w1_exp_mantissa_3;
            get_w1_exp_mantissa_4;
            get_w1_exp_mantissa_5;
            get_w1_exp_mantissa_6;
            get_w1_exp_mantissa_7;
            get_w1_exp_mantissa_8;
            get_w1_exp_mantissa_9;
            get_w1_exp_mantissa_10;
            get_w1_exp_mantissa_11;
            get_w1_exp_mantissa_12;
            get_w1_exp_mantissa_13;
            get_w1_exp_mantissa_14;
            get_w1_exp_mantissa_15;
            get_w1_exp_mantissa_16;
            get_w1_exp_mantissa_17;
            get_w1_exp_mantissa_18;
            get_w1_exp_mantissa_19;
            get_w1_exp_mantissa_20;
            get_w1_exp_mantissa_21;
            get_w1_max;
        }
        default_action = get_w1_max();
    }

/*----------------------------------------------------------------------*/
/*Calculate floating point expression for w on path 2*/

    action get_w2_exp_mantissa_0() {
        meta.w2_exp = 0;
        meta.w2_mantissa = meta.w2;
    }
    action get_w2_exp_mantissa_1() {
        meta.w2_exp = 1;
        meta.w2_mantissa = (meta.w2 >> 1);
    }
    action get_w2_exp_mantissa_2() {
        meta.w2_exp = 2;
        meta.w2_mantissa = (meta.w2 >> 2);
    }
    action get_w2_exp_mantissa_3() {
        meta.w2_exp = 3;
        meta.w2_mantissa = (meta.w2 >> 3);
    }
    action get_w2_exp_mantissa_4() {
        meta.w2_exp = 4;
        meta.w2_mantissa = (meta.w2 >> 4);
    }
    action get_w2_exp_mantissa_5() {
        meta.w2_exp = 5;
        meta.w2_mantissa = (meta.w2 >> 5);
    }
    action get_w2_exp_mantissa_6() {
        meta.w2_exp = 6;
        meta.w2_mantissa = (meta.w2 >> 6);
    }
    action get_w2_exp_mantissa_7() {
        meta.w2_exp = 7;
        meta.w2_mantissa = (meta.w2 >> 7);
    }
    action get_w2_exp_mantissa_8() {
        meta.w2_exp = 8;
        meta.w2_mantissa = (meta.w2 >> 8);
    }
    action get_w2_exp_mantissa_9() {
        meta.w2_exp = 9;
        meta.w2_mantissa = (meta.w2 >> 9);
    }
    action get_w2_exp_mantissa_10() {
        meta.w2_exp = 10;
        meta.w2_mantissa = (meta.w2 >> 10);
    }
    action get_w2_exp_mantissa_11() {
        meta.w2_exp = 11;
        meta.w2_mantissa = (meta.w2 >> 11);
    }
    action get_w2_exp_mantissa_12() {
        meta.w2_exp = 12;
        meta.w2_mantissa = (meta.w2 >> 12);
    }
    action get_w2_exp_mantissa_13() {
        meta.w2_exp = 13;
        meta.w2_mantissa = (meta.w2 >> 13);
    }
    action get_w2_exp_mantissa_14() {
        meta.w2_exp = 14;
        meta.w2_mantissa = (meta.w2 >> 14);
    }
    action get_w2_exp_mantissa_15() {
        meta.w2_exp = 15;
        meta.w2_mantissa = (meta.w2 >> 15);
    }
    action get_w2_exp_mantissa_16() {
        meta.w2_exp = 16;
        meta.w2_mantissa = (meta.w2 >> 16);
    }
    action get_w2_exp_mantissa_17() {
        meta.w2_exp = 17;
        meta.w2_mantissa = (meta.w2 >> 17);
    }
    action get_w2_exp_mantissa_18() {
        meta.w2_exp = 18;
        meta.w2_mantissa = (meta.w2 >> 18);
    }
    action get_w2_exp_mantissa_19() {
        meta.w2_exp = 19;
        meta.w2_mantissa = (meta.w2 >> 19);
    }
    action get_w2_exp_mantissa_20() {
        meta.w2_exp = 20;
        meta.w2_mantissa = (meta.w2 >> 20);
    }
    action get_w2_exp_mantissa_21() {
        meta.w2_exp = 21;
        meta.w2_mantissa = (meta.w2 >> 21);
    }
    action get_w2_max() {
        meta.w2_exp = 21;
        meta.w2_mantissa = 15;
    }

    table tab_cal_float_w2 {
        key = {
            meta.w2: lpm;
        }
        actions = {
            get_w2_exp_mantissa_0;
            get_w2_exp_mantissa_1;
            get_w2_exp_mantissa_2;
            get_w2_exp_mantissa_3;
            get_w2_exp_mantissa_4;
            get_w2_exp_mantissa_5;
            get_w2_exp_mantissa_6;
            get_w2_exp_mantissa_7;
            get_w2_exp_mantissa_8;
            get_w2_exp_mantissa_9;
            get_w2_exp_mantissa_10;
            get_w2_exp_mantissa_11;
            get_w2_exp_mantissa_12;
            get_w2_exp_mantissa_13;
            get_w2_exp_mantissa_14;
            get_w2_exp_mantissa_15;
            get_w2_exp_mantissa_16;
            get_w2_exp_mantissa_17;
            get_w2_exp_mantissa_18;
            get_w2_exp_mantissa_19;
            get_w2_exp_mantissa_20;
            get_w2_exp_mantissa_21;
            get_w2_max;
        }
        default_action = get_w2_max();
    }

/*----------------------------------------------------------------------*/
/*Calculate floating point expression for w on path 3*/

    action get_w3_exp_mantissa_0() {
        meta.w3_exp = 0;
        meta.w3_mantissa = meta.w3;
    }
    action get_w3_exp_mantissa_1() {
        meta.w3_exp = 1;
        meta.w3_mantissa = (meta.w3 >> 1);
    }
    action get_w3_exp_mantissa_2() {
        meta.w3_exp = 2;
        meta.w3_mantissa = (meta.w3 >> 2);
    }
    action get_w3_exp_mantissa_3() {
        meta.w3_exp = 3;
        meta.w3_mantissa = (meta.w3 >> 3);
    }
    action get_w3_exp_mantissa_4() {
        meta.w3_exp = 4;
        meta.w3_mantissa = (meta.w3 >> 4);
    }
    action get_w3_exp_mantissa_5() {
        meta.w3_exp = 5;
        meta.w3_mantissa = (meta.w3 >> 5);
    }
    action get_w3_exp_mantissa_6() {
        meta.w3_exp = 6;
        meta.w3_mantissa = (meta.w3 >> 6);
    }
    action get_w3_exp_mantissa_7() {
        meta.w3_exp = 7;
        meta.w3_mantissa = (meta.w3 >> 7);
    }
    action get_w3_exp_mantissa_8() {
        meta.w3_exp = 8;
        meta.w3_mantissa = (meta.w3 >> 8);
    }
    action get_w3_exp_mantissa_9() {
        meta.w3_exp = 9;
        meta.w3_mantissa = (meta.w3 >> 9);
    }
    action get_w3_exp_mantissa_10() {
        meta.w3_exp = 10;
        meta.w3_mantissa = (meta.w3 >> 10);
    }
    action get_w3_exp_mantissa_11() {
        meta.w3_exp = 11;
        meta.w3_mantissa = (meta.w3 >> 11);
    }
    action get_w3_exp_mantissa_12() {
        meta.w3_exp = 12;
        meta.w3_mantissa = (meta.w3 >> 12);
    }
    action get_w3_exp_mantissa_13() {
        meta.w3_exp = 13;
        meta.w3_mantissa = (meta.w3 >> 13);
    }
    action get_w3_exp_mantissa_14() {
        meta.w3_exp = 14;
        meta.w3_mantissa = (meta.w3 >> 14);
    }
    action get_w3_exp_mantissa_15() {
        meta.w3_exp = 15;
        meta.w3_mantissa = (meta.w3 >> 15);
    }
    action get_w3_exp_mantissa_16() {
        meta.w3_exp = 16;
        meta.w3_mantissa = (meta.w3 >> 16);
    }
    action get_w3_exp_mantissa_17() {
        meta.w3_exp = 17;
        meta.w3_mantissa = (meta.w3 >> 17);
    }
    action get_w3_exp_mantissa_18() {
        meta.w3_exp = 18;
        meta.w3_mantissa = (meta.w3 >> 18);
    }
    action get_w3_exp_mantissa_19() {
        meta.w3_exp = 19;
        meta.w3_mantissa = (meta.w3 >> 19);
    }
    action get_w3_exp_mantissa_20() {
        meta.w3_exp = 20;
        meta.w3_mantissa = (meta.w3 >> 20);
    }
    action get_w3_exp_mantissa_21() {
        meta.w3_exp = 21;
        meta.w3_mantissa = (meta.w3 >> 21);
    }
    action get_w3_max() {
        meta.w3_exp = 21;
        meta.w3_mantissa = 15;
    }

    table tab_cal_float_w3 {
        key = {
            meta.w3: lpm;
        }
        actions = {
            get_w3_exp_mantissa_0;
            get_w3_exp_mantissa_1;
            get_w3_exp_mantissa_2;
            get_w3_exp_mantissa_3;
            get_w3_exp_mantissa_4;
            get_w3_exp_mantissa_5;
            get_w3_exp_mantissa_6;
            get_w3_exp_mantissa_7;
            get_w3_exp_mantissa_8;
            get_w3_exp_mantissa_9;
            get_w3_exp_mantissa_10;
            get_w3_exp_mantissa_11;
            get_w3_exp_mantissa_12;
            get_w3_exp_mantissa_13;
            get_w3_exp_mantissa_14;
            get_w3_exp_mantissa_15;
            get_w3_exp_mantissa_16;
            get_w3_exp_mantissa_17;
            get_w3_exp_mantissa_18;
            get_w3_exp_mantissa_19;
            get_w3_exp_mantissa_20;
            get_w3_exp_mantissa_21;
            get_w3_max;
        }
        default_action = get_w3_max();
    }

/*----------------------------------------------------------------------*/
/*Calculate t mantissa based on w and s mantissa*/

    action get_t0_mantissa(bit<16> tMantissa) {
        meta.t0_mantissa = tMantissa;
        meta.t0_exp = 10+meta.w0_exp-meta.s_exp;  // before offset 4 
    }

    table tab_cal_t0_mantissa {
        key = {
            meta.w0_mantissa: exact;
            meta.s_mantissa: exact;
        }
        actions = {
            get_t0_mantissa;
            NoAction;
        }
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*Calculate t mantissa based on w and s mantissa*/

    action get_t1_mantissa(bit<16> tMantissa) {
        meta.t1_mantissa = tMantissa;
        meta.t1_exp = 10+meta.w1_exp-meta.s_exp;  // before offset 4 
    }

    table tab_cal_t1_mantissa {
        key = {
            meta.w1_mantissa: exact;
            meta.s_mantissa: exact;
        }
        actions = {
            get_t1_mantissa;
            NoAction;
        }
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*Calculate t mantissa based on w and s mantissa*/

    action get_t2_mantissa(bit<16> tMantissa) {
        meta.t2_mantissa = tMantissa;
        meta.t2_exp = 10+meta.w2_exp-meta.s_exp;  // before offset 4 
    }

    table tab_cal_t2_mantissa {
        key = {
            meta.w2_mantissa: exact;
            meta.s_mantissa: exact;
        }
        actions = {
            get_t2_mantissa;
            NoAction;
        }
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*Calculate t mantissa based on w and s mantissa*/

    action get_t3_mantissa(bit<16> tMantissa) {
        meta.t3_mantissa = tMantissa;
        meta.t3_exp = 10+meta.w3_exp-meta.s_exp;  // before offset 4 
    }

    table tab_cal_t3_mantissa {
        key = {
            meta.w3_mantissa: exact;
            meta.s_mantissa: exact;
        }
        actions = {
            get_t3_mantissa;
            NoAction;
        }
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/* Get integer t for path 0 */

    action get_t0_n4() {
        meta.t0 = (meta.t0_mantissa >> 4);
    }
    action get_t0_n3() {
        meta.t0 = (meta.t0_mantissa >> 3);
    }
    action get_t0_n2() {
        meta.t0 = (meta.t0_mantissa >> 2);
    }
    action get_t0_n1() {
        meta.t0 = (meta.t0_mantissa >> 1);
    }
    action get_t0_0() {
        meta.t0 = (meta.t0_mantissa);
    }
    action get_t0_1() {
        meta.t0 = (meta.t0_mantissa << 1);
    }
    action get_t0_2() {
        meta.t0 = (meta.t0_mantissa << 2);
    }
    action get_t0_3() {
        meta.t0 = (meta.t0_mantissa << 3);
    }
    action get_t0_4() {
        meta.t0 = (meta.t0_mantissa << 4);
    }
    action get_t0_5() {
        meta.t0 = (meta.t0_mantissa << 5);
    }
    action get_t0_6() {
        meta.t0 = (meta.t0_mantissa << 6);
    }
    action get_zero_t0() {
        meta.t0 = 0; 
    }

    table tab_get_t0 {
        key = {
            meta.t0_exp     : exact;
        }
        actions = {
            get_t0_n4;
            get_t0_n3;
            get_t0_n2;
            get_t0_n1;
            get_t0_0;
            get_t0_1;
            get_t0_2;
            get_t0_3;
            get_t0_4;
            get_t0_5;
            get_t0_6;
            get_zero_t0;
        }
        default_action = get_zero_t0();
    }

/*----------------------------------------------------------------------*/
/* Get integer t for path 1 */

    action get_t1_n4() {
        meta.t1 = (meta.t1_mantissa >> 4);
    }
    action get_t1_n3() {
        meta.t1 = (meta.t1_mantissa >> 3);
    }
    action get_t1_n2() {
        meta.t1 = (meta.t1_mantissa >> 2);
    }
    action get_t1_n1() {
        meta.t1 = (meta.t1_mantissa >> 1);
    }
    action get_t1_0() {
        meta.t1 = (meta.t1_mantissa);
    }
    action get_t1_1() {
        meta.t1 = (meta.t1_mantissa << 1);
    }
    action get_t1_2() {
        meta.t1 = (meta.t1_mantissa << 2);
    }
    action get_t1_3() {
        meta.t1 = (meta.t1_mantissa << 3);
    }
    action get_t1_4() {
        meta.t1 = (meta.t1_mantissa << 4);
    }
    action get_t1_5() {
        meta.t1 = (meta.t1_mantissa << 5);
    }
    action get_t1_6() {
        meta.t1 = (meta.t1_mantissa << 6);
    }
    action get_zero_t1() {
        meta.t1 = 0; 
    }

    table tab_get_t1 {
        key = {
            meta.t1_exp     : exact;
        }
        actions = {
            get_t1_n4;
            get_t1_n3;
            get_t1_n2;
            get_t1_n1;
            get_t1_0;
            get_t1_1;
            get_t1_2;
            get_t1_3;
            get_t1_4;
            get_t1_5;
            get_t1_6;
            get_zero_t1;
        }
        default_action = get_zero_t1();
    }

/*----------------------------------------------------------------------*/
/* Get integer t for path 2 */

    action get_t2_n4() {
        meta.t2 = (meta.t2_mantissa >> 4);
    }
    action get_t2_n3() {
        meta.t2 = (meta.t2_mantissa >> 3);
    }
    action get_t2_n2() {
        meta.t2 = (meta.t2_mantissa >> 2);
    }
    action get_t2_n1() {
        meta.t2 = (meta.t2_mantissa >> 1);
    }
    action get_t2_0() {
        meta.t2 = (meta.t2_mantissa);
    }
    action get_t2_1() {
        meta.t2 = (meta.t2_mantissa << 1);
    }
    action get_t2_2() {
        meta.t2 = (meta.t2_mantissa << 2);
    }
    action get_t2_3() {
        meta.t2 = (meta.t2_mantissa << 3);
    }
    action get_t2_4() {
        meta.t2 = (meta.t2_mantissa << 4);
    }
    action get_t2_5() {
        meta.t2 = (meta.t2_mantissa << 5);
    }
    action get_t2_6() {
        meta.t2 = (meta.t2_mantissa << 6);
    }
    action get_zero_t2() {
        meta.t2 = 0; 
    }

    table tab_get_t2 {
        key = {
            meta.t2_exp     : exact;
        }
        actions = {
            get_t2_n4;
            get_t2_n3;
            get_t2_n2;
            get_t2_n1;
            get_t2_0;
            get_t2_1;
            get_t2_2;
            get_t2_3;
            get_t2_4;
            get_t2_5;
            get_t2_6;
            get_zero_t2;
        }
        default_action = get_zero_t2();
    }

/*----------------------------------------------------------------------*/
/* Get integer t for path 3 */

    action get_t3_n4() {
        meta.t3 = (meta.t3_mantissa >> 4);
    }
    action get_t3_n3() {
        meta.t3 = (meta.t3_mantissa >> 3);
    }
    action get_t3_n2() {
        meta.t3 = (meta.t3_mantissa >> 2);
    }
    action get_t3_n1() {
        meta.t3 = (meta.t3_mantissa >> 1);
    }
    action get_t3_0() {
        meta.t3 = (meta.t3_mantissa);
    }
    action get_t3_1() {
        meta.t3 = (meta.t3_mantissa << 1);
    }
    action get_t3_2() {
        meta.t3 = (meta.t3_mantissa << 2);
    }
    action get_t3_3() {
        meta.t3 = (meta.t3_mantissa << 3);
    }
    action get_t3_4() {
        meta.t3 = (meta.t3_mantissa << 4);
    }
    action get_t3_5() {
        meta.t3 = (meta.t3_mantissa << 5);
    }
    action get_t3_6() {
        meta.t3 = (meta.t3_mantissa << 6);
    }
    action get_zero_t3() {
        meta.t3 = 0; 
    }

    table tab_get_t3 {
        key = {
            meta.t3_exp     : exact;
        }
        actions = {
            get_t3_n4;
            get_t3_n3;
            get_t3_n2;
            get_t3_n1;
            get_t3_0;
            get_t3_1;
            get_t3_2;
            get_t3_3;
            get_t3_4;
            get_t3_5;
            get_t3_6;
            get_zero_t3;
        }
        default_action = get_zero_t3();
    }

/*----------------------------------------------------------------------*/
/*Process Probe: Update weight if source, forward otherwise*/

    action forward_probe(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action update_w0_n1() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa >> 1);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_0() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_1() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 1);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_2() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 2);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_3() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 3);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_4() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 4);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_5() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 5);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_6() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 6);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_7() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 7);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_8() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 8);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_9() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 9);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_10() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 10);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_11() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 11);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_12() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 12);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_13() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 13);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_14() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 14);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_15() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 15);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_16() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 16);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w0_17() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight0.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 17);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight0.write(dst, newWeight);
    }
    action update_w1_n1() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa >> 1);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_0() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_1() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 1);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_2() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 2);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_3() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 3);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_4() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 4);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_5() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 5);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_6() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 6);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_7() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 7);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_8() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 8);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_9() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 9);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_10() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 10);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_11() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 11);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_12() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 12);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_13() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 13);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_14() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 14);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_15() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 15);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_16() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 16);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w1_17() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight1.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 17);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight1.write(dst, newWeight);
    }
    action update_w2_n1() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa >> 1);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_0() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_1() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 1);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_2() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 2);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_3() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 3);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_4() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 4);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_5() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 5);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_6() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 6);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_7() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 7);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_8() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 8);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_9() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 9);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_10() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 10);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_11() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 11);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_12() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 12);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_13() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 13);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_14() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 14);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_15() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 15);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_16() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 16);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w2_17() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight2.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 17);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight2.write(dst, newWeight);
    }
    action update_w3_n1() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa >> 1);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_0() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_1() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 1);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_2() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 2);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_3() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 3);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_4() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 4);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_5() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 5);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_6() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 6);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_7() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 7);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_8() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 8);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_9() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 9);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_10() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 10);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_11() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 11);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_12() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 12);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_13() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 13);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_14() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 14);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_15() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 15);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_16() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 16);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    action update_w3_17() {
        bit<32> oldWeight;
        bit<32> newWeight;
        bit<32> s;
        bit<32> dst = (bit<32>) hdr.hulapp.dst_tor;
        weight3.read(oldWeight, dst);
        sumWeight.read(s, dst);

        newWeight = (meta.weight_mantissa << 17);  // weight_mantissa << (17 - meta.util_exp)
        meta.debug_probe_w = newWeight;

        sumWeight.write(dst, s + newWeight - oldWeight);
        weight3.write(dst, newWeight);
    }
    table tab_process_probe {
        key = {
            hdr.hulapp.src_tor: ternary;
            hdr.hulapp.dst_tor: ternary;
            hdr.hulapp.pathId : exact;
            meta.util_exp     : ternary;
        }
        actions = {
            forward_probe;
            update_w0_n1;
            update_w0_0;
            update_w0_1;
            update_w0_2;
            update_w0_3;
            update_w0_4;
            update_w0_5;
            update_w0_6;
            update_w0_7;
            update_w0_8;
            update_w0_9;
            update_w0_10;
            update_w0_11;
            update_w0_12;
            update_w0_13;
            update_w0_14;
            update_w0_15;
            update_w0_16;
            update_w0_17;
            update_w1_n1;
            update_w1_0;
            update_w1_1;
            update_w1_2;
            update_w1_3;
            update_w1_4;
            update_w1_5;
            update_w1_6;
            update_w1_7;
            update_w1_8;
            update_w1_9;
            update_w1_10;
            update_w1_11;
            update_w1_12;
            update_w1_13;
            update_w1_14;
            update_w1_15;
            update_w1_16;
            update_w1_17;
            update_w2_n1;
            update_w2_0;
            update_w2_1;
            update_w2_2;
            update_w2_3;
            update_w2_4;
            update_w2_5;
            update_w2_6;
            update_w2_7;
            update_w2_8;
            update_w2_9;
            update_w2_10;
            update_w2_11;
            update_w2_12;
            update_w2_13;
            update_w2_14;
            update_w2_15;
            update_w2_16;
            update_w2_17;
            update_w3_n1;
            update_w3_0;
            update_w3_1;
            update_w3_2;
            update_w3_3;
            update_w3_4;
            update_w3_5;
            update_w3_6;
            update_w3_7;
            update_w3_8;
            update_w3_9;
            update_w3_10;
            update_w3_11;
            update_w3_12;
            update_w3_13;
            update_w3_14;
            update_w3_15;
            update_w3_16;
            update_w3_17;
            NoAction;
        }
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*If Hula++ probe, mcast it to the right set of next hops*/

    // Write to the standard_metadata's mcast field!
    action set_hulapp_mcast(bit<16> mcast_id) {
      standard_metadata.mcast_grp = mcast_id;
    }

    table tab_hulapp_mcast {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
          set_hulapp_mcast; 
          drop; 
          NoAction; 
        }
        default_action = drop();
    }

/*----------------------------------------------------------------------*/
/*Update the mac address based on the port*/

    action update_macs(macAddr_t dstAddr) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    table tab_port_to_mac {
        key = {
            meta.outbound_port: exact;
        }   
        actions = {
            update_macs;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
/*----------------------------------------------------------------------*/
/*Remove hula header between IP and TCP/UDP header*/

    action remove_hula_tcp() {
        if (hdr.ipv4.isValid())
            hdr.ipv4.protocol = TCP_PROTOCOL;
        else if (hdr.ethernet.isValid())
            hdr.ethernet.etherType = TYPE_ARP;
        hdr.hulapp_data.setInvalid();
    }

    action remove_hula_udp() {
        if (hdr.ipv4.isValid())
            hdr.ipv4.protocol = UDP_PROTOCOL;
        else if (hdr.ethernet.isValid())
            hdr.ethernet.etherType = TYPE_ARP;
        hdr.hulapp_data.setInvalid();
    }

    table tab_remove_hula_header {
        key = {
            hdr.ppp.pppType              : exact;
            hdr.ipv4.protocol            : ternary;
            meta.dst_switch_id           : exact;
        }
        actions = {
            remove_hula_tcp;
            remove_hula_udp;
            NoAction;
        }
//        const entries = {
//            (TYPE_HULAPP_TCP_DATA, _,                        1) : remove_hula_tcp();
//            (TYPE_IPV4,            HULAPP_TCP_DATA_PROTOCOL, 1) : remove_hula_tcp();
//            (TYPE_HULAPP_UDP_DATA, _,                        1) : remove_hula_udp();
//            (TYPE_IPV4,            HULAPP_UDP_DATA_PROTOCOL, 1) : remove_hula_udp();
//        }
        size = 4;
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*At leaf switch, forward data packet to end host*/

    action forward_to_end_hosts(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action mcast_to_all_end_hosts(bit<16> mcast_id) {
      standard_metadata.mcast_grp = mcast_id;
    }

    table tab_forward_to_end_hosts {
        key = {
            hdr.ppp.pppType              : exact;
            hdr.ipv4.protocol            : ternary;
            meta.dst_switch_id           : exact;
            hdr.ipv4.dstAddr             : ternary;
        }
        actions = {
            forward_to_end_hosts;
            mcast_to_all_end_hosts;
            NoAction;
        }
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*Inject hula header between IP and TCP/UDP header*/

    action inject_hula_below_ipv4_above_tcp() {
        hdr.ipv4.protocol = HULAPP_TCP_DATA_PROTOCOL;
        hdr.hulapp_data.setValid();
        currentid.read(hdr.ipv4.identification, 0);
        currentid.write(0, hdr.ipv4.identification+1);
        //hdr.hulapp_data.data_id = hdr.tcp.seqNo; // use tcp.seqNo as our data_id
    }

    action inject_hula_below_ipv4_above_udp() {
        hdr.ipv4.protocol = HULAPP_UDP_DATA_PROTOCOL;
        hdr.hulapp_data.setValid();
        currentid.read(hdr.ipv4.identification, 0);
        currentid.write(0, hdr.ipv4.identification+1);
    }

    action inject_hula_above_arp() {
        hdr.ppp.pppType = TYPE_HULAPP_TCP_DATA;
        hdr.hulapp_data.setValid();
        //hdr.hulapp_data.data_id = 0; // use tcp.seqNo as our data_id
    }

    table tab_inject_hula_header {
        key = {
            hdr.ppp.pppType                 : exact;
            hdr.ipv4.protocol               : ternary;
        }
        actions = {
            inject_hula_below_ipv4_above_tcp;
            inject_hula_below_ipv4_above_udp;
            inject_hula_above_arp;
            NoAction;
        }
        const entries = {
            (TYPE_IPV4, TCP_PROTOCOL) : inject_hula_below_ipv4_above_tcp();
            (TYPE_IPV4, UDP_PROTOCOL) : inject_hula_below_ipv4_above_udp();
            (TYPE_ARP,  _)            : inject_hula_above_arp();
        }
        size = 3;
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*Update the destination switch ID from the ip prefix*/

    action update_dst_id(bit<16> id) {
        meta.dst_switch_id = id;
    }

    table tab_prefix_to_dst_id {
        key = {
            meta.ipv4DstAddr: lpm;
        }   
        actions = {
            update_dst_id;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*Update the source switch ID from the ip prefix*/

    action update_src_id(bit<16> id) {
        meta.src_switch_id = id;
    }

    table tab_prefix_to_src_id {
        key = {
            meta.ipv4SrcAddr: lpm;
        }   
        actions = {
            update_src_id;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*If data traffic, do normal forwarding*/

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
//        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
//        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table tab_ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }   
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*Table used to observe some registers' value*/

    table tab_observe_metadata_probe {
        key = { 
            standard_metadata.ns3_node_id: ternary;
            meta.debug_probe_port: ternary;
            meta.debug_probe_dst_tor: ternary;
            meta.debug_probe_src_tor: ternary;
            meta.debug_probe_pathId: ternary;
            meta.debug_probe_w: ternary;
            meta.debug_probe_util: ternary;
            meta.debug_probe_time: ternary;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }
/*Table used to observe some registers' value*/

    table tab_observe_metadata_pkt {
        key = { 
            standard_metadata.ns3_node_id: ternary;
            meta.debug_pkt_ingress_port: ternary;
            meta.debug_pkt_egress_port: ternary;
            meta.debug_pkt_fidx: ternary;
            meta.debug_pkt_flowlet_create: ternary;
            meta.debug_pkt_flowlet_cached: ternary;
            meta.debug_pkt_flowlet_thrash: ternary;
            meta.debug_pkt_util: ternary;
            meta.debug_pkt_deficit: ternary;
            meta.debug_pkt_excess: ternary;
            meta.debug_pkt_s: ternary;
            meta.debug_pkt_time: ternary;
            meta.debug_pkt_w0: ternary;
            meta.debug_pkt_w1: ternary;
            meta.debug_pkt_w2: ternary;
            meta.debug_pkt_w3: ternary;
            meta.debug_pkt_w4: ternary;
            meta.debug_pkt_i: ternary;
            meta.debug_pkt_t0: ternary;
            meta.debug_pkt_t1: ternary;
            meta.debug_pkt_t2: ternary;
            meta.debug_pkt_t3: ternary;
            meta.debug_pkt_t4: ternary;
            meta.debug_pkt_dst: ternary;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }

/*----------------------------------------------------------------------*/
/*Applying the tables*/

    apply {

        if (hdr.tcp.isValid() || hdr.udp.isValid() || hdr.arp_ipv4.isValid()) {
            tab_prefix_to_dst_id.apply();
            tab_prefix_to_src_id.apply();

            if (! hdr.hulapp_data.isValid()) {

                meta.debug_pkt_ingress_port = standard_metadata.ingress_port;
    
                tab_inject_hula_header.apply();
                bit<32> dst = (bit<32>) meta.dst_switch_id;

                bit<32> hash_ecmp_index;
                hash(hash_ecmp_index, 
                     HashAlgorithm.crc32,
                     (bit<10>) 0,
                     { standard_metadata.ingress_global_timestamp },
                     (bit<32>) NUM_ENTRIES-1);
                meta.hash_ecmp_index = hash_ecmp_index;
                tab_get_path_from_hash.apply();
    
                if (hdr.ipv4.isValid()) {
                    bit<16> srcPort;
                    bit<16> dstPort;
                    if (hdr.tcp.isValid()) {
                        srcPort = hdr.tcp.srcPort;
                        dstPort = hdr.tcp.dstPort;
                    } else {
                        srcPort = hdr.udp.srcPort;
                        dstPort = hdr.udp.dstPort;
                    }
                    // Compute flowlet hash index
                    bit<32> hash_index;
                    hash(hash_index, 
                         HashAlgorithm.crc32,
                         (bit<10>) 0,
                         { hdr.ipv4.srcAddr,
                           hdr.ipv4.dstAddr,
                           hdr.ipv4.protocol,
                           srcPort,
                           dstPort },
                         (bit<32>) 1023);
    
                    meta.debug_pkt_flowlet_create = false;
                    meta.debug_pkt_flowlet_cached = false;
                    meta.debug_pkt_flowlet_thrash = false;
    
                    bit<32> fidx = ((bit<32>) hash_index);
    
                    meta.debug_pkt_fidx = fidx;
    
                    bit<48> ftime;
                    bit<32> fdst;
                    bit<16>  fpathId;
                    flowlet_time.read(ftime, fidx);
                    flowlet_dst.read(fdst, fidx);
                    flowlet_pathId.read(fpathId, fidx);
                    bit<32> fpidx = dst * MAX_NUM_PATHS + (bit<32>) fpathId;
    
                    // use HashBucket ranges
                    bit<16> pathId = meta.pathId;
    
                    // Check path timeout for path failure detection
                    bit<48> ptime;
                    path_time.read(ptime, (bit<32>) fpidx);
    
                    bool initial_time = (ftime == 0);
                    bool time_expired = initial_time || (standard_metadata.ingress_global_timestamp - ftime > FLOWLET_TIMEOUT);
                    bool link_failed = (standard_metadata.ingress_global_timestamp - ptime > LINK_TIMEOUT);
    
                    if (!time_expired && dst == fdst && !link_failed) {
                        meta.debug_pkt_flowlet_cached = true;
                        hdr.hulapp_data.pathId = fpathId;
                        flowlet_time.write(fidx, standard_metadata.ingress_global_timestamp);
                    } else {
                        // We use the ECMP table to lookup the pathId
                        hdr.hulapp_data.pathId = pathId;
                        // Update flowlet table if expired
                        if (time_expired || link_failed) {
                            meta.debug_pkt_flowlet_create = true;
                            flowlet_time.write(fidx, standard_metadata.ingress_global_timestamp);
                            flowlet_dst.write(fidx, dst);
                            flowlet_pathId.write(fidx, hdr.hulapp_data.pathId);
                        }
                        else {
                            meta.debug_pkt_flowlet_thrash = true;
                        }
                    }
    
                } else {  // no ip header => arp req/reply => forward without flowlet routing
                    hdr.hulapp_data.pathId = meta.pathId;
                }
            }

            tab_traffic_forward.apply();
            // Remember the outbound port for mac translation
            meta.outbound_port = standard_metadata.egress_spec;

            tab_remove_hula_header.apply();

            //tab_port_to_mac.apply();
            if (hdr.ipv4.isValid())
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            meta.debug_pkt_egress_port = standard_metadata.egress_spec;

            tab_forward_to_end_hosts.apply();

            // Update the path utilization if necessary
            if (hdr.hulapp_data.isValid()) {
                bit<64> tmp_util = 0;
                bit<48> tmp_time = 0;
                bit<64> time_diff = 0;
                local_util.read(tmp_util, (bit<32>) standard_metadata.egress_spec - 2);
                last_packet_time.read(tmp_time, (bit<32>) standard_metadata.egress_spec - 2);
                time_diff = (bit<64>)(standard_metadata.ingress_global_timestamp - tmp_time);
                bit<64> temp = tmp_util*time_diff;
                tmp_util = time_diff > UTIL_RESET_TIME_THRESHOLD ?
                           0 : (bit<64>)standard_metadata.packet_length + tmp_util - (temp >> TAU_EXPONENT);
                last_packet_time.write((bit<32>) standard_metadata.egress_spec - 2,
                                       standard_metadata.ingress_global_timestamp);
                local_util.write((bit<32>) standard_metadata.egress_spec - 2, tmp_util);

                meta.debug_pkt_util = tmp_util;
                meta.debug_pkt_time = standard_metadata.ingress_global_timestamp;
            }


            // Update HashBucket ranges
            bit<16> tmpRange;
            tmpRange = 0;

            bit<32> dst;
            dst = (bit<32>) meta.dst_switch_id;

            sumWeight.read(meta.s, dst);
            weight0.read(meta.w0, dst);
            weight1.read(meta.w1, dst);
            weight2.read(meta.w2, dst);
            weight3.read(meta.w3, dst);
            tab_cal_float_s.apply();
            tab_cal_float_w0.apply();
            tab_cal_float_w1.apply();
            tab_cal_float_w2.apply();
            tab_cal_float_w3.apply();
            tab_cal_t0_mantissa.apply();
            tab_cal_t1_mantissa.apply();
            tab_cal_t2_mantissa.apply();
            tab_cal_t3_mantissa.apply();
            tab_get_t0.apply();
            tab_get_t1.apply();
            tab_get_t2.apply();
            tab_get_t3.apply();

            tmpRange = tmpRange + meta.t0;
            range0.write(dst, tmpRange);

            tmpRange = tmpRange + meta.t1;
            range1.write(dst, tmpRange);

            tmpRange = tmpRange + meta.t2;
            range2.write(dst, tmpRange);

//            tmpRange = tmpRange + meta.t3;
//            range3.write(dst, tmpRange);

            meta.debug_pkt_s = meta.s;
            meta.debug_pkt_t0 = meta.t0;
            meta.debug_pkt_t1 = meta.t1;
            meta.debug_pkt_t2 = meta.t2;
            meta.debug_pkt_t3 = meta.t3;
            meta.debug_pkt_w0 = meta.w0;
            meta.debug_pkt_w1 = meta.w1;
            meta.debug_pkt_w2 = meta.w2;
            meta.debug_pkt_w3 = meta.w3;
            meta.debug_pkt_dst = meta.dst_switch_id;
            tab_observe_metadata_pkt.apply();

        } // end of processing hula data packet

        else if (hdr.ipv4.isValid()) { // processing probe and background traffic

            if (hdr.ipv4.protocol == HULAPP_BACKGROUND_PROTOCOL && standard_metadata.ingress_port == 1) {
                standard_metadata.egress_spec = (bit<9>)hdr.hulapp_background.port;
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;



                // Update the path utilization if necessary
                if (standard_metadata.egress_spec != 1) {
                    bit<64> tmp_util = 0;
                    bit<48> tmp_time = 0;
                    bit<64> time_diff = 0;
                    local_util.read(tmp_util, (bit<32>) standard_metadata.egress_spec - 2);
                    last_packet_time.read(tmp_time, (bit<32>) standard_metadata.egress_spec - 2);
                    time_diff = (bit<64>)(standard_metadata.ingress_global_timestamp - tmp_time);
                    bit<64> temp = tmp_util*time_diff;
                    tmp_util = time_diff > UTIL_RESET_TIME_THRESHOLD ?
                               0 : (bit<64>)standard_metadata.packet_length + tmp_util - (temp >> TAU_EXPONENT);
                    last_packet_time.write((bit<32>) standard_metadata.egress_spec - 2,
                                           standard_metadata.ingress_global_timestamp);
                    local_util.write((bit<32>) standard_metadata.egress_spec - 2, tmp_util);

                    meta.debug_pkt_util = tmp_util;
                    meta.debug_pkt_time = standard_metadata.ingress_global_timestamp;
                }

            }

            else if (hdr.ipv4.protocol == HULAPP_PROTOCOL) {

                meta.debug_probe_port = standard_metadata.ingress_port;
                meta.debug_probe_dst_tor = hdr.hulapp.dst_tor;

                bit<32> pidx = (bit<32>) hdr.hulapp.dst_tor * MAX_NUM_PATHS + (bit<32>) hdr.hulapp.pathId;

                // Update PathTable for Path Failure Detection
                path_time.write(pidx, standard_metadata.ingress_global_timestamp);

                // Update Util
                bit<64> tmp_util = 0;
                bit<48> tmp_time;
                if (standard_metadata.ingress_port != 1) {
                    local_util.read(tmp_util, (bit<32>) standard_metadata.ingress_port - 2);
                    last_packet_time.read(tmp_time, (bit<32>) standard_metadata.ingress_port - 2);
                    if ((bit<64>)(standard_metadata.ingress_global_timestamp - tmp_time) > UTIL_RESET_TIME_THRESHOLD)
                        tmp_util = 0;
                }
                hdr.hulapp.util = hdr.hulapp.util > tmp_util ? hdr.hulapp.util : tmp_util;
                meta.debug_probe_util = hdr.hulapp.util;

                tab_cal_float_util.apply(); // calculate the util_exp and util_mantissa
                tab_cal_weight_mantissa.apply(); // calculate the weight mantissa based on util_mantissa
                tab_process_probe.apply();  // update weight if source, forward otherwise
                meta.debug_probe_src_tor = hdr.hulapp.src_tor;
                meta.debug_probe_pathId = hdr.hulapp.pathId;
                meta.debug_probe_time = standard_metadata.ingress_global_timestamp;
                tab_observe_metadata_probe.apply();
            }

            else {  // not hula data packet, not hulapp probe, not background, but with ipv4 header => should not happen in our test
                tab_ipv4_lpm.apply();
            }

        }

        if (standard_metadata.egress_spec == 0 && standard_metadata.mcast_grp == 0) // avoid loopback
        {
            drop();
        }
    }

/*----------------------------------------------------------------------*/

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(
inout headers  hdr,
inout metadata meta)
{
    apply {
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ppp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.hulapp_background);
        packet.emit(hdr.hulapp);
        packet.emit(hdr.hulapp_data);
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***************************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
ParserImpl(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
DeparserImpl()
) main;
