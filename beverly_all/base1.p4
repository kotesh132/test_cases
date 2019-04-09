
error {
    NoError,           
    PacketTooShort,    
    NoMatch,           
    StackOutOfBounds,  
    OverwritingHeader, 
    HeaderTooShort,    
    ParserTimeout      
}

extern packet_in {
    
    void extract<T>(out T hdr);
    
    void extract<T>(out T variableSizeHeader,
                    in bit<32> variableFieldSizeInBits);
    
    T lookahead<T>();
    
    void advance(in bit<32> sizeInBits);
    
    bit<32> length();
}

extern packet_out {
    void emit<T>(in T hdr);
    void emit<T>(in bool condition, in T data);
}

extern void verify(in bool check, in error toSignal);

@name("NoAction")
action NoAction() {}

match_kind {
    exact,
    ternary,
    lpm
}

struct standard_metadata_t {
    bit<8>  ingress_port;
    bit<8>  egress_port;
}

struct fwd_metadata_t {
    bit<24> l2ptr;
    bit<24> out_bd;
}

struct l3_metadata_t {
    bit<16> lkp_l4_sport;
    bit<16> lkp_l4_dport;
}

header ipv4_up_to_ihl_only_h {
    bit<4> version;
    bit<4> ihl;
}

header pie_t {
    bit<32> pie_word0;
    bit<32> pie_word1;
    bit<32> pie_word2;
    bit<32> pie_word3;
    bit<32> pie_word4;
    bit<32> pie_word5;
    bit<32> pie_word6;
    bit<32> pie_word7;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header vntag_t {
    bit<1>  direction;
    bit<1>  pointer;
    bit<14> destVif;
    bit<1>  looped;
    bit<1>  reserved;
    bit<2>  version;
    bit<12> srcVif;
    bit<16> etherType;
}

header vlan_tag_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> etherType;
}

header cisco_cmd_pt1_header_t {
    bit<8>      version;
    bit<8>      length_;
    bit<3>      len;
    bit<13>     optionType;
}

header cisco_cmd_pt2_header_t {
    varbit<480> metadataPayload;
}

header cisco_cmd_pt3_header_t {
    bit<16> etherType;
}

header llc_header_t {
    bit<8> dsap;
    bit<8> ssap;
    bit<8> control_;
}

header snap_header_t {
    bit<24> oui;
    bit<16> type_;
}

header fcoe_header_t {
    bit<4>  version;
    bit<4>  type_;
    bit<8>  sof;
    bit<32> rsvd1;
    bit<32> ts_upper;
    bit<32> ts_lower;
    bit<32> size_;
    bit<8>  eof;
    bit<24> rsvd2;
}

header roce_header_t {
    bit<320> ib_grh;
    bit<96>  ib_bth;
}

header vxlan_t {
    bit<8>  flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8>  reserved2;
}

header gre_t {
    bit<1>  C;
    bit<1>  R;
    bit<1>  K;
    bit<1>  S;
    bit<1>  s;
    bit<3>  recurse;
    bit<5>  flags;
    bit<3>  ver;
    bit<16> proto;
}

header nvgre_t {
    bit<24> tni;
    bit<8>  flow_id;
}

header geneve_t {
    bit<2>  ver;
    bit<6>  optLen;
    bit<1>  oam;
    bit<1>  critical;
    bit<6>  reserved;
    bit<16> protoType;
    bit<24> vni;
    bit<8>  reserved2;
}

header nsh_t {
    bit<2>  version;
    bit<1>  oam;
    bit<1>  context;
    bit<6>  flags;
    bit<6>  length_;
    bit<8>  md_type;
    bit<8>  next_proto;
    bit<24> spath;
    bit<8>  sindex;
    bit<32> network_platform;
    bit<32> network_shared;
    bit<32> service_platform;
    bit<32> service_shared;
}

/*header nsh_context_t {
    
}*/

header roce_v2_header_t {
    bit<96> ib_bth;
}

header vxlan_gpe_t {
    bit<2>  flags_reserved;
    bit<2>  flags_version;
    bit<1>  flags_i;
    bit<1>  flags_p;
    bit<1>  flags_reserved2;
    bit<1>  flags_o;
    bit<16> reserved;
    bit<8>  next_proto;
    bit<24> vni;
    bit<8>  reserved2;
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
    varbit<320> options;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header ipv6exhdr_up_to_hdrextlen_only_t {
    bit<8>   nextHdr;
    bit<8>   hdrExtLen;
}

header ipv6exhdr_hopbyhop_t {
    bit<8>   nextHdr;
    bit<8>   hdrExtLen;
    varbit<240> options;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
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

struct metadata {
    @name("fwd_metadata") 
    fwd_metadata_t fwd_metadata;
    @name("l3_metadata") 
    l3_metadata_t  l3_metadata;
}

struct headers {
    @name("pie_header")
    pie_t pie_header;
    @name("ethernet") 
    ethernet_t ethernet;
    @name("vntag") 
    vntag_t vntag;
    @name("vlan_tag_0") 
    vlan_tag_t vlan_tag_0;
    @name("cmd_pt1") 
    cisco_cmd_pt1_header_t cmd_pt1;
    @name("cmd_pt2") 
    cisco_cmd_pt2_header_t cmd_pt2;
    @name("cmd_pt3") 
    cisco_cmd_pt3_header_t cmd_pt3;
    @name("llc_header") 
    llc_header_t llc_header;
    @name("snap_header") 
    snap_header_t snap_header;
    @name("roce") 
    roce_header_t roce;
    @name("fcoe") 
    fcoe_header_t fcoe;
    @name("ipv6") 
    ipv6_t     ipv6;
    @name("ipv6_hopbyhop_0")
    ipv6exhdr_hopbyhop_t ipv6_hopbyhop_0;
    @name("ipv6_hopbyhop_1")
    ipv6exhdr_hopbyhop_t ipv6_hopbyhop_1;
    @name("ipv4") 
    ipv4_t     ipv4;
    @name("gre") 
    gre_t gre;
    @name("nvgre") 
    nvgre_t nvgre;
    @name("udp") 
    udp_t      udp;
    @name("vxlan_gpe") 
    vxlan_gpe_t vxlan_gpe;
    @name("nsh") 
    nsh_t nsh;
    @name("roce_v2") 
    roce_v2_header_t roce_v2;
    @name("geneve") 
    geneve_t geneve;
    @name("vxlan") 
    vxlan_t vxlan;
    @name("tcp") 
    tcp_t      tcp;
}

headers() hdr;
metadata() meta;
standard_metadata_t() standard_metadata;

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("parse_pie") state parse_pie {
        packet.extract(hdr.pie_header);
        transition parse_ethernet;
    }
    @name("parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x564E: parse_vntag;
            16w0x8100: parse_vlan;
            //TODO Hyper Edge?
            //16w0x88a8: parse_vlan;
            //TODO Clarify with Andy
            //16w0x9100: parse_qinq;

            16w0x8909: parse_cmd_pt1;
            //16w0x0000 &&& 16w0xfc00: parse_llc_header; 
            //16w0x0400 &&& 16w0xfe00: parse_llc_header;
            16w0x0400: parse_llc_header;
            16w0x0800: parse_ipv4; 
            16w0x86dd: parse_ipv6; 
            16w0x8906: parse_fcoe; 
            16w0x8915: parse_roce;
            default: accept;
        }
    }

    @name("parse_vntag") state parse_vntag {
        packet.extract(hdr.vntag);
        transition select(hdr.vntag.etherType) {
            16w0x8100: parse_vlan;
            //16w0x88a8: parse_vlan;
            //16w0x9100: parse_qinq;
            16w0x8909: parse_cmd_pt1;
            //16w0x0000 &&& 0xfc00: parse_llc_header; 
            //16w0x0400 &&& 0xfe00: parse_llc_header;
            16w0x0400: parse_llc_header;
            16w0x0800: parse_ipv4; 
            16w0x86dd: parse_ipv6; 
            16w0x8906: parse_fcoe; 
            16w0x8915: parse_roce;
            default: accept;
        }
    }

    @name("parse_vlan") state parse_vlan {
        packet.extract(hdr.vlan_tag_0);
        transition select(hdr.vlan_tag_0.etherType) {
            //16w0x9100: parse_qinq;
            16w0x8909: parse_cmd_pt1;
            //16w0x0000 &&& 0xfc00: parse_llc_header; 
            16w0x0400: parse_llc_header;
            16w0x0800: parse_ipv4; 
            16w0x86dd: parse_ipv6; 
            16w0x8906: parse_fcoe; 
            16w0x8915: parse_roce;
            default: accept;
        }
    }

    state parse_cmd_pt1 {
        packet.extract(hdr.cmd_pt1);
        transition select(hdr.cmd_pt1.length_) {
            8w0x0: parse_cmd_pt2;
            default: accept;
        }
    }
    state parse_cmd_pt2 {
        packet.extract(hdr.cmd_pt2,(bit<32>) (4 * (bit<9>) hdr.cmd_pt1.length_));
        transition parse_cmd_pt3;
    }

    state parse_cmd_pt3 {
        packet.extract(hdr.cmd_pt3);
        transition select(hdr.cmd_pt3.etherType) {
            //0x0000 &&& 0xfc00: parse_llc_header; 
            //0x0400 &&& 0xfe00: parse_llc_header;
            16w0x0400: parse_llc_header;
            16w0x0800: parse_ipv4; 
            16w0x86dd: parse_ipv6; 
            16w0x8906: parse_fcoe; 
            16w0x8915: parse_roce;
            default: accept;
        }
    }

    state parse_llc_header {
        packet.extract(hdr.llc_header);
        transition select(hdr.llc_header.dsap, hdr.llc_header.ssap) {
            (8w0xaa, 8w0xaa): parse_snap_header;
            default: accept;
        }
    }
    state parse_snap_header {
        packet.extract(hdr.snap_header);
        transition select(hdr.snap_header.type_) {
            16w0x0800: parse_ipv4; 
            16w0x86dd: parse_ipv6; 
            16w0x8906: parse_fcoe; 
            16w0x8915: parse_roce;
            default: accept;
        }
    }

    @name("parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4,(bit<32>) (4 * ((bit<9>) (packet.lookahead<ipv4_up_to_ihl_only_h>().ihl))));
        transition select(hdr.ipv4.fragOffset, hdr.ipv4.protocol) {
            (13w0x0, 8w0x6): parse_tcp;
            (13w0x0, 8w0x11): parse_udp;
            (13w0x0, 8w0x2f): parse_gre;
            default: accept;
        }
    }
    @name("parse_ipv6") state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            8w0x0: parse_ipv6ext_hopbyhop_0;
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            8w0x2f: parse_gre;
            default: accept;
        }
    }

    state parse_ipv6ext_hopbyhop_0 {
        packet.extract(hdr.ipv6_hopbyhop_0,(bit<32>) (8 * packet.lookahead<ipv6exhdr_up_to_hdrextlen_only_t>().hdrExtLen + 6));
        transition select (hdr.ipv6_hopbyhop_0.nextHdr) {
            8w0x0: parse_ipv6ext_hopbyhop_1;
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            8w0x2f: parse_gre;
            default: accept;
        }
    }

    state parse_ipv6ext_hopbyhop_1 {
        packet.extract(hdr.ipv6_hopbyhop_1,(bit<32>) (8 * packet.lookahead<ipv6exhdr_up_to_hdrextlen_only_t>().hdrExtLen + 6));
        transition select (hdr.ipv6_hopbyhop_1.nextHdr) {
            //8w0x0: parse_ipv6ext_hopbyhop_1;
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            8w0x2f: parse_gre;
            default: accept;
        }
    }

    state parse_fcoe {
        packet.extract(hdr.fcoe);
        transition accept;
    }
    state parse_roce {
        packet.extract(hdr.roce);
        transition accept;
    }

    @name("parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        meta.l3_metadata.lkp_l4_sport = hdr.tcp.srcPort;
        meta.l3_metadata.lkp_l4_dport = hdr.tcp.dstPort;
        transition accept;
    }
    @name("parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        meta.l3_metadata.lkp_l4_sport = hdr.udp.srcPort;
        meta.l3_metadata.lkp_l4_dport = hdr.udp.dstPort;
        //transition accept;
        transition select(hdr.udp.dstPort) {
            16w0x12b5: parse_vxlan;
            16w0x17c1: parse_geneve;
            //TODO Hyper Edge
            //4791: parse_roce_v2;
            16w0x5ba0: parse_roce_v2;
            16w0x12b6: parse_vxlan_gpe;
            default: accept;
        }
    }
state parse_gre {
        packet.extract(hdr.gre);
        //
        //transition select(hdr.gre.C, hdr.gre.R, hdr.gre.K, hdr.gre.S, hdr.gre.s,
        //                  hdr.gre.recurse, hdr.gre.flags, hdr.gre.ver,
        //                  hdr.gre.proto) {
        transition select(hdr.gre.proto){
            16w0x6558: parse_nvgre;
            default: accept;
        }
    }
    state parse_nvgre {
        packet.extract(hdr.nvgre);
        //meta.l4_meta.l4_info_is_nvgre = 1;
        //TODO transition to inner
        transition accept;
    }

    state parse_vxlan {
        packet.extract(hdr.vxlan);
        //meta.l4_meta.l4_info_vxlan_vnid = hdr.vxlan.vni ++ hdr.vxlan.reserved2;
        //TODO transition to inner
        transition accept;
    }

    state parse_geneve {
        packet.extract(hdr.geneve);
        //meta.l4_meta.l4_info_geneve_vnid = hdr.geneve.vni ++ hdr.geneve.reserved2;
        //TODO transition to inner
        transition accept;
    }

    state parse_roce_v2 {
        packet.extract(hdr.roce_v2);
        transition accept;
    }

    state parse_vxlan_gpe {
        packet.extract(hdr.vxlan_gpe);
        transition select(hdr.vxlan_gpe.next_proto) {
            //(1, 0x03): inner_parse_ethernet;
            8w0x04: parse_nsh;
            default: accept;
        }
    }
    state parse_nsh {
        packet.extract(hdr.nsh);
        //packet.extract(hdr.nsh_context);
        transition accept;
    }

    @name("start") state start {
        transition parse_pie;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("NoAction") action NoAction() {
    }
    @name("action1") action action1(bit<24> ptr) {
        meta.fwd_metadata.l2ptr = ptr;
    }
    @name("action2") action action2(bit<24> bd) {
        meta.fwd_metadata.out_bd = bd;
    }
    @name("action3") action action3(bit<32> dst_adr) {
        hdr.ipv4.dstAddr = dst_adr;
    }
    @name("action4") action action4(bit<32> src_adr) {
        hdr.ipv4.srcAddr = src_adr;
    }
    @name("action5") action action5(bit<16> ipv6_payloadLen) {
        hdr.ipv6.payloadLen = ipv6_payloadLen;
    }
    @name("action6") action action6(bit<16> tcp_srcPort) {
        hdr.tcp.srcPort = tcp_srcPort;
    }
    @name("action7") action action7(bit<16> udp_srcPort) {
        hdr.udp.srcPort = udp_srcPort;
    }

    @name("table1") table table1 {
        actions = {
            action1;
            @default_only NoAction;
        }
        key = {
            hdr.ethernet.dstAddr: ternary;
        }
        default_action = NoAction();
    }
    @name("table2") table table2 {
        actions = {
            action2;
            @default_only NoAction;
        }
        key = {
            hdr.ethernet.srcAddr: ternary;
        }
        default_action = NoAction();
    }
    @name("table3") table table3 {
        actions = {
            action3;
            @default_only NoAction;
        }
        key = {
            meta.fwd_metadata.l2ptr: ternary;
        }
        default_action = NoAction();
    }
    @name("table4") table table4 {
        actions = {
            action4;
            @default_only NoAction;
        }
        key = {
            meta.fwd_metadata.out_bd: ternary;
        }
        default_action = NoAction();
    }
    @name("table5") table table5 {
        actions = {
            action5;
            @default_only NoAction;
        }
        key = {
            hdr.ethernet.srcAddr: ternary;
        }
        default_action = NoAction();
    }
    @name("table6") table table6 {
        actions = {
            action6;
            @default_only NoAction;
        }
        key = {
            hdr.ethernet.srcAddr: ternary;
        }
        default_action = NoAction();
    }
    @name("table7") table table7 {
        actions = {
            action7;
            @default_only NoAction;
        }
        key = {
            hdr.ethernet.srcAddr: ternary;
        }
        default_action = NoAction();
    }
    apply {
        table1.apply();
        table2.apply();
        if(hdr.ipv4.isValid()){
 	    if(hdr.ipv4.srcAddr != hdr.ipv4.dstAddr){
    	        table3.apply();
	    }
            table4.apply();
        }

        if(hdr.ipv6.isValid()){
            table5.apply();
        }
        if(hdr.tcp.isValid()){
            table6.apply();
        }
        if(hdr.udp.isValid()){
            table7.apply();
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(in headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

