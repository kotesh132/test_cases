
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
    bit<16> lkp_outer_l4_sport;
    bit<16> lkp_outer_l4_dport;
}

header ipv4_up_to_ihl_only_h {
    bit<4> version;
    bit<4> ihl;
}

header pie_t {
    bit<32> pie_word0;
    bit<32> pie_word1;
    bit<32> pie_word2;
    bit<24> pie_word3;
    bit<8>  pie_transition;
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
    varbit<240> options;
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
    @name("ipv4") 
    ipv4_t     ipv4;
    @name("ipv6") 
    ipv6_t     ipv6;
    @name("tcp") 
    tcp_t      tcp;
    @name("udp") 
    udp_t      udp;
    @name("ethernet") 
    ethernet_t inner_ethernet;
    @name("ipv4") 
    ipv4_t     inner_ipv4;
    @name("ipv6") 
    ipv6_t     inner_ipv6;
    @name("tcp") 
    tcp_t      inner_tcp;
    @name("udp") 
    udp_t      inner_udp;
}

headers() hdr;
metadata() meta;
standard_metadata_t() standard_metadata;

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("parse_pie") state parse_pie {
        packet.extract(hdr.pie_header);
        transition select(hdr.pie_header.pie_transition) {
            8w0x1: parse_ethernet;
            default: parse_inner_ethernet;
        }
    }
    @name("parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            16w0x86dd: parse_ipv6;
            default: accept;
        }
    }
    @name("parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4,(bit<32>) (4 * ((bit<9>) (packet.lookahead<ipv4_up_to_ihl_only_h>().ihl))));
        transition select(hdr.ipv4.fragOffset, hdr.ipv4.protocol) {
            (13w0x0, 8w0x6): parse_tcp;
            (13w0x0, 8w0x11): parse_udp;
            default: accept;
        }
    }
    @name("parse_ipv6") state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name("parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort) {
            16w0x12b5: parse_inner_ethernet;
            default:   accept;
        }
    }
    @name("parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w0x12b5: parse_inner_ethernet;
            default:   accept;
        }
    }
    @name("parse_ethernet") state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            16w0x800: parse_inner_ipv4;
            16w0x86dd: parse_inner_ipv6;
            default: accept;
        }
    }
    @name("parse_ipv4") state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4,(bit<32>) (4 * ((bit<9>) (packet.lookahead<ipv4_up_to_ihl_only_h>().ihl))));
        transition select(hdr.inner_ipv4.fragOffset, hdr.inner_ipv4.protocol) {
            (13w0x0, 8w0x6): parse_inner_tcp;
            (13w0x0, 8w0x11): parse_inner_udp;
            default: accept;
        }
    }
    @name("parse_ipv6") state parse_inner_ipv6 {
        packet.extract(hdr.inner_ipv6);
        transition select(hdr.inner_ipv6.nextHdr) {
            8w0x6: parse_inner_tcp;
            8w0x11: parse_inner_udp;
            default: accept;
        }
    }
    @name("parse_tcp") state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        transition accept;
    }
    @name("parse_udp") state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }
    @name("parse_dummy") state parse_dummy {
	transition parse_pie;
    }

    @name("start") state start {
        transition parse_dummy;
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

