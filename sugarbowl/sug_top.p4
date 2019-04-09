#include <core.p4>

// There are several tables in this program that are only defined and
// apply'd if you #define EXTRA_DEBUG.  They have only the action
// NoAction, so they cannot change the packet forwarding behavior.
// The bmv2 simple_switch executable, when you enable --log-console or
// --log-file, will show the values of all header and metadata fields
// that are part of a table search key whenever the table is apply'd,
// regardless of whether there is a match in the table or not.  This
// provides a quick way to 'debug printf' the values of those header
// and metadata fields at that point in the execution.  That in turn
// can help a developer quickly determine which if/else paths a
// control block follows.
#define EXTRA_DEBUG

// Normally you want all of these to be #define'd.  The only reason to
// #undef any of them is to do a quick and dirty test of whether
// ingress code is accessing egress metadata, or vice versa, since
// metadata for both is currently combined into one big struct right
// now.
#define INCLUDE_PARSER
//#define INCLUDE_INGRESS
//#define INCLUDE_EGRESS

#include <v1model.p4>

#include "includes/sug_p4features.h"
#include "sug_parser_defines.p4"
#include "sug_eg_parser_defines.p4"
#include "includes/sug_defines.p4"

// Collections of search key fields and match types common across
// multiple ingress ACL TCAM search key formats.

#define CMN_ACL_KEY \
    hdr.ieth.isValid()             : exact; \
    hdr.ieth.sup_tx                : ternary; \
    hdr.ieth.tclass                : ternary; \
    meta.l3.l3_type              : ternary; \
    meta.l2.l2_da_type           : ternary; \
    meta.src_if.acl_label        : ternary; \
    meta.src_bd.acl_label        : ternary; \
    meta.ig_tunnel.decap         : ternary; \
    meta.ig_tunnel.src_encap_type: ternary; \
    meta.src_tep.src_ptr         : ternary; \
    meta.ingress.l2_fwd_mode     : ternary; \
    meta.ingress.l3_fwd_mode     : ternary; \
    meta.ig_acl.src_mac_label    : ternary; \
    meta.ig_acl.dst_mac_label    : ternary; \
    meta.l2.l2_src_hit           : ternary; \
    meta.l2.l2_dst_hit           : ternary; \
    meta.dst_mac.sup_copy        : ternary; \
    meta.dst_mac.sup_redirect    : ternary; \
    meta.src_bd.sg_label         : ternary; \
    meta.pt_key.src_class        : ternary; \
    meta.pt_key.dst_class        : ternary; \
    meta.ingress.src_bd          : ternary;

#define IPV4_FLOW_KEY \
    meta.ipv4m.lkp_ipv4_sa        : ternary; \
    meta.ipv4m.lkp_ipv4_da        : ternary; \
    meta.l3.lkp_ip_proto         : ternary; \
    meta.l3.lkp_l4_sport         : range; \
    meta.l3.lkp_l4_dport         : range; \
    meta.l3.lkp_ip_ttl           : ternary; \
    meta.l3.lkp_ip_flag_more     : ternary; \
    meta.l3.ipfrag               : ternary; \
    meta.src_bd.ipv4_ucast_en    : ternary; \
    meta.src_bd.ipv4_mcast_en    : ternary; \
    meta.src_bd.igmp_snp_en      : ternary; \
    meta.dst_fib.da_sup_redirect : ternary; \
    meta.dst_fib.sup_copy        : ternary; \
    hdr.tcp.flags                  : ternary;

#define IPV6_FLOW_KEY \
    meta.ipv6m.lkp_ipv6_sa        : ternary; \
    meta.ipv6m.lkp_ipv6_da        : ternary; \
    meta.l3.lkp_ip_proto         : ternary; \
    meta.l3.lkp_l4_sport         : range; \
    meta.l3.lkp_l4_dport         : range; \
    meta.l3.lkp_ip_ttl           : ternary; \
    meta.l3.lkp_ip_flag_more     : ternary; \
    meta.l3.ipfrag               : ternary; \
    meta.src_bd.ipv6_ucast_en    : ternary; \
    meta.src_bd.ipv6_mcast_en    : ternary; \
    meta.src_bd.mld_snp_en       : ternary; \
    meta.dst_fib.da_sup_redirect : ternary; \
    meta.dst_fib.sup_copy        : ternary; \
    hdr.tcp.flags                  : ternary;

#define MAC_FLOW_KEY \
    meta.l2.lkp_mac_sa           : ternary; \
    meta.l2.lkp_mac_da           : ternary; \
    hdr.ethernet.etherType         : ternary;


// Collections of search key fields and match types common across
// multiple egress ACL TCAM search key formats.

#define EG_CMN_ACL_KEY \
    meta.l3.l3_type             : ternary; \
    meta.dst_if.if_label        : ternary; \
    meta.dst_bd.bd_label        : ternary; \
    meta.egress.tunnel_decap    : ternary; \
    meta.egress.tunnel_encap    : ternary; \
    meta.ig_tunnel.src_encap_pkt: ternary; \
    meta.egress.l2_fwd_mode     : ternary; \
    meta.egress.l3_fwd_mode     : ternary; \
    meta.dp_eg_header.localcpu           : ternary; \
    meta.dp_eg_header.spanvld            : ternary;

#define EG_IPV4_FLOW_KEY \
    meta.ipv4m.lkp_ipv4_sa       : ternary; \
    meta.ipv4m.lkp_ipv4_da       : ternary; \
    meta.l2.l2_da_type          : ternary; \
    meta.l3.lkp_ip_proto        : ternary; \
    meta.l3.lkp_l4_sport        : ternary; \
    meta.l3.lkp_l4_dport        : ternary;

#define EG_IPV6_FLOW_KEY \
    meta.ipv6m.lkp_ipv6_sa       : ternary; \
    meta.ipv6m.lkp_ipv6_da       : ternary; \
    meta.l2.l2_da_type          : ternary; \
    meta.l3.lkp_ip_proto        : ternary; \
    meta.l3.lkp_l4_sport        : ternary; \
    meta.l3.lkp_l4_dport        : ternary;

#define EG_MAC_FLOW_KEY \
    meta.l2.lkp_mac_sa          : ternary; \
    meta.l2.lkp_mac_da          : ternary; \
    meta.l2.l2_da_type          : ternary; \
    hdr.ethernet.etherType        : ternary;

struct CFG_aci_tor_mode_t {
    bit<1> enable;
}

struct CFG_ip_frag_t {
    bit<13> offset0;
    bit<13> offset1;
}

struct CFG_BdServiceBypassInfo_t {
    bit<1> rpf_bypass; // Force RPF to pass
    bit<1> keep_ieth;
    bit<1> outer_vlan_xlate_bypass; // Bypass Outer VLAN translation, Use outer_bd from ieth hdr 
    bit<1> is_rmac_bypass; // Bypass the operation.     
    bit<1> eg_mtu_check_bypass; // Bypass the operation.     
    bit<1> pt_bypass; // Bypass PT lookup.               
    bit<1> fwd_lookup_bypass; // Bypass Host address lookups  
    bit<1> acl_bypass; // Bypass the operation.     
    bit<1> learn_bypass;
    bit<1> sup_rx_bypass;
}

struct CFG_mark_t {
    bit<1> override;
    bit<1> val;
}

struct acl_redirect_t {
    bit<1>  drop;
    bit<16> l3_base_ptr_or_met_ptr;
    bit<1>  use_met;
    bit<13> l3_num_paths;
    bit<1>  decap_vld;
    bit<1>  src_if_pruning_bypass;
    bit<6>  mc_slice_vec;
    bit<1>  l3_hash_prof_sel;
    bit<2>  l2_fwd_mode;
    bit<2>  l3_fwd_mode;
    bit<1>  omf;
    bit<1>  sup_copy;
    bit<1>  encap_vld;
    bit<14> encap_idx;
    bit<1>  redirect;
    bit<1>  redirect_to_src;
    bit<5>  ieth_sup_code;
    bit<1>  ieth_sup_code_vld;
    bit<1>  vnid_use_epg;
    bit<4>  drop_mask_select;
    bit<14> dst_idx;
    bit<11> l2_base_ptr;
    bit<10> l2_num_paths;
    bit<1>  l2_hash_prof_sel;
    bit<1>  bd_rw;
    bit<1>  ce_sa_rw;
    bit<1>  ce_da_rw;
    bit<14> bd;
    bit<48> ce_da;
    bit<13> encap_l2_idx;
    bit<9>  outer_bd;
    bit<1>  rw_adj_vld;
    bit<14> rw_adj;
    bit<9>  ovector_idx;
    bit<8>  dst_chip;
    bit<8>  dst_port;
    bit<12> l3_ecmp_mbr;
    bit<11> l2_pc_mbr;
}

struct bypass_info_t {
    bit<1> outer_vlan_xlate_bypass;
    bit<1> rpf_bypass;
    bit<1> is_rmac_bypass;
    bit<1> pt_bypass;
    bit<1> fwd_lookup_bypass;
    bit<1> acl_bypass;
    bit<1> learn_bypass;
    bit<1> sup_rx_bypass;
    bit<1> eg_mtu_check_bypass;
}

struct dp_eg_intrinsic_t {
    bit<4>  oclass;
    bit<4>  fceof;
    bit<4>  fcsof;
    bit<6>  oport;
    bit<1>  drop;
    bit<14> blen;
    bit<1>  ecnmark;
    bit<1>  localcpu;
    bit<1>  cpu;
    bit<3>  oqueue;
    bit<13> ovidx;
    bit<16> met_index;
    bit<1>  cputransit;
    bit<1>  met_v;
    bit<1>  met1_v;
    bit<1>  mcast;
    bit<1>  spantr_v;
    bit<5>  spansess;
    bit<1>  spanvld;
    bit<1>  service_copy;
}

struct dp_ig_intrinsic_t {
    bit<9>  ingress_port;
    bit<2>  port_type;
    bit<48> ingress_global_tstamp;
    bit<8>  tdmid;
    bit<11> pktid;
}

struct dst_adj_t {
    bit<48> mac;
    bit<14> bd;
    bit<1>  is_ptr;
    bit<14> ptr_or_idx;
}

struct dst_bd_t {
    bit<14> bd_stats_idx;
    bit<10> rmac_index;
    bit<14> bd_label;
    bit<1>  cts_en;
    // TBD: These fields are used in some code not surrounded by
    // #ifdef ACI_TOR_MODE.
    bit<14> scope;
    bit<1>  bypass_self_fwd_check;
    bit<1>  bypass_same_vtep_check;
//#ifdef ACI_TOR_MODE
    bit<16> sclass;
//#else  /*ACI_TOR_MODE*/
    bit<1> l2mp_en;
    bit<3> vft_idx;
    bit<1> dce_bd_bypass;
    bit<1> provider_bd;
    bit<1> keep_inner_qtag;
//#endif /*ACI_TOR_MODE*/
    //	ifmbr : 50; //
    bit<4> mtu_idx;
}

struct dst_fib_t {
    bit<1>  sup_copy;
    bit<1>  sa_sup_redirect;
    bit<1>  da_sup_redirect;
    bit<1>  sa_direct_connect;
    bit<1>  ttl_decrement_bypass;
    bit<1>  default_entry;
    // TBD: Moved outside of ACI_TOR_MODE #ifdef since it was used
    // outside of one.
    bit<1>  preserve_vrf;
    bit<1>  ep_bounce;
    bit<1>  spine_proxy;
//#ifdef ACI_TOR_MODE
    bit<2>  class_pri;
    bit<16> class;
    bit<16> epg;
    bit<1>  policy_incomplete;
    bit<1>  bind_notify_en;
    bit<1>  class_notify_en;
    bit<1>  addr_notify_en;
    bit<1>  ivxlan_dl;
    bit<1>  policy_applied;
    bit<1>  shared_service;
    bit<12> sg_label;
    bit<1>  dst_local;
//#else  /*ACI_TOR_MODE*/
    bit<16> sgt;
//#endif /*ACI_TOR_MODE*/
}

struct dst_if_t {
    bit<13> bd_xlate_idx;
    bit<12> if_label;
    bit<2>  cts_mode;
    bit<12> default_vlan;
    bit<1>  is_l2_trunk;
    bit<1>  untag_default_vlan;
    bit<1>  priority_tag_default_vlan;
    bit<1>  same_vtep_prune_en;
    bit<1>  sclass_sgt_xlate_miss_drop;
    bit<2>  provider_type;
    bit<2>  vlan_mode;
}

struct mac_key_t {
    bit<14> bd;
    bit<48> addr;
}

struct dst_mac_t {
    bit<14> bd;
    bit<48> mac;
    bit<14> ptr_or_idx;
    bit<1>  is_ptr;
    bit<1>  preserve_vrf;
    bit<1>  sup_copy;
    bit<1>  sup_redirect;
    bit<1>  ep_bounce;
    bit<1>  spine_proxy;
    bit<2>  learn_info;
    bit<1>  dst_local;
    bit<1>  default_entry;
    bit<2>  class_pri;
    bit<16> class;
    bit<16> epg;
    bit<1>  policy_incomplete;
    bit<1>  bind_notify_en;
    bit<1>  class_notify_en;
    bit<1>  addr_notify_en;
    bit<1>  ivxlan_dl;
    bit<1>  policy_applied;
    bit<1>  shared_service;
    bit<1>  vnid_use_bd;
    bit<1>  dst_vpc;
}

struct dst_port_t {
    bit<3>  fabric_if_stats_idx;
    bit<1>  vnic_if;
    bit<12> if_idx;
    bit<7>  uc_vif_xlate_idx;
    bit<7>  mc_vif_xlate_idx;
    bit<8>  dst_chip;
    bit<8>  dst_port;
    bit<1>  ihdr_if;
    bit<1>  tunnel_edge_mc;
    bit<1>  block_bc;
    bit<1>  block_uuc;
    bit<1>  block_umc;
    bit<2>  qtag_mode;
    bit<2>  vntag_mode;
    bit<1>  vntag_dir;
    bit<1>  is_l2_trunk;
    bit<1>  priority_tag_default_vlan;
    bit<1>  untag_default_vlan;
    bit<1>  src_if_check_en;
    bit<8>  pcnum;
    bit<1>  qinq_if;
    bit<13> vnic_mcast_vif;
    bit<13> default_vif;
    bit<2>  drop_count_mask_sel;
    bit<1>  pif_drop_mask_sel;
    bit<1>  cts_override;
    bit<1>  src_addr_port_type;
    bit<1>  port_is_fabric;
    bit<10> dmac_idx;
}

struct eg_acl_t {
    bit<1>  vacl_hit;
    bit<1>  copp_hit;
    bit<1>  qos_hit;
    bit<12> vacl_hit_idx;
    bit<12> copp_hit_idx;
    bit<12> qos_hit_idx;
}

struct eg_bypass_t {
    bit<1> l2_rw_bypass;
    bit<1> service_rw_bypass;
    bit<1> tunnel_decap_bypass;
    bit<1> tunnel_encap_bypass;
    bit<1> vntag_bypass;
    bit<1> qtag_bypass;
    bit<1> cmd_bypass;
    bit<1> ttag_bypass;
    bit<1> ttl_dec_bypass;
    bit<1> ecn_mark_bypass;
    bit<1> qos_rw_bypass;
    bit<1> nat_rw_bypass;
    bit<1> acl_bypass;
    bit<1> eg_mtu_check_bypass;
    bit<1> switchport_block_bypass;
    bit<1> vlan_mbr_chk_bypass;
    bit<1> same_if_check_bypass;
    bit<1> same_vtep_check_bypass;
}

struct eg_dp_intrinsic_t {
    bit<1> drop;
}

struct eg_drop_t {
    bit<1> inc_drop_counters;
    bit<1> acl_deny;
    bit<1> switchport_block_bc;
    bit<1> switchport_block_umc;
    bit<1> switchport_block_uuc;
    bit<1> vlan_mbr;
    bit<1> same_if_check;
    bit<1> same_vif_uc;
    bit<1> ttl_expired;
    bit<1> sup_policer_drop;
    bit<1> mc_dvif_xlate_miss;
    bit<1> uc_dvif_xlate_miss;
    bit<1> vlan_xlate_miss;
    bit<1> vnid_xlate_miss;
    bit<1> mc_met_core_if_prune;
    bit<1> l3_same_if_mc;
    bit<1> sup_tx_mask;
    bit<1> same_vtep;
    bit<1> sclass_sgt_xlate_miss;
    bit<1> epg_cross;
    bit<1> svif_xlate_miss;
    bit<1> qos_drop;
    bit<1> qos_policer_drop;
}

struct eg_l3_t {
    bit<1>   ipv4_nat_l3_src_rw;
    bit<32>  ipv4_nat_l3_src_addr;
    bit<32>  ipv4_nat_l3_src_addr_mask;
    bit<1>   ipv6_nat_l3_src_rw;
    bit<128> ipv6_nat_l3_src_addr;
    bit<128> ipv6_nat_l3_src_addr_mask;
    bit<1>   nat_l4_src_rw;
    bit<16>  nat_l4_src_addr;
    bit<1>   ipv4_nat_l3_dst_rw;
    bit<32>  ipv4_nat_l3_dst_addr;
    bit<32>  ipv4_nat_l3_dst_addr_mask;
    bit<1>   ipv6_nat_l3_dst_rw;
    bit<128> ipv6_nat_l3_dst_addr;
    bit<128> ipv6_nat_l3_dst_addr_mask;
    bit<1>   nat_l4_dst_rw;
    bit<16>  nat_l4_dst_addr;
}

struct eg_local_t {
    bit<12>  erspan_vlan;
    bit<3>   erspan_cos;
    bit<2>   erspan_en;
    bit<2>   erspan_bso;
    bit<1>   erspan_t;
    bit<20>  erspan_idx;
    bit<32>  erspan_tstmp;
    bit<32>  erspan_tstmp_hi;
    bit<10>  erspan_ses;
    bit<2>   erspan_gra;
    bit<32>  erspan_seq_num;
    bit<1>   span_dir;
    bit<1>   src_qtag0_vld;
    bit<12>  src_qtag0_vid;
    bit<3>   src_qtag0_pcp;
    bit<1>   dst_qtag0_vld;
    bit<12>  dst_qtag0_vid;
    bit<3>   dst_qtag0_pcp;
    bit<1>   mc_dvif_key_alt_vntag;
    bit<13>  mc_dvif_key_mc_idx;
    bit<8>   chosen_ttl;
    bit<8>   final_ttl;
    bit<8>   outer_src_ttl;
    bit<8>   outer_dst_ttl;
    bit<6>   outer_dscp;
    bit<2>   outer_ecn;
    bit<3>   outer_cos;
    bit<1>   outer_de;
    bit<32>  outer_ipv4_sa;
    bit<128> outer_ipv6_sa;
    bit<1>   cbl_state;
    bit<12>  encap_vlan;
    bit<1>   is_default_vlan;
    bit<13>  dst_tep_stats_idx;
    bit<13>  dst_port_stats_idx;
    bit<11>  dst_port_class_stats_idx;
}

struct eg_qos_acl_t {
    bit<1>  policer_apply;
    bit<1>  mark_policer_apply;
    bit<10> pol_idx;
    bit<1>  qos_map_vld;
    bit<11> qos_map_idx;
}

struct eg_qos_t {
    bit<11> qos_map_idx;
    bit<3>  oqueue;
    bit<3>  cos;
    bit<1>  de;
    bit<6>  dscp;
    bit<4>  tc;
    bit<1>  cos_rw;
    bit<1>  de_rw;
    bit<1>  dscp_rw;
    bit<1>  tc_rw;
    bit<3>  ol_cos;
    bit<1>  ol_de;
    bit<6>  ol_dscp;
    bit<1>  ol_cos_rw;
    bit<1>  ol_de_rw;
    bit<1>  ol_dscp_rw;
    bit<1>  dscp_coi;
    bit<1>  dscp_cio;
}

struct eg_src_port_t {
    bit<1> vnic_if;
    bit<8> pcnum;
    bit<1> l3if;
    bit<1> core_if;
    bit<4> domain;
    bit<1> keep_inner_qtag;
    bit<1> ttag_rw;
    bit<2> provider_port_type;
}

struct eg_tunnel_t {
    bit<1>  encap;
    bit<1>  l3_tunnel_encap;
    bit<13> encap_ecmp_ptr;
    bit<4>  dst_encap_type;
    bit<2>  dst_encap_l3_type;
    bit<3>  dst_encap_l4_type;
    bit<13> encap_idx;
    bit<13> encap_l2_idx;
    bit<14> outer_dst_bd;
    bit<24> dst_vnid;
    bit<1>  inner_dst_bd_xlate_hit;
    bit<13> inner_dst_bd_xlate_idx;
    bit<9>  ipv4_sipo_rw_ptr;
    bit<7>  ipv6_sipo_rw_ptr;
    bit<13> ipv4_dipo_rw_ptr;
    bit<11> ipv6_dipo_rw_ptr;
    bit<16> encap_ip_len;
    bit<1>  ttl_cio;
    bit<2>  cts_mode;
    bit<4>  src_sh_group;
    bit<4>  dst_sh_group;
}

struct egress_t {
    bit<1>  bypass;
    bit<5>  bypass_code;
    bit<2>  port_type;
    bit<7>  dst_port;
    bit<2>  vlan_mode;
    bit<16> payload_length;
    bit<14> dst_bd;
    bit<14> outer_dst_bd;
    bit<14> inner_dst_bd;
    bit<14> inner_epg_or_bd;
    bit<12> smac_idx;
    bit<1>  routed;
    bit<1>  is_unicast;
    bit<14> same_bd_check;
    bit<64> drop_vector;
    bit<6>  drop_reason;
    bit<1>  same_src_check;
    bit<4>  src_encap_type;
    bit<1>  tunnel_decap;
    bit<1>  tunnel_encap;
    bit<1>  src_l3_tunnel;
    bit<1>  met_vld;
    bit<16> met_ptr;
    bit<1>  use_met;
    bit<1>  use_encap;
    bit<1>  adj_vld;
    bit<14> adj_idx;
    bit<14> epg_or_bd;
    bit<1>  encap_vld;
    bit<14> encap_idx;
    bit<2>  l2_fwd_mode;
    bit<2>  l3_fwd_mode;
    bit<1>  same_epg;
    bit<1>  same_bd;
    bit<1>  same_encap;
    bit<16> pkt_len;
    bit<1>  copy_service;
    bit<13> dst_if_idx;
    bit<14> dst_epg;
    bit<14> inner_dst_epg;
}

struct hash_t {
    bit<16> hash1;
    bit<16> hash2;
    bit<16> flowlet_hash;
    bit<16> entropy_hash;
    bit<13> flowlet_map_index;
    bit<13> flowlet_id;
    bit<32> flow_ipg;
    bit<32> flowlet_lasttime;
}

struct ig_acl_t {
    bit<12> src_mac_label;
    bit<12> dst_mac_label;
    bit<1>  sup_hit;
    bit<1>  pacl_hit;
    bit<1>  vacl_hit;
    bit<1>  racl_hit;
    bit<1>  output_acl_hit;
    bit<1>  fstat0_hit;
    bit<1>  fstat1_hit;
    bit<1>  fstat2_hit;
    bit<1>  fstat3_hit;
    bit<12> sup_hit_idx;
    bit<12> pacl_hit_idx;
    bit<12> vacl_hit_idx;
    bit<12> racl_hit_idx;
    bit<12> output_acl_hit_idx;
    bit<12> fstat0_hit_idx;
    bit<12> fstat1_hit_idx;
    bit<12> fstat2_hit_idx;
    bit<12> fstat3_hit_idx;
    bit<1>  permit_log_ready;
    bit<1>  deny_log_ready;
    bit<1>  permit_log;
    bit<1>  deny_log;
    bit<6>  sup_code;
    bit<2>  sup_dst;
    bit<8>  sup_qnum;
    bit<1>  sup_redirect;
    bit<1>  sup_copy;
    bit<2>  sup_pri;
    bit<4>  drop_mask_select;
    bit<1>  redirect;
    bit<3>  redirect_type;
    bit<16> redirect_ptr;
    bit<1>  nat_redirect;
    bit<1>  nat_rewrite;
    bit<1>  tstmp_1588_out;
    bit<16> mac_spare;
    bit<16> ipv4_spare;
    bit<16> ipv6_spare;
    bit<96> drop_mask;
    bit<1>  qos_vld;
    bit<11> qos_map_idx;
    bit<1>  qos_policer_mark;
    bit<11> mark_qos_map_idx;
    bit<1>  flood_to_epg;
    bit<1>  missing_vntag_drop_mask;
    bit<1>  illegal_vntag_drop_mask;
    bit<1>  src_if_miss_drop_mask;
    bit<1>  src_vlan_mbr_drop_mask;
    bit<1>  src_tep_miss_drop_mask;
    bit<1>  iic_check_failure_drop_mask;
    bit<1>  outer_ttl_expired_drop_mask;
    bit<1>  vlan_xlate_miss_drop_mask;
    bit<1>  ttl_expired_drop_mask;
    bit<1>  routing_disabled_drop_mask;
    bit<1>  sgt_xlate_miss_drop_mask;
    bit<1>  src_nat_drop_drop_mask;
    bit<1>  dst_nat_drop_drop_mask;
    bit<1>  twice_nat_drop_drop_mask;
    bit<1>  smac_miss_drop_mask;
    bit<1>  route_miss_drop_mask;
    bit<1>  bridge_miss_drop_mask;
    bit<1>  mtu_check_failure_drop_mask;
    bit<1>  uc_rpf_failure_drop_mask;
    bit<1>  mc_rpf_failure_drop_mask;
    bit<1>  l3_binding_failure_drop_mask;
    bit<1>  ipv6_uc_link_local_cross_bd_drop_mask;
    bit<1>  ipv6_mc_sa_local_da_global_svi_drop_mask;
    bit<1>  ipv6_mc_sa_local_da_global_l3if_drop_mask;
    bit<1>  self_fwd_failure_drop_mask;
    bit<1>  split_horizon_check_drop_mask;
    bit<1>  arp_nd_ucast_cross_bd_drop_mask;
    bit<1>  double_exception_drop_mask;
    bit<1>  secure_mac_move_drop_mask;
    bit<1>  non_secure_mac_drop_mask;
    bit<1>  l2_bind_failure_drop_mask;
    bit<1>  pt_deny_drop_mask;
    bit<1>  qos_policer_drop_drop_mask;
}

struct ig_drop_t {
    bit<1> inc_drop_counters;
    bit<1> missing_vntag;
    bit<1> illegal_vntag;
    bit<1> src_if_miss;
    bit<1> src_vlan_mbr;
    bit<1> src_tep_miss;
    bit<1> iic_check_failure;
    bit<1> outer_ttl_expired;
    bit<1> vlan_xlate_miss;
    bit<1> ttl_expired;
    bit<1> routing_disabled;
    bit<1> sgt_xlate_miss;
    bit<1> src_nat_drop;
    bit<1> dst_nat_drop;
    bit<1> twice_nat_drop;
    bit<1> smac_miss;
    bit<1> route_miss;
    bit<1> bridge_miss;
    bit<1> mtu_check_failure;
    bit<1> uc_rpf_failure;
    bit<1> mc_rpf_failure;
    bit<1> l3_binding_failure;
    bit<1> ipv6_uc_link_local_cross_bd;
    bit<1> ipv6_mc_sa_local_da_global_svi;
    bit<1> ipv6_mc_sa_local_da_global_l3if;
    bit<1> self_fwd_failure;
    bit<1> split_horizon_check;
    bit<1> arp_nd_ucast_cross_bd;
    bit<1> double_exception;
    bit<1> secure_mac_move;
    bit<1> non_secure_mac;
    bit<1> l2_bind_failure;
    bit<1> pt_deny;
    bit<1> qos_policer_drop;
#ifndef DISABLE_MPLS
    bit<1> mpls_disabled;
    bit<1> mpls_miss;
#endif /*DISABLE_MPLS*/
#ifndef DISABLE_FCF
    bit<1> fcf_miss;
#endif /*DISABLE_FCF*/
}

struct ig_dst_bd_t {
    bit<16> flood_met_ptr;
    bit<16> omf_met_ptr;
    bit<8>  acl_label;
    bit<4>  mtu_idx;
}

struct ig_dst_port_t {
    bit<1> vnic_if;
    bit<1> is_local;
    bit<1> is_vpc;
    bit<6> acl_label;
}

@union("=dst_addr", "bitset=adj", "adj_idx") @union("=dst_addr", "bitset=l2", "dmac") @union("=dst_addr", "bitset=mpls", "mpls_frr_fwd", "mpls_frr_idx", "mpls_label0_vld", "mpls_label0_lbl") struct ig_eg_intrinsic_t {
    bit<1>  erspan_term;
    bit<1>  qinq_customer_port;
    bit<48> tstmp;
    bit<9>  ingress_port;
    bit<1>  cap_1588;
    bit<1>  len_type;
    bit<5>  pkt_type;
    bit<1>  vnid_use_bd;
    bit<2>  l2_fwd_mode;
    bit<2>  l3_fwd_mode;
    bit<1>  tunnel_encap;
    bit<1>  tunnel_decap;
    bit<1>  l2_tunnel_decap;
    bit<1>  ieth_fwd;
    bit<1>  aa_multihomed;
    bit<1>  encap_vld;
    bit<14> encap_idx;
    bit<13> encap_l2_idx;
    bit<1>  adj_vld;
    bit<14> adj_idx;
    bit<48> dmac;
    bit<1>  mpls_frr_fwd;
    bit<12> mpls_frr_idx;
    bit<1>  mpls_label0_vld;
    bit<20> mpls_label0_lbl;
    bit<1>  service_redir;
    bit<12> nat_idx;
    bit<2>  ol_ecn;
    bit<16> ol_udp_sp;
    bit<1>  ol_lb;
    bit<1>  ol_dl;
    bit<1>  ol_e;
    bit<1>  ol_sp;
    bit<1>  ol_dp;
    bit<5>  ol_vpath;
    bit<3>  ol_dre;
    bit<5>  ol_fb_vpath;
    bit<3>  ol_fb_metric;
    bit<10> lat_index;
    bit<1>  lat_update;
    bit<11> qos_map_idx;
    bit<1>  ttl_cio;
    bit<1>  ttl_coi;
    bit<1>  ecn_cio;
    bit<1>  ecn_coi;
    bit<8>  sup_code;
    bit<6>  sup_qnum;
    bit<16> src_class;
    bit<16> dst_class;
    bit<14> src_epg_or_bd;
    bit<14> dst_epg_or_bd;
    bit<2>  pif_block_type;
    bit<1>  bounce;
    bit<1>  cap_access;
    bit<1>  lat_index_msb;
    bit<1>  block_epg_crossing;
    bit<16> nat_port;
    bit<1>  nat_type;
    bit<2>  ieth_l2_fwd_mode;
    bit<2>  ieth_l3_fwd_mode;
    bit<14> ieth_src_idx;
    bit<14> ieth_dst_idx;
    bit<8>  ieth_src_chip;
    bit<16> ieth_src_port;
    bit<8>  ieth_dst_chip;
    bit<8>  ieth_dst_port;
    bit<9>  ieth_outer_bd;
    bit<14> ieth_bd;
    bit<1>  ieth_mark;
    bit<1>  ieth_dont_lrn;
    bit<1>  ieth_span;
    bit<1>  ieth_alt_if_profile;
    bit<1>  ieth_ip_ttl_bypass;
    bit<1>  ieth_src_is_tunnel;
    bit<1>  ieth_dst_is_tunnel;
    bit<1>  ieth_sup_tx;
    bit<5>  ieth_sup_code;
    bit<4>  ieth_cos;
    bit<4>  ieth_de;
    bit<4>  ieth_tclass;
    bit<1>  ieth_vpc_df;
    bit<8>  ieth_pkt_hash;
}

struct ig_local_t {
    bit<1>   vlan0_vld;
    bit<1>   vlan1_vld;
    bit<14>  src_vlan_xlate_key_vlan0;
    bit<14>  src_vlan_xlate_key_vlan1;
    bit<14>  src_epg_or_bd;
    bit<16>  ieth_met_ptr;
    bit<14>  inner_src_bd;
    bit<11>  ftag_addr;
    bit<16>  mtu_val;
    bit<7>   mtu_idx;
    bit<7>   mtu_idx_msb;
    bit<14>  spine_proxy_dst_ptr;
    bit<32>  lkp_outer_ipv4_ga;
    bit<128> lkp_outer_ipv6_ga;
    bit<1>   src_mac_mismatch;
    bit<1>   mark;
    bit<13>  src_tep_stats_idx;
    bit<11>  src_port_stats_idx;
    bit<11>  src_port_class_stats_idx;
}

struct ig_qos_t {
    bit<1>  qos_layer;
    bit<6>  inner_dscp;
    bit<2>  inner_ecn;
    bit<3>  inner_cos;
    bit<1>  inner_de;
    bit<3>  inner_exp;
    bit<1>  acl_key_dscp_vld;
    bit<6>  acl_key_dscp;
    bit<2>  acl_key_ecn;
    bit<3>  acl_key_exp;
    bit<1>  acl_key_exp_vld;
    bit<3>  acl_key_cos;
    bit<1>  acl_key_de;
    bit<1>  qos_use_tc;
    bit<1>  qos_use_dscp;
    bit<1>  qos_use_exp;
    bit<8>  qos_map_grp;
    bit<11> qos_map_idx;
    bit<4>  iclass;
    bit<4>  oclass;
    bit<1>  cpu;
    bit<4>  tclass;
    bit<1>  spantransit;
}

struct ig_tunnel_t {
    bit<1>   src_encap_pkt;
    bit<4>   src_encap_type;
    bit<3>   src_l3_encap_type;
    bit<10>  erspan_session;
    bit<1>   dst_tep_hit;
    bit<24>  src_vnid;
    bit<1>   src_vnid_xlate_hit;
    bit<1>   decap;
    bit<14>  inner_src_bd;
    bit<1>   l3_tunnel_decap;
    bit<1>   mc_tunnel_decap;
    bit<1>   encap_flood;
    bit<1>   encap_flood_fwd_lkup;
    bit<1>   mc_group_lookup_hit;
    bit<1>   mc_group_rpf_en;
    bit<1>   mc_group_bidir;
    bit<14>  mc_group_rpf_bd_or_group;
    bit<16>  mc_group_mcast_spec;
    bit<14>  mc_group_rpf_bd_match;
    bit<1>   mc_group_bidir_rpf_pass;
    bit<16>  mc_group_hit_addr;
    bit<1>   mc_sg_lookup_hit;
    bit<1>   mc_sg_rpf_en;
    bit<1>   mc_sg_bidir;
    bit<14>  mc_sg_rpf_bd;
    bit<16>  mc_sg_mcast_spec;
    bit<14>  mc_sg_rpf_bd_match;
    bit<1>   mc_sg_sup_copy;
    bit<16>  mc_sg_hit_addr;
    bit<1>   ftag_mode;
    bit<4>   ifabric_ftag;
    bit<128> ftag_oif_list;
    bit<1>   ftag_iic_result;
    bit<1>   sup_copy;
    bit<1>   no_dc_sup_redirect;
    bit<1>   rpf_fail_send_to_sup;
    bit<1>   mc_rpf_pass;
    bit<1>   mc_group_rpf_pass;
    bit<1>   mc_sg_rpf_pass;
    bit<1>   pim_bloom_filter_en;
    bit<4>   pim_bloom_filter_rcode;
    bit<4>   pim_acl_key;
    bit<1>   encap;
    bit<1>   l3_tunnel_encap;
    bit<13>  encap_ecmp_ptr;
    bit<13>  encap_ecmp_mbr;
    bit<4>   dst_encap_type;
    bit<2>   dst_encap_l3_type;
    bit<3>   dst_encap_l4_type;
    bit<13>  encap_idx;
    bit<13>  encap_l2_idx;
    bit<24>  dst_vnid;
    bit<1>   inner_dst_bd_xlate_hit;
    bit<13>  inner_dst_bd_xlate_idx;
    bit<9>   ipv4_sipo_rw_ptr;
    bit<7>   ipv6_sipo_rw_ptr;
    bit<13>  ipv4_dipo_rw_ptr;
    bit<11>  ipv6_dipo_rw_ptr;
    bit<16>  encap_ip_len;
    bit<1>   ttl_mode;
    bit<8>   outer_ttl;
    bit<4>   src_sh_group;
    bit<4>   dst_sh_group;
    bit<1>   erspan_term;
    bit<1>   erspan_term_decap;
}

struct local_ingress_t {
    bit<7>  src_chip;
    bit<8>  src_port;
    bit<12> src_chip_offset;
    bit<12> src_global_port;
}

struct ingress_t {
    bit<7>  src_port_grp;
    bit<7>  dst_port_grp;
    bit<1>  dst_is_ptr;
    bit<13> dst_ptr_or_idx;
    bit<13> src_if_idx;
    bit<13> dst_if_idx;
    bit<13> dst_vpc_idx;
    bit<2>  port_type;
    bit<14> dst_port_idx;
    bit<1>  ieth_fwd;
    bit<5>  bypass_code;
    bit<14> src_bd;
    bit<14> dst_bd;
    bit<14> outer_dst_bd;
    bit<14> outer_src_bd;
    bit<14> src_epg;
    bit<14> dst_epg;
    bit<2>  l2_fwd_mode;
    bit<2>  l3_fwd_mode;
    bit<1>  met0_vld;
    bit<16> met0_ptr;
    bit<1>  met1_vld;
    bit<16> met1_ptr;
    bit<1>  use_met;
    bit<1>  ifabric_ingress;
    bit<1>  vpc_df;
    bit<1>  ep_bounce;
    bit<1>  vpc_bounce;
    bit<1>  vpc_bounce_en;
    bit<1>  drop_flag;
    bit<8>  drop_reason;
    bit<1>  storm_control_drop;
    bit<1>  copp_drop;
    bit<4>  oclass;
    bit<14> flowlet_id;
    bit<1>  len_type;
    bit<8>  dst_chip;
    bit<8>  dst_port;
    bit<9>  ovector_idx;
    bit<1>  span_vld;
    bit<6>  span_idx;
    bit<1>  rw_adj_vld;
    bit<14> rw_adj_idx;
    bit<1>  sup_redirect;
    bit<1>  sup_copy;
}

struct ig_dp_intrinsic_t {
    bit<1>  mark;
    bit<2>  srvc_oslice_vec;
    bit<1>  is_tcp;
    bit<2>  srvc_class;
    bit<4>  cpu_oclass;
    bit<1>  set_v;
    bit<16> set_idx;
    bit<14> bd;
    bit<1>  vpc_df;
    bit<1>  is_my_tep;
    bit<4>  src_sh_group;
    bit<5>  ftag;
    bit<1>  rpf_fail;
    bit<12> pkt_hash;
    bit<1>  alt_if_profile;
    bit<1>  met0_vld;
    bit<16> met0_ptr;
    bit<1>  met1_vld;
    bit<16> met1_ptr;
    bit<1>  ifabric_ftag_mode;
    bit<1>  ifabric_ingress_mode;
    bit<1>  ifabric_egress_mode;
    bit<11> src_if_num;
    bit<1>  span_vld;
    bit<1>  is_epg;
    bit<1>  flood_to_epg;
    bit<1>  storefwd;
    bit<1>  ecncapable;
    bit<1>  opcode_uc;
    bit<1>  opcode_l2mc;
    bit<1>  opcode_l3mc;
    bit<1>  opcode_drop;
    bit<1>  opcode_lcpu;
    bit<1>  opcode_rcpu;
    bit<1>  opcode_span;
    bit<4>  oclass;
    bit<4>  iclass;
    bit<13> ovector_idx;
    bit<6>  span_idx;
    bit<11> pktid;
    bit<8>  tdmid;
    bit<9>  ingress_port;
}

struct mcast_filter_t {
    bit<4>  rcode;
    bit<14> bd;
    bit<16> hit_addr;
    bit<14> hash0;
    bit<14> hash1;
    bit<8>  fixed0;
    bit<8>  fixed1;
    bit<1>  hit0;
    bit<1>  hit1;
}

struct input_qos_info_t {
    bit<3> oqueue;
    bit<3> cos;
    bit<1> de;
    bit<6> dscp;
    bit<4> tc;
    bit<1> cos_rw;
    bit<1> de_rw;
    bit<1> dscp_rw;
    bit<1> tc_rw;
    bit<1> dscp_coi;
}

struct ipv4_metadata_t {
    bit<32> lkp_ipv4_sa;
    bit<32> lkp_ipv4_da;
    bit<1>  ipv4_uc_routing_en;
    bit<1>  ipv4_mc_routing_en;
    bit<1>  igmp_snooping_en;
    bit<2>  ipv4_urpf_mode;
    bit<1>  ipv4_sa_ll;
    bit<1>  ipv4_da_ll;
    bit<32> nat_overload_addr;
    bit<32> fib_da_key_addr;
    bit<32> fib_sa_key_addr;
}

struct ipv6_metadata_t {
    bit<128> lkp_ipv6_sa;
    bit<128> lkp_ipv6_da;
    bit<1>   ipv6_uc_routing_en;
    bit<1>   ipv6_mc_routing_en;
    bit<1>   mld_snooping_en;
    bit<2>   ipv6_urpf_mode;
    bit<1>   ipv6_sa_ll;
    bit<1>   ipv6_da_ll;
    bit<1>   ipv6_sa_eq0;
    bit<1>   inner_ipv6_sa_eq0;
    bit<128> nat_overload_addr;
    bit<128> fib_da_key_addr;
    bit<128> fib_sa_key_addr;
}

struct l2_t {
    bit<2>  l2_da_type;
    bit<2>  inner_l2_da_type;
    bit<48> lkp_mac_sa;
    bit<48> lkp_mac_da;
    bit<13> same_if_check;
    bit<1>  l2_dst_hit;
    bit<1>  l2_src_hit;
    bit<1>  l2_src_move;
    bit<1>  src_secure_mac;
    bit<14> vlan_mbr_idx;
    bit<1>  vlan_mbr_chk_en;
    bit<1>  vlan_mbr_state;
    bit<16> bd_stats_idx;
    bit<1>  port_vlan_mapping_miss;
    bit<1>  src_is_epg;
    bit<1>  mac_sclass_binding_failure;
}

struct l3_t {
    bit<3>  l3_type;
    bit<3>  inner_l3_type;
    // TBD l3_type_ip and inner_l3_type are only assigned values of
    // TRUE or FALSE in the original P4_14 code.  Why is it 3 bits
    // wide?
    bit<3>  l3_type_ip;
    bit<3>  inner_l3_type_ip;
    bit<4>  l4_type;
    bit<4>  lkp_ip_version;
    bit<8>  lkp_ip_proto;
    bit<8>  lkp_ip_ttl;
    bit<6>  lkp_ip_dscp;
    bit<2>  lkp_ip_ecn;
    bit<16> lkp_ip_len;
    bit<1>  lkp_ip_opt;
    bit<13> lkp_ip_fragOffset;
    bit<1>  lkp_ip_flag_more;
    bit<16> lkp_l4_sport;
    bit<16> lkp_l4_dport;
    bit<8>  lkp_tcp_flags;
    bit<1>  lkp_tcp_flag_ack;
    bit<1>  lkp_tcp_flag_rst;
    bit<16> lkp_inner_l4_sport;
    bit<16> lkp_inner_l4_dport;
    bit<8>  lkp_inner_tcp_flags;
    bit<4>  inner_l4_type;
    bit<2>  ip_da_type;
    bit<2>  ip_sa_type;
    bit<2>  nd_type;
    bit<3>  arp_type;
    bit<1>  nd_ta_ll;
    bit<2>  inner_ip_da_type;
    bit<2>  inner_ip_sa_type;
    bit<2>  inner_nd_type;
    bit<3>  inner_arp_type;
    bit<1>  inner_nd_ta_ll;
    bit<1>  arp_unicast_mode;
    bit<1>  rarp_unicast_mode;
    bit<1>  nd_unicast_mode;
    bit<1>  ip_mac_binding_failure;
    bit<1>  ip_sclass_binding_failure;
    bit<1>  egress_tor_glean;
    bit<14> vrf;
    bit<12> rmac_group;
    bit<1>  rmac_hit;
    bit<2>  urpf_type;
    bit<1>  urpf_enable;
    bit<3>  fib_lkup_type;
    bit<1>  fib_sa_hit;
    bit<1>  fib_sa_default_entry;
    bit<14> urpf_group;
    bit<1>  urpf_pass;
    bit<14> fib_da_bd_or_vrf;
    bit<1>  fib_da_hit;
    bit<1>  src_fib_hit;
    bit<16> src_adj_ptr;
    bit<1>  src_ecmp_vld;
    bit<16> src_ecmp_ptr;
    bit<1>  dst_fib_hit;
    bit<16> dst_adj_ptr;
    bit<1>  dst_ecmp_vld;
    bit<16> dst_ecmp_ptr;
    bit<1>  src_ip_move;
    bit<48> outer_src_bd_rmac;
    bit<48> dmac;
    bit<1>  ttl_expired;
    bit<1>  ipfrag;
    bit<1>  inner_ipfrag;
    bit<8>  exposed_ttl;
    bit<14> fib_da_key_vrf;
    bit<14> fib_sa_key_vrf;
    bit<1>  fib_sa_lookup_en;
    bit<1>  fib_da_lookup_en;
    bit<1>  nat_hit;
    bit<1>  nat_overload;
    bit<14> nat_overload_vrf;
    bit<12> nat_ptr;
    bit<1>  twice_nat_hit;
    bit<1>  twice_nat_sup_redirect;
    bit<1>  twice_nat_sup_copy;
    bit<14> twice_adj_bd;
    bit<48> twice_adj_mac;
    bit<1>  src_nat_hit;
    bit<1>  src_nat_sup_redirect;
    bit<1>  src_nat_sup_copy;
    bit<14> src_adj_bd;
    bit<48> src_adj_mac;
    bit<1>  dst_nat_hit;
    bit<1>  dst_nat_sup_redirect;
    bit<1>  dst_nat_sup_copy;
    bit<14> dst_adj_bd;
    bit<48> dst_adj_mac;
}

struct met_t {
    bit<14> epg;
    bit<1>  use_epg_in;
    bit<1>  epg_cross_drop;
    bit<1>  mc_ftag_mode;
    bit<1>  service_vld;
    bit<1>  force_route;
    bit<1>  force_bridge;
    bit<1>  ttl_dec_disable;
    bit<14> bd;
    bit<14> outer_bd;
    bit<13> ovector_idx;
    bit<1>  encap_vld;
    bit<14> encap_idx;
    bit<14> encap_l2_idx;
    bit<1>  fm_bridge_only;
    bit<1>  use_bd;
    bit<1>  use_in;
    bit<1>  adj_vld;
    bit<14> adj_idx;
    bit<1>  same_if_check_bypass;
}

struct mpls_metadata_t {
    bit<1>  mpls_en;
    bit<20> topmost_non_null_label_val;
    bit<8>  topmost_non_null_label_ttl;
    bit<3>  topmost_non_null_label_exp;
    bit<1>  entropy_label_vld;
    bit<20> entropy_label_val;
    bit<8>  outermost_ttl;
    bit<1>  l2vpn_term;
    bit<1>  l3vpn_term;
    bit<13> l3vpn_term_tunnel_id;
    bit<1>  fib_lbl0_vld;
    bit<20> fib_lbl0;
    bit<14> frr_dst_ptr;
    bit<14> label_rw_ptr;
    bit<1>  frr_en;
    bit<3>  label_op;
    bit<1>  ttl_mode;
}

struct multicast_t {
    bit<16> egress_spec;
    bit<1>  rpf_pass;
    bit<1>  group_rpf_pass;
    bit<1>  sg_rpf_pass;
    bit<1>  bidir;
    bit<1>  mc_route_group_lookup_hit;
    bit<16> mc_route_group_hit_addr;
    bit<1>  mc_route_sg_lookup_hit;
    bit<16> mc_route_sg_hit_addr;
    bit<1>  group_rpf_en;
    bit<14> group_rpf_bd_match;
    bit<14> group_rpf_bd_or_group;
    bit<1>  sg_rpf_en;
    bit<14> sg_rpf_bd_match;
    bit<14> rpf_bd;
    bit<1>  mc_bridge_group_lookup_hit;
    bit<16> mc_bridge_group_hit_addr;
    bit<1>  mc_bridge_sg_lookup_hit;
    bit<16> mc_bridge_sg_hit_addr;
    bit<1>  routerg_entry;
    bit<1>  force_bridge;
    bit<14> same_bd_check;
    bit<14> outer_same_bd_check;
    bit<1>  non_ip_group_lookup_hit;
    bit<1>  sup_copy;
    bit<1>  rpf_fail_send_to_sup;
//#ifdef ACI_TOR_MODE
    bit<3>  active_ftag_idx;
    bit<1>  force_rpf_pass;
//#endif /*ACI_TOR_MODE*/
    bit<1>  default_entry;
    bit<1>  no_dc_sup_redirect;
    bit<1>  pim_bloom_filter_en;
    bit<4>  pim_bloom_filter_rcode;
    bit<4>  pim_acl_key;
    bit<1>  igmp_mld_match_omf;
    bit<1>  igmp_mld_match_flood;
    bit<4>  mtu_idx;
}

struct notify_vec_t {
    bit<48>  src_mac_addr;
    bit<128> src_ip_addr;
    bit<1>   src_is_ptr;
    bit<14>  src_ptr_or_idx;
}

struct outer_dst_bd_t {
    bit<10> rmac_index;
    bit<50> ifmbr;
    bit<4>  mtu_idx;
//#ifdef ACI_TOR_MODE
    bit<1>  bypass_self_fwd_check;
    bit<1>  bypass_same_vtep_check;
//#else  /*ACI_TOR_MODE*/
    bit<1> cts_en;
    bit<1> l2mp_en;
    bit<3> vft_idx;
    bit<1> dce_bd_bypass;
    bit<1> provider_bd;
    bit<1> keep_inner_qtag;
//#endif /*ACI_TOR_MODE*/
}

struct outer_src_bd_t {
    bit<14> vrf;
    bit<12> mbr_bitmap_idx;
    bit<10> rmac_index;
    bit<1>  ipv4_ucast_en;
    bit<1>  ipv6_ucast_en;
    bit<1>  ipv4_mcast_en;
    bit<1>  ipv6_mcast_en;
    bit<2>  ids_mask_sel;
    bit<1>  mpls_en;
    bit<1>  route_bd;
    bit<16> bd_stats_idx;
    bit<1>  is_l3_if;
}

struct parser_t {
    bit<6> parser_status;
    bit<1> inner_header_present;
    bit<1> qtag_valid;
    bit<1> qinq_tag_valid;
    bit<1> cmd_valid;
    bit<1> inner_qtag_valid;
}

struct pt_info_t {
    bit<2>  queuing_ctrl;
    bit<1>  mcast_flood_ctrl0;
    bit<1>  mcast_flood_ctrl1;
    bit<3>  uplink_ctrl;
    bit<1>  deny;
    bit<1>  log;
    bit<1>  src_policy_applied;
    bit<1>  dst_policy_applied;
    bit<1>  service_redir;
    bit<12> service_idx;
    bit<1>  service_override_route;
    bit<1>  service_copy;
    bit<2>  service_oslice_vec;
    bit<16> set_idx;
    bit<1>  qos_vld;
    bit<6>  qos_map_grp;
    bit<1>  qos_map_use_dscp;
    bit<1>  cnt_dir0;
    bit<1>  cnt_dir1;
    bit<1>  collect_override;
    bit<1>  collect;
    bit<1>  analytics_vld_override;
    bit<1>  analytics_vld;
    bit<2>  mask_sel;
    bit<2>  rtt_profile;
    bit<1>  cnt_vld;
    bit<1>  service_sample_en;
    bit<1>  flow_sample_en;
    bit<6>  sampler_index;
    bit<2>  service_pri;
    bit<2>  sup_pri;
    bit<1>  lkup_hit;
    bit<1>  log_status;
    bit<17> hit_idx;
}

struct pt_key_t {
    bit<16> class0;
    bit<16> class1;
    bit<16> port0;
    bit<16> port1;
    bit<8>  protocol;
    bit<1>  l2;
    bit<1>  sup_tx;
    bit<1>  src_policy_incomplete;
    bit<1>  dst_policy_incomplete;
    bit<1>  class_eq;
    bit<1>  ipv6_route;
    bit<1>  encap_transit;
    bit<12> sg_label;
    bit<1>  ip_opt;
    bit<1>  ip_fragment;
    bit<1>  ip_frag_offset0;
    bit<1>  ip_frag_offset1;
    bit<1>  ip_mf;
    bit<1>  ieth;
    bit<1>  ipv6;
    bit<1>  dst_local;
    bit<1>  routable;
    bit<1>  multidest;
    bit<8>  tcp_flags;
    bit<1>  class_dir;
    bit<16> sport;
    bit<16> dport;
    bit<6>  dscp;
    bit<1>  ARD0;
    bit<1>  ARD1;
    bit<1>  AR;
    bit<1>  policy_skip_remote_tep;
    bit<1>  vpc_df;
    bit<5>  ip_flags;
    bit<8>  proto;
    bit<16> src_class;
    bit<16> dst_class;
    bit<2>  src_class_pri;
    bit<16> ss_src_class;
    bit<1>  src_policy_applied;
    bit<1>  dst_policy_applied;
    bit<1>  use_station_src_class;
    bit<1>  sgt_to_sclass_hit;
    bit<16> sgt_sclass;
}

struct rewrite_t {
    bit<12> svif;
    bit<12> uc_dvif;
    bit<14> mc_dvif;
    bit<1>  vntag_loop;
    bit<16> sgt;
    bit<2>  cts_mode;
    bit<16> encap_ip_len;
}

struct service_redir_t {
    bit<1>  vld;
    bit<2>  pri;
    bit<16> idx;
    bit<13> mp_mbr;
    bit<1>  override_route;
}

struct service_rw_t {
//#ifdef ACI_TOR_MODE
    bit<48> dmac;
    bit<1>  dmac_rw;
    bit<1>  smac_rw;
    bit<14> epg;
    bit<1>  epg_rw;
    bit<16> sclass;
    bit<14> bd_label;
    bit<1>  ttl_rw;
    bit<1>  copy_service;
    bit<1>  erspan;
//#else  /*ACI_TOR_MODE*/

	// FC
//	dmac : 48; //        dmac
//	dmac_rw : 1; //        enable dmac rewrite
//	dmac_type : 1; //        0 => use dmac from this table. 1 => dmac = fc_oui|d_id
//	smac_rw : 1; //        enable source mac rewrite using pif.fc_edge_addr
//	vsan : 12; //        vsan
//	vsan_rw : 1; //        enable vsan rewrite
//	bd_label : 11; //        bd label
//	spare : 39; //
    bit<28> padfield; // Reserved. Padding field.


	// MPLS-wide
//	wide : 1; //
//	opcode : 2; //
//	label_cnt : 3; //  Number of labels to push/pop/swap.                                                   Push upto 5 labels ( first label is from FIB ).                                                   Swap+push upto 4 labels. If label_cnt=1, just swap the topmost label.                                                   Pop upto 2 labels not including null.
//	label1 : 20; //
//	label2 : 20; //
//	label0_vld : 1; //  Use Label from FIB as first label to push/swap
//	rll : 1; //  Remove last label
//	ttl_mode : 1; //  0=uniform; 1=pipe
//	qos_mode : 1; //  0=uniform; 1=pipe
//	wide : 1; //
//	opcode : 2; //
//	label_cnt : 3; //  Number of labels to push/pop/swap.                                                   Push upto 5 labels ( first label is from FIB ).                                                   Swap+push upto 4 labels. If label_cnt=1, just swap the topmost label.                                                   Pop upto 2 labels not including null.
//	label1 : 20; //
//	label2 : 20; //
//	label0_vld : 1; //  Use Label from FIB as first label to push/swap
//	rll : 1; //  Remove last label
//	ttl_mode : 1; //  0=uniform; 1=pipe
//	qos_mode : 1; //  0=uniform; 1=pipe
//	padf3ield : 42; // Reserved. Padding field.
//
//	//NSH
//	dmac : 48; //
//	dmac_rw : 1; //
//	smac_rw : 1; //
//	rmac_idx : 10; //
//	ttl_rw : 1; //
//	nsh_service_path : 24; //  nsh service path id
//	nsh_service_id : 8; //  nsh service index
//	nsh_encap_vnid_or_vlan : 1; //
//	nsh_encap_vnid : 24; //  vxlan vnid for nsh
//	nsh_opcode : 2; //
//	nsh_vlan_opcode : 2; //
//	dl : 1; //        don't learn bit
//	bd_label : 11; //        bd label
//	trunc_idx : 3; //   truncation index
//	qos_op : 2; //   truncation index
//	keep_inner_qtag : 1; //   truncation index
//	sp : 1; //   truncation index
//	dp : 1; //   truncation index
//
//	// ERSPAN
//	span_session : 8; //   span session configuration
//	hdr_idx : 8; //   erspan index
//	erspan_idx : 16; //   erspan index
//	bd_label : 11; //        bd label
//	padfield : 99; // Reserved. Padding field.

    //Openflow
    //bit<48> dmac; //
    //bit<1>  dmac_rw; //
    //bit<1>  smac_rw; //
    bit<10> rmac_idx; //
    bit<3>  qiq_op; //  nsh service path id
    bit<12> vlan; //  nsh service index
    //bit<1>  ttl_rw; //
    bit<1>  cos_rw; //
    bit<3>  cos; //  vxlan vnid for nsh
    bit<1>  de_rw; //
    bit<1>  de; //
    //bit<11> bd_label; //        bd label
    bit<3>  adj_type; //
    bit<1>  use_bd_label; //  use bd_label from adjacency
    bit<1>  truncation_en; //
//#endif /*ACI_TOR_MODE*/
}

struct src_adj_t {
    bit<48> mac;
    bit<14> bd;
    bit<1>  is_ptr;
    bit<14> ptr_or_idx;
}

struct src_bd_t {
    bit<14> bd;
    bit<14> vrf;
    bit<16> acl_label;
    bit<10> rmac_index;
    bit<14> primary_bd;
    bit<10> bd_profile_idx;
    bit<1>  fcf_en;
    bit<1>  cts_en;
    bit<1>  ipv4_ucast_en;
    bit<1>  ipv6_ucast_en;
    bit<1>  ipv4_mcast_en;
    bit<1>  ipv6_mcast_en;
    bit<1>  v4_ignore_self_fwd_check;
    bit<1>  v6_ignore_self_fwd_check;
    bit<1>  igmp_snp_en;
    bit<1>  mld_snp_en;
    bit<2>  ipv4_rpf_type;
    bit<2>  ipv6_rpf_type;
    bit<1>  nat_inside_if;
    bit<1>  nat_outside_if;
    bit<1>  nat_overload_fwd;
    bit<1>  l3_bind_check_en;
    bit<1>  use_primary_l3_self;
    bit<1>  use_primary_rpf;
    bit<1>  fib_sa_dc_redirect_en;
    bit<1>  enforce_v6_link_local_uc;
    bit<1>  enforce_v6_link_local_mc;
    bit<1>  v4_omf;
    bit<1>  v6_omf;
    bit<1>  route_bd;
    bit<1>  l2mc_use_mac;
    bit<1>  qos_vld;
    bit<7>  qos_map_grp;
    bit<1>  qos_map_use_dscp;
    bit<1>  qos_map_use_exp;
    bit<1>  qos_map_use_tc;
    bit<1>  force_mac_sa_lkup;
    bit<1>  ecn_mark_en;
    bit<1>  l2_bind_check_en;
    bit<1>  is_l3_if;
    bit<2>  ids_mask_sel;
    bit<1>  flow_collect_en;
    bit<1>  fib_sa_lkup_always_use_vrf;
    bit<1>  fib_force_rpf_pass_en;
    bit<1>  encap_flood_fwd_lkup_en;
    bit<1>  encap_flood_fwd_rslt_en;
    bit<1>  encap_flood_outer_only_on_miss;
    bit<1>  mac_pkt_classify;
    bit<1>  flowtbl_mac_pkt_classify;
    bit<16> bd_stats_idx;
    bit<1>  mpls_en;
#ifndef DISABLE_MPLS
    bit<1>  mpls_ignore_self_fwd_check;
#endif /*DISABLE_MPLS*/
    // TBD: These fields are used outside of #ifdef ACI_TOR_MODE
    // somewhere in the code, so moving it outside of #ifdef
    // ACI_TOR_MODE here, at least for now.
    bit<12> sg_label;
    bit<1>  ivxlan_dl;
    bit<1>  arp_unicast_mode;
    bit<1>  arp_req_unicast_mode_dis;
    bit<1>  arp_res_unicast_mode_dis;
    bit<1>  garp_unicast_mode_dis;
    bit<1>  rarp_unicast_mode;
    bit<1>  rarp_req_unicast_mode_dis;
    bit<1>  rarp_res_unicast_mode_dis;
    bit<1>  nd_unicast_mode;
    bit<1>  uc_nd_sol_unicast_mode_dis;
    bit<1>  mc_nd_adv_unicast_mode_dis;
    bit<1>  normal_arp_nd_learn;
    bit<1>  mac_learn_en;
    bit<1>  ip_learn_en;
    bit<1>  sclass_learn_en;
    bit<1>  arp_nd_bd_crossing_dis;
    bit<1>  unknown_uc_flood;
    bit<1>  unknown_uc_proxy;
    bit<1>  arp_unicast_flood_on_miss;
    bit<1>  unknown_mc_flood;
//#ifdef ACI_TOR_MODE
    bit<14> epg;
    bit<8>  ss_vrf;
    bit<16> src_class;
    bit<12> service_idx;
    bit<1>  service_redir;
    bit<2>  service_redir_pri;
    bit<2>  src_class_pri;
    bit<1>  arp_l3_bind_check_en;
    bit<1>  nd_l3_bind_check_en;
    bit<1>  lb_disable;
    bit<1>  unknown_mc_tocpu;
    bit<1>  analytics_en;
    bit<1>  rarp_unicast_flood_on_miss;
    bit<1>  nd_unicast_flood_on_miss;
    bit<5>  spine_proxy_idx;
    bit<1>  src_policy_applied;
    bit<1>  dst_policy_applied;
    bit<1>  src_policy_incomplete;
    bit<1>  dst_policy_incomplete;
    bit<1>  mc_nd_sol_unicast_mode_dis;
    bit<1>  dad_nd_sol_unicast_mode_dis;
    bit<1>  uc_nd_adv_unicast_mode_dis;
    bit<1>  gna_unicast_mode_dis;

//#else  /*ACI_TOR_MODE*/

    bit<14> fid; // Forwarding ID. Used as part of L2 table keys
    bit<1> ftag_uu_flood_ctl_v4_en; // IPv4 FTAG unknown unicast routing control enable
    bit<1> ftag_uu_flood_ctl_v6_en; // IPv6 FTAG unknown unicast routing control enable
    bit<1> fabric_copy_en; // Enable fabric or_mask for flood
    bit<1> allow_fc_l4_multi_path; // Enable OX_ID in fc multipath calculation.
    bit<1> fc_full_did_en; // Use the full did for searches
    bit<1> l2mp_uu_flood_en; // Allow L2MP unknown unicast flood
    bit<1> l2_mp_enable; // enable L2 MP: DCE/TRILL
    bit<1> l2_mp_iic_check_dis; // disable L2 MP Incoming interface check
    bit<1> enabled_on_mct; //
    bit<1> qinq_core; // QinQ core
    bit<1> drop_mpls; // Drop packet with MPLS

//#endif /*ACI_TOR_MODE*/
}

struct src_bd_profile_t {
    bit<1> ttl_cio;
    bit<1> ttl_coi;
    bit<1> ecn_cio;
    bit<1> ecn_coi;
    bit<1> mc_storefwd;
    bit<1> ftag_mode;
}

struct src_fib_t {
    bit<1>  sup_copy;
    bit<1>  sa_sup_redirect;
    bit<1>  da_sup_redirect;
    bit<1>  sa_direct_connect;
    bit<1>  ttl_decrement_bypass;
    bit<1>  default_entry;
    // TBD: These fields were used in code included even if
    // ACI_TOR_MODE was not #define'd, so for now moving it here.
    bit<1>  preserve_vrf;
    bit<1>  ivxlan_dl;
    bit<1>  bind_notify_en;
    bit<1>  class_notify_en;
    bit<1>  addr_notify_en;
    bit<16> class;
//#ifdef ACI_TOR_MODE
    bit<1>  spine_proxy;
    bit<1>  ep_bounce;
    bit<2>  class_pri;
    bit<16> epg;
    bit<1>  policy_incomplete;
    bit<1>  policy_applied;
    bit<1>  shared_service;
    bit<12> sg_label;
    bit<1>  dst_local;
//#else  /*ACI_TOR_MODE*/
    bit<16> sgt;
//#endif /*ACI_TOR_MODE*/
}

struct src_if_t {
    bit<14> src_idx;
    bit<12> acl_label;
    bit<12> rbacl_label;
    bit<13> bd_xlate_idx;
    bit<10> profile_idx;
    bit<1>  trust_frame_cos;
    bit<1>  default_de;
    bit<3>  default_cos;
    bit<1>  vlan_mbr_chk_bypass;
    bit<1>  vlan_mbr_chk_en;
    bit<1>  vlan_mbr_chk_16k;
    bit<10> vlan_mbr_chk_idx;
    bit<1>  vntag_bypass;
    bit<1>  expect_vft;
    bit<1>  l3_bind_check_en;
    bit<1>  l2_bind_check_en;
    bit<1>  ig_vlan_xlate_bypass;
    bit<1>  is_l2_if;
    bit<1>  from_fc_device;
    bit<1>  mac_pkt_classify;
    bit<1>  vpc;
    bit<1>  set_dont_learn;
    bit<1>  mct;
    bit<1>  require_fcoe_thru_fcf;
    bit<1>  require_fc_mac_chk;
    bit<1>  analytics_en;
    bit<1>  flow_collect_en;
    bit<1>  is_local;
    bit<1>  drop_on_smac_miss;
    bit<1>  drop_non_secure_mac;
    bit<1>  cts_edge;
    bit<16> cts_sgt;
    bit<1>  cts_sgt_priority;
    bit<1>  cts_dgt_priority;
    bit<1>  priority_tag_default_vlan;
    bit<1>  untag_default_vlan;
    bit<1>  dce_qinq_if;
    bit<1>  dce_qinq_core_en;
    bit<1>  trad_qinq_if;
    bit<8>  src_chip;
    bit<8>  src_port;
    bit<1>  allow_nsh;
    bit<1>  skip_qtag0;
    bit<9>  pbp_idx;
    bit<1>  arp_l3_bind_check_en;
    bit<1>  nd_l3_bind_check_en;
    bit<1>  expect_default_vlan;
    bit<1>  flowtbl_mac_pkt_classify;
    bit<1>  qinq_customer_port;
}

struct src_if_profile_t {
    bit<7> qos_map_grp;
    bit<1> qos_map_use_dscp;
    bit<1> qos_map_use_exp;
    bit<1> qos_map_use_tc;
    bit<1> mac_learn_en;
    bit<1> ip_learn_en;
    bit<1> sclass_learn_en;
    bit<1> ivxlan_dl;
    bit<1> fc_device_support_vft;
    bit<1> fcoe_vft_ignore;
    bit<1> conv_learn_en;
    bit<1> learn_drop;
    bit<1> drop_mac_da_local;
    bit<1> drop_mac_sa_local;
    bit<1> bitmap_mbr_chk_1k;
    bit<1> bitmap_mbr_chk_2k;
}

struct src_mac_t {
    bit<14> bd;
    bit<48> mac;
    bit<14> ptr_or_idx;
    bit<1>  is_ptr;
    bit<1>  preserve_vrf;
    bit<1>  sup_copy;
    bit<1>  sup_redirect;
    bit<1>  ep_bounce;
    bit<1>  spine_proxy;
    bit<2>  learn_info;
    bit<1>  dst_local;
    bit<1>  default_entry;
    bit<2>  class_pri;
    bit<16> class;
    bit<16> epg;
    bit<1>  policy_incomplete;
    bit<1>  bind_notify_en;
    bit<1>  class_notify_en;
    bit<1>  addr_notify_en;
    bit<1>  ivxlan_dl;
    bit<1>  policy_applied;
    bit<1>  shared_service;
    bit<1>  vnid_use_bd;
    bit<1>  dst_vpc;
}

struct src_port_t {
    bit<3>  fabric_if_stats_idx;
    bit<12> if_idx;
    bit<2>  vnic_if;
    bit<11> niv_idx;
    bit<1>  storefwd;
    bit<1>  learn_enable;
    bit<1>  trust_frame_cos;
    bit<6>  iic_port_idx;
    bit<2>  drop_to_sup_mask_sel;
    bit<2>  drop_cnt_mask_sel;
    bit<8>  outer_vlan_xlate_idx;
    bit<4>  src_sh_group;
    bit<11> src_if_num;
    bit<1>  mct;
    bit<1>  dis_outer_mc;
    bit<1>  fabric_port;
    bit<1>  ifabric_direction;
    bit<1>  chasis_direction;
    bit<1>  l2mp_core;
    bit<8>  src_chip;
    bit<8>  src_port;
    bit<1>  trunk_port;
    bit<1>  bypass;
    bit<1>  flow_collect_en;
    bit<1>  ieth_fwd_mode;
    bit<1>  igmp_snp_en;
    bit<1>  mld_snp_en;
    bit<1>  ft_port_type;
    bit<1>  mac_learn_en;
    bit<1>  ip_learn_en;
    bit<1>  sclass_learn_en;
    bit<1>  ivxlan_dl;
    bit<1>  conv_learn_en;
    bit<1>  skip_qtag0;
    bit<5>  bypass_code;
    bit<2>  ieor_tep_port_grp;
    bit<1>  expect_default_vlan;
    bit<1>  ifabric_ingress;
    bit<1>  ifabric_egress;
    bit<1>  ftag_mode;
}

struct src_tep_t {
    bit<13> src_ptr;
    bit<1>  lkup_hit;
    bit<1>  is_vpc_peer;
    bit<1>  mac_learn_en;
    bit<1>  trust_cos;
    bit<2>  encap_type;
    bit<1>  tstats_path;
    bit<1>  is_local;
    bit<1>  dcs;
    bit<1>  drop;
    bit<4>  src_sh_group;
    bit<1>  if_idx_chk_en;
    bit<1>  dually_connected;
    bit<13> bd_xlate_idx;
    bit<1>  bd_xlate_idx_vld;
    // TBD: Moving this outside of #ifdef ACI_TOR_MODE since it is
    // used in some code not qualified by that.
    bit<1>  ivxlan_dl;
    bit<1>  trust_dl;
    bit<1>  rw_mark;
    bit<1>  keep_mark;
    bit<1>  ip_learn_en;
    bit<1>  sclass_learn_en;
//#ifdef ACI_TOR_MODE
    bit<1>  trust_sclass;
    bit<1>  is_ivleaf;
    bit<1>  analytics_en;
    bit<1>  flow_collect_en;
    bit<1>  trust_tstmp;
    bit<1>  dis_latency;
//#else  /*ACI_TOR_MODE*/
    bit<13> if_idx;
    bit<1>  l3_tunnel;
    bit<1>  pop_2_labels;
    bit<1>  force_hash_df;
    bit<14> inner_bd;
//#endif /*ACI_TOR_MODE*/
}

header arp_rarp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> opcode;
    bit<48> srcHwAddr;
    bit<32> srcProtoAddr;
    bit<48> dstHwAddr;
    bit<32> dstProtoAddr;
}

header cmd_t {
    bit<8> version;
    bit<8> length_cmd;
}

header cmd_sgt_t {
    bit<3>  length_sgt;
    bit<13> optiontype_sgt;
    bit<16> sgt;
    bit<16> etherType;
}

header erspan2_t {
    bit<4>  ver;
    bit<12> vlan;
    bit<3>  cos;
    bit<2>  en;
    bit<1>  t;
    bit<10> ses;
    bit<12> rsvd;
    bit<20> idx;
}

header erspan3_t {
    bit<4>  ver;
    bit<12> vlan;
    bit<3>  cos;
    bit<2>  bso;
    bit<1>  t;
    bit<10> ses;
    bit<32> tstmp;
    bit<16> sgt;
    bit<1>  p;
    bit<5>  ft;
    bit<6>  hwid;
    bit<1>  dir;
    bit<2>  gra;
    bit<1>  opt;
    bit<6>  platfid;
    bit<6>  rsvd;
    bit<20> idx;
    bit<32> tstmp_hi;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header fcoe_t {
    bit<4>  version;
    bit<32> rsvd0;
    bit<32> rsvd1;
    bit<32> rsvd2;
    bit<4>  rsvd3;
    bit<8>  esof;
    bit<8>  rctl;
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

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

header icmpv6_t {
    bit<8>  type_;
    bit<8>  code;
    bit<16> hdrChecksum;
}

header ieth_t {
    bit<8>  sof;
    bit<1>  hdr_type;
    bit<1>  ext_hdr;
    bit<2>  l2_fwd_mode;
    bit<2>  l3_fwd_mode;
    bit<14> src_idx;
    bit<14> dst_idx;
    bit<8>  src_chip;
    bit<8>  src_port;
    bit<8>  dst_chip;
    bit<8>  dst_port;
    bit<14> outer_bd;
    bit<14> bd;
    bit<1>  mark;
    bit<1>  span;
    bit<1>  alt_if_profile;
    bit<1>  ip_ttl_bypass;
    bit<1>  src_is_tunnel;
    bit<1>  dst_is_tunnel;
    bit<1>  l2_tunnel;
    bit<1>  sup_tx;
    bit<5>  sup_code;
    bit<4>  tclass;
    bit<1>  src_is_peer;
    bit<8>  pkt_hash;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<1>  flag_rsvd;
    bit<1>  flag_noFrag;
    bit<1>  flag_more;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHeader;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header ipv6_neighbor_discovery_t {
    bit<8>   flags;
    bit<24>  rsvd;
    bit<128> targetAddr;
}

header l3l4_arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> opcode;
    bit<48> srcHwAddr;
    bit<32> srcProtoAddr;
    bit<48> dstHwAddr;
    bit<32> dstProtoAddr;
}

header l3l4_ipv4_t {
    bit<32> ipv4_sa;
    bit<32> ipv4_da;
    bit<8>  ip_proto;
    bit<8>  ip_ttl;
    bit<6>  ip_dscp;
    bit<2>  ip_ecn;
    bit<16> ip_len;
    bit<1>  ip_opt;
    bit<13> ip_fragOffset;
    bit<1>  ip_flag_more;
    bit<16> l4_sport;
    bit<16> l4_dport;
    bit<8>  tcp_flags;
    bit<1>  tcp_flag_ack;
    bit<1>  tcp_flag_rst;
    bit<1>  ivxlan_flags_nonce;
    bit<1>  ivxlan_flags_locator;
    bit<1>  ivxlan_flags_color;
    bit<1>  ivxlan_flags_ext_fb_lb_tag;
    bit<1>  ivxlan_flags_instance;
    bit<1>  ivxlan_flags_protocol;
    bit<1>  ivxlan_flags_fcn;
    bit<1>  ivxlan_flags_oam;
    bit<1>  ivxlan_nonce_lb;
    bit<1>  ivxlan_nonce_dl;
    bit<1>  ivxlan_nonce_e;
    bit<1>  ivxlan_nonce_sp;
    bit<1>  ivxlan_nonce_dp;
    bit<3>  ivxlan_nonce_dre;
    bit<16> ivxlan_nonce_sclass;
    bit<24> ivxlan_vni;
    bit<4>  erspan_ver;
    bit<10> erspan_ses;
}

header l3l4_ipv6_t {
    bit<128> ipv6_sa;
    bit<128> ipv6_da;
    bit<8>   ip_proto;
    bit<8>   ip_ttl;
    bit<6>   ip_dscp;
    bit<2>   ip_ecn;
    bit<16>  ip_len;
    bit<1>   ip_opt;
    bit<13>  ip_fragOffset;
    bit<1>   ip_flag_more;
    bit<16>  l4_sport;
    bit<16>  l4_dport;
    bit<8>   tcp_flags;
    bit<1>   tcp_flag_ack;
    bit<1>   tcp_flag_rst;
    bit<1>   ivxlan_flags_nonce;
    bit<1>   ivxlan_flags_locator;
    bit<1>   ivxlan_flags_color;
    bit<1>   ivxlan_flags_ext_fb_lb_tag;
    bit<1>   ivxlan_flags_instance;
    bit<1>   ivxlan_flags_protocol;
    bit<1>   ivxlan_flags_fcn;
    bit<1>   ivxlan_flags_oam;
    bit<1>   ivxlan_nonce_lb;
    bit<1>   ivxlan_nonce_dl;
    bit<1>   ivxlan_nonce_e;
    bit<1>   ivxlan_nonce_sp;
    bit<1>   ivxlan_nonce_dp;
    bit<3>   ivxlan_nonce_dre;
    bit<16>  ivxlan_nonce_sclass;
    bit<24>  ivxlan_vni;
    bit<4>   erspan_ver;
    bit<10>  erspan_ses;
}

header l3l4_nd_t {
    bit<128> ipv6_sa;
    bit<128> ipv6_da;
    bit<8>   ip_proto;
    bit<8>   ip_ttl;
    bit<6>   ip_dscp;
    bit<2>   ip_ecn;
    bit<16>  ip_len;
    bit<1>   ip_opt;
    bit<13>  ip_fragOffset;
    bit<1>   ip_flag_more;
    bit<8>   type_;
    bit<8>   code;
    bit<8>   flags;
    bit<128> targetAddr;
}

header vlan_tag_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> etherType;
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

header timestamp_t {
    bit<48> time;
    bit<16> etherType;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header ipv6_hbh_hel1_t {
    bit<64> options;
}

header ipv6_hbh_hel2_t {
    bit<128> options;
}

header ipv6_hbh_hel3_t {
    bit<192> options;
}

header ipv6_hop_by_hop_t {
    bit<8>  protocol;
    bit<8>  hdr_ext_len;
    bit<16> options01;
    bit<32> options02;
}

header ipv6frag_t {
    bit<8>  protocol;
    bit<8>  hdr_ext_len;
    bit<13> fragOffset;
    bit<2>  rsvd;
    bit<1>  flag_more;
    bit<32> id;
}

header ivxlan_t {
    bit<1>  flags_nonce;
    bit<1>  flags_locator;
    bit<1>  flags_color;
    bit<1>  flags_ext_fb_lb_tag;
    bit<1>  flags_instance;
    bit<1>  flags_protocol;
    bit<1>  flags_fcn;
    bit<1>  flags_oam;
    bit<1>  nonce_lb;
    bit<1>  nonce_dl;
    bit<1>  nonce_e;
    bit<1>  nonce_sp;
    bit<1>  nonce_dp;
    bit<3>  nonce_dre;
    bit<16> nonce_sclass;
    bit<24> vni;
    bit<1>  lsb_m;
    bit<4>  lsb_vpath;
    bit<3>  lsb_metric;
}

header llc_header_t {
    bit<8> dsap;
    bit<8> ssap;
    bit<8> control_;
}

header nsh_t {
    bit<2>  version;
    bit<1>  oam;
    bit<1>  context;
    bit<6>  flags;
    bit<6>  lenght;
    bit<8>  md_type;
    bit<8>  next_proto;
    bit<24> spath;
    bit<8>  sindex;
}

header nsh_context_t {
    bit<32> network_platform;
    bit<32> network_shared;
    bit<32> service_platform;
    bit<32> service_shared;
}

header nvgre_t {
    bit<24> tni;
    bit<8>  flow_id;
}

header snap_header_t {
    bit<24> oui;
    bit<16> type_;
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

header vxlan_t {
    bit<8>  flags;
    bit<24> rsvd;
    bit<24> vni;
    bit<8>  rsvd2;
}

header mpls_t {
    bit<20> label;
    bit<3>  exp;
    bit<1>  bos;
    bit<8>  ttl;
}

struct metadata {
#if defined(INCLUDE_INGRESS) || defined(INCLUDE_EGRESS)
    ig_eg_intrinsic_t ig_eg_header;

    CFG_aci_tor_mode_t CFG_aci_tor_mode;

    // TBD: It makes sense that ig_eg_header would be accessed in both
    // ingress and egress code, but the rest of these seem like they
    // should be either only accessed in ingress, or if they are
    // accessed in egress, it should be after some kind of egress
    // parsing to fill them in again from the packet.
    l2_t              l2;
    l3_t              l3;
    ig_tunnel_t       ig_tunnel;
    ipv4_metadata_t            ipv4m;
    ipv6_metadata_t            ipv6m;
    mpls_metadata_t            mplsm;
#endif /*defined(INCLUDE_INGRESS) || defined(INCLUDE_EGRESS)*/

#ifdef INCLUDE_INGRESS
    parser_t          parse;
    src_tep_t         src_tep;
    outer_src_bd_t    outer_src_bd;
    bypass_info_t     bypass_info;
    ingress_t         ingress;
    src_port_t        src_port;
    dp_ig_intrinsic_t dp_ig_header;
    local_ingress_t         local_ingress;
    ig_drop_t         ig_drop;
    src_if_profile_t  src_if_profile;
    src_if_t          src_if;
    ig_local_t        ig_local;
    mcast_filter_t    outer_mcast_filter;
    hash_t            hash;
    ig_qos_t          ig_qos;
    src_bd_t          src_bd;
    mac_key_t         src_mac_key;
    dst_fib_t         dst_fib;
    multicast_t       multicast;
    mcast_filter_t    inner_mcast_filter;
    mac_key_t         dst_mac_key;
    dst_mac_t         dst_mac;
    service_redir_t   service_redir;
    notify_vec_t      notify_vec;
    src_adj_t         src_adj;
    src_fib_t         src_fib;
    src_mac_t         src_mac;
    ig_dst_bd_t       ig_dst_bd;
    dst_adj_t         dst_adj;
    pt_key_t          pt_key;
    ig_dp_intrinsic_t ingress_sideband;
    ig_dst_port_t     ig_dst_port;
    ig_acl_t          ig_acl;
    pt_info_t         pt_info;
    CFG_mark_t                 CFG_mark;
//#ifdef ACI_TOR_MODE
    CFG_BdServiceBypassInfo_t  CFG_BdServiceBypassInfo;
//#endif /*ACI_TOR_MODE*/
#if 0
    // TBD: The original P4_14 ingress code has a commented out table
    // called acl_redirect, with several actions.  It is not apply'd
    // anywhere, so it did not get translated into P4_16.  Should it
    // be here?
    acl_redirect_t    acl_redirect;

    // TBD: The original P4_14 ingress code, and this translated code,
    // has a table src_bd_profile, but it doesn't do anything with the
    // contents of struct src_bd_profile.  Should it?
    src_bd_profile_t  src_bd_profile;
#endif /*0*/
#endif /*INCLUDE_INGRESS*/

#ifdef INCLUDE_EGRESS
    egress_t          egress;
    eg_local_t        eg_local;
    dp_eg_intrinsic_t dp_eg_header;
    met_t             met;
    eg_bypass_t       eg_bypass;
    dst_port_t        dst_port;
    dst_if_t          dst_if;
    service_rw_t      service_rw;
    eg_l3_t           eg_l3;
    input_qos_info_t  input_qos_info;
    eg_qos_t          eg_qos;
    eg_drop_t         eg_drop;
    eg_acl_t          eg_acl;
    dst_bd_t          dst_bd;
    rewrite_t         rewrite;
    eg_tunnel_t       eg_tunnel;
    outer_dst_bd_t    outer_dst_bd;
    eg_src_port_t     eg_src_port;
    eg_dp_intrinsic_t eg_dp_header;
#if 0
    // TBD: The original P4_14 ingress code has a commented out
    // reference to one field inside of a struct eg_qos_acl_metadata.
    // Should eg_qos_acl.qos_map_vld, and the other fields of that
    // struct, be used somewhere in the egress code?
    eg_qos_acl_t      eg_qos_acl;
#endif /*0*/
#endif /*INCLUDE_EGRESS*/

}

struct headers {
    arp_rarp_t                arp_rarp;
    cmd_t                     cmd;
    cmd_sgt_t                 cmd_sgt;
    erspan2_t                 erspan2;
    erspan3_t                 erspan3;
    ethernet_t                ethernet;
    fcoe_t                    fcoe;
    geneve_t                  geneve;
    gre_t                     gre;
    icmp_t                    icmp;
    icmpv6_t                  icmpv6;
    ieth_t                    ieth;
    arp_rarp_t                inner_arp_rarp;
    cmd_t                     inner_cmd;
    cmd_sgt_t                 inner_cmd_sgt;
    ethernet_t                inner_ethernet;
    fcoe_t                    inner_fcoe;
    icmp_t                    inner_icmp;
    icmpv6_t                  inner_icmpv6;
    ipv4_t                    inner_ipv4;
    ipv6_t                    inner_ipv6;
    ipv6_neighbor_discovery_t inner_ipv6_nd;
    l3l4_arp_t       inner_l3l4_arp;
    l3l4_ipv4_t      inner_l3l4_ipv4;
    l3l4_ipv6_t      inner_l3l4_ipv6;
    l3l4_nd_t        inner_l3l4_nd;
    vlan_tag_t                inner_qtag0;
    vlan_tag_t                inner_qtag1;
    tcp_t                     inner_tcp;
    timestamp_t               inner_timestamp;
    udp_t                     inner_udp;
    ipv4_t                    ipv4;
    ipv6_hbh_hel1_t           ipv6_hbh_hel1;
    ipv6_hbh_hel2_t           ipv6_hbh_hel2;
    ipv6_hbh_hel3_t           ipv6_hbh_hel3;
    ipv6_t                    ipv6;
    ipv6_hop_by_hop_t         ipv6_hop_by_hop;
    ipv6_neighbor_discovery_t ipv6_nd;
    ipv6frag_t                ipv6frag;
    ivxlan_t                  ivxlan;
    llc_header_t              llc;
    nsh_t                     nsh;
    nsh_context_t             nsh_context;
    nvgre_t                   nvgre;
    l3l4_arp_t       outer_l3l4_arp;
    l3l4_ipv4_t      outer_l3l4_ipv4;
    l3l4_ipv6_t      outer_l3l4_ipv6;
    l3l4_nd_t        outer_l3l4_nd;
    vlan_tag_t                qtag0;
    vlan_tag_t                qtag1;
    snap_header_t             snap;
    tcp_t                     tcp;
    timestamp_t               timestamp;
    udp_t                     udp;
    vntag_t                   vntag;
    vxlan_gpe_t               vxlan_gpe;
    vxlan_t                   vxlan;
    //mpls_t[8]                 mpls;
}
headers() hdr;
#ifdef INCLUDE_PARSER

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state parse_arp {
        meta.l3.l3_type = L3TYPE_ARP;
        meta.l3.l3_type_ip = FALSE;
        packet.extract(hdr.arp_rarp);
        transition accept;
    }
    state parse_cmd {
        packet.extract(hdr.cmd);
        transition select(hdr.cmd.length_cmd) {
            8w1: parse_cmd_sgt;
	    // 8w2 : parse_cmd_sgt_dgt;
            default: accept;
        }
    }
    state parse_cmd_sgt {
        packet.extract(hdr.cmd_sgt);
        meta.parse.cmd_valid = TRUE;
        transition select(hdr.cmd_sgt.length_sgt, hdr.cmd_sgt.optiontype_sgt) {
            (3w0, 13w1): parse_ethertype_after_cmd;
            default: accept;
        }
    }
    state parse_erspan2 {
        packet.extract(hdr.erspan2);
        meta.ig_tunnel.erspan_session = hdr.erspan2.ses;
        transition parse_inner_ethernet;
    }
    state parse_erspan3 {
        packet.extract(hdr.erspan3);
        meta.ig_tunnel.erspan_session = hdr.erspan3.ses;
        transition parse_inner_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.l2.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2.lkp_mac_da = hdr.ethernet.dstAddr;
        transition select(hdr.ethernet.etherType) {
	    /*TODO: What is this?? I expect a length check here. */
            16w0 &&& 16w0xfe00: parse_llc_header;
            16w0 &&& 16w0xfa00: parse_llc_header;
            ETHERTYPE_IETH: parse_ieth_tag;
            ETHERTYPE_VNTAG: parse_vntag;
            ETHERTYPE_QTAG: parse_qtag0;
            ETHERTYPE_STAG: parse_qinq;
            ETHERTYPE_CMD: parse_cmd;
            ETHERTYPE_TIMESTAMP: parse_timestamp;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_RARP: parse_rarp;
            ETHERTYPE_FCOE: parse_fcoe;
            default: accept;
        }
    }
    state parse_ethertype_after_cmd {
        transition select(hdr.cmd_sgt.etherType) {
            ETHERTYPE_TIMESTAMP: parse_timestamp;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_RARP: parse_rarp;
            ETHERTYPE_FCOE: parse_fcoe;
            default: accept;
        }
    }
    state parse_ethertype_after_inner_cmd_sgt {
        transition select(hdr.inner_cmd_sgt.etherType) {
            ETHERTYPE_TIMESTAMP: parse_inner_timestamp;
            ETHERTYPE_IPV4: parse_inner_ipv4;
            ETHERTYPE_IPV6: parse_inner_ipv6;
            ETHERTYPE_ARP: parse_inner_arp;
            ETHERTYPE_RARP: parse_inner_rarp;
            ETHERTYPE_FCOE: parse_inner_fcoe;
            default: accept;
        }
    }
    state parse_fcoe {
        packet.extract(hdr.fcoe);
        transition accept;
    }
    state parse_geneve {
        packet.extract(hdr.geneve);
        meta.ig_tunnel.src_vnid = hdr.geneve.vni;
        meta.ig_tunnel.src_encap_type = ENCAP_TYPE_GENEVE;
        meta.ig_tunnel.src_l3_encap_type = L3_ENCAP_TYPE_IP;
        transition select(hdr.geneve.ver, hdr.geneve.optLen, hdr.geneve.protoType) {
            (2w0x0, 6w0x0, ETHERTYPE_ETHERNET): parse_inner_ethernet;
            (2w0x0, 6w0x0, ETHERTYPE_IPV4): parse_inner_ipv4;
            (2w0x0, 6w0x0, ETHERTYPE_IPV6): parse_inner_ipv6;
            default: accept;
        }
    }
    state parse_gre {
        packet.extract(hdr.gre);
        transition select(hdr.gre.C, hdr.gre.R, hdr.gre.K, hdr.gre.S, hdr.gre.s, hdr.gre.recurse, hdr.gre.flags, hdr.gre.ver, hdr.gre.proto) {
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, ETHERTYPE_IPV4): parse_gre_ipv4;
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, ETHERTYPE_IPV6): parse_gre_ipv6;
            (1w0x0, 1w0x0, 1w0x1, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, ETHERTYPE_ETHERNET): parse_nvgre;
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, GRE_PROTOCOLS_ERSPAN2): parse_erspan2;
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, GRE_PROTOCOLS_ERSPAN3): parse_erspan3;
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, ETHERTYPE_NSH): parse_nsh;
            default: accept;
        }
    }
    state parse_gre_ipv4 {
        meta.ig_tunnel.src_encap_pkt = TRUE;
        meta.ig_tunnel.src_encap_type = ENCAP_TYPE_GRE;
        meta.ig_tunnel.src_l3_encap_type = L3_ENCAP_TYPE_IP;
        transition parse_inner_ipv4;
    }
    state parse_gre_ipv6 {
        meta.ig_tunnel.src_encap_pkt = TRUE;
        meta.ig_tunnel.src_encap_type = ENCAP_TYPE_GRE;
        meta.ig_tunnel.src_l3_encap_type = L3_ENCAP_TYPE_IP;
        transition parse_inner_ipv6;
    }
    state parse_icmp {
        packet.extract(hdr.icmp);
        meta.l3.lkp_l4_sport = hdr.icmp.typeCode;
        transition select(hdr.icmp.typeCode) {
            default: accept;
        }
    }
    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        meta.l3.l4_type = L4TYPE_ICMPV6;
        transition select(hdr.icmpv6.code, hdr.icmpv6.type_) {
            (8w0, ICMPV6_ND_SOLICITATION): parse_ipv6_nd;
            (8w0, ICMPV6_ND_ADVERTISEMENT): parse_ipv6_nd;
            default: accept;
        }
    }
    state parse_ieth_tag {
        packet.extract(hdr.ieth);
        transition select(hdr.ieth.etherType) {
            ETHERTYPE_VNTAG: parse_vntag;
            ETHERTYPE_QTAG: parse_qtag0;
            ETHERTYPE_STAG: parse_qinq;
            ETHERTYPE_CMD: parse_cmd;
            ETHERTYPE_TIMESTAMP: parse_timestamp;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_RARP: parse_rarp;
            ETHERTYPE_FCOE: parse_fcoe;
            default: accept;
        }
    }
    state parse_inner_arp {
        packet.extract(hdr.inner_arp_rarp);
        meta.l3.inner_l3_type = L3TYPE_ARP;
        meta.l3.inner_l3_type_ip = FALSE;
        transition accept;
    }
    state parse_inner_cmd {
        packet.extract(hdr.inner_cmd);
        transition select(hdr.inner_cmd.length_cmd) {
            8w1: parse_inner_cmd_sgt;
        }
    }
    state parse_inner_cmd_sgt {
        packet.extract(hdr.inner_cmd_sgt);
        transition select(hdr.inner_cmd_sgt.length_sgt, hdr.inner_cmd_sgt.optiontype_sgt) {
            (3w0, 13w1): parse_ethertype_after_inner_cmd_sgt;
        }
    }
    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            ETHERTYPE_QTAG: parse_inner_vlan0;
            ETHERTYPE_CMD: parse_inner_cmd;
            ETHERTYPE_TIMESTAMP: parse_inner_timestamp;
            ETHERTYPE_IPV4: parse_inner_ipv4;
            ETHERTYPE_IPV6: parse_inner_ipv6;
            ETHERTYPE_ARP: parse_inner_arp;
            ETHERTYPE_RARP: parse_inner_rarp;
            ETHERTYPE_FCOE: parse_inner_fcoe;
            default: accept;
        }
    }
    state parse_inner_fcoe {
        packet.extract(hdr.inner_fcoe);
        transition accept;
    }
    state parse_inner_icmp {
        packet.extract(hdr.inner_icmp);
        meta.l3.lkp_inner_l4_sport = hdr.inner_icmp.typeCode;
        transition accept;
    }
    state parse_inner_icmpv6 {
        packet.extract(hdr.inner_icmpv6);
        meta.l3.inner_l4_type = L4TYPE_ICMPV6;
        transition select(hdr.inner_icmpv6.code, hdr.inner_icmpv6.type_) {
            (8w0, ICMPV6_ND_SOLICITATION): parse_inner_ipv6_nd;
            (8w0, ICMPV6_ND_ADVERTISEMENT): parse_inner_ipv6_nd;
            default: accept;
        }
    }
    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        meta.l3.inner_l3_type = L3TYPE_IPV4;
        meta.l3.inner_l3_type_ip = TRUE;
        transition select(hdr.inner_ipv4.fragOffset, hdr.inner_ipv4.ihl, hdr.inner_ipv4.protocol) {
            (13w0x0, 4w0x5, IP_PROTOCOLS_ICMP): parse_inner_icmp;
            (13w0x0, 4w0x5, IP_PROTOCOLS_TCP): parse_inner_tcp;
            (13w0x0, 4w0x5, IP_PROTOCOLS_UDP): parse_inner_udp;
            default: accept;
        }
    }
    state parse_inner_ipv6 {
        packet.extract(hdr.inner_ipv6);
        meta.l3.inner_l3_type = L3TYPE_IPV6;
        meta.l3.inner_l3_type_ip = TRUE;
        transition select(hdr.inner_ipv6.nextHeader) {
            IP_PROTOCOLS_ICMPV6: parse_inner_icmpv6;
            IP_PROTOCOLS_TCP: parse_inner_tcp;
            IP_PROTOCOLS_UDP: parse_inner_udp;
            default: accept;
        }
    }
    state parse_inner_ipv6_nd {
        packet.extract(hdr.inner_ipv6_nd);
        meta.l3.inner_l4_type = L4TYPE_ND;
        transition accept;
    }
    state parse_inner_rarp {
        packet.extract(hdr.inner_arp_rarp);
        meta.l3.inner_l3_type = L3TYPE_RARP;
        meta.l3.inner_l3_type_ip = FALSE;
        transition accept;
    }
    state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        meta.l3.lkp_inner_l4_sport = hdr.inner_tcp.srcPort;
        meta.l3.lkp_inner_l4_dport = hdr.inner_tcp.dstPort;
        meta.l3.lkp_inner_tcp_flags = hdr.inner_tcp.flags;
        transition accept;
    }
    state parse_inner_timestamp {
        packet.extract(hdr.inner_timestamp);
        transition select(hdr.inner_timestamp.etherType) {
            ETHERTYPE_IPV4: parse_inner_ipv4;
            ETHERTYPE_IPV6: parse_inner_ipv6;
            ETHERTYPE_ARP: parse_inner_arp;
            ETHERTYPE_RARP: parse_inner_rarp;
            ETHERTYPE_FCOE: parse_inner_fcoe;
            default: accept;
        }
    }
    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        meta.l3.lkp_inner_l4_sport = hdr.inner_udp.srcPort;
        meta.l3.lkp_inner_l4_dport = hdr.inner_udp.dstPort;
        transition accept;
    }
    state parse_inner_vlan0 {
        packet.extract(hdr.inner_qtag0);
        meta.parse.inner_qtag_valid = TRUE;
        transition select(hdr.inner_qtag0.etherType) {
            ETHERTYPE_CMD: parse_inner_cmd;
            ETHERTYPE_TIMESTAMP: parse_inner_timestamp;
            ETHERTYPE_IPV4: parse_inner_ipv4;
            ETHERTYPE_IPV6: parse_inner_ipv6;
            ETHERTYPE_ARP: parse_inner_arp;
            ETHERTYPE_RARP: parse_inner_rarp;
            ETHERTYPE_FCOE: parse_inner_fcoe;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.ipv4m.lkp_ipv4_sa = hdr.ipv4.srcAddr;
        meta.ipv4m.lkp_ipv4_da = hdr.ipv4.dstAddr;
        meta.l3.l3_type = L3TYPE_IPV4;
        meta.l3.l3_type_ip = TRUE;
        meta.l3.lkp_ip_proto = hdr.ipv4.protocol;
        meta.l3.lkp_ip_ttl = hdr.ipv4.ttl;
        meta.l3.lkp_ip_dscp = hdr.ipv4.dscp;
        meta.l3.lkp_ip_ecn = hdr.ipv4.ecn;
        meta.l3.lkp_ip_len = hdr.ipv4.totalLen;
        meta.l3.lkp_ip_fragOffset = hdr.ipv4.fragOffset;
        meta.l3.lkp_ip_flag_more = hdr.ipv4.flag_more;
        transition select(hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.flag_rsvd, hdr.ipv4.flag_noFrag, hdr.ipv4.flag_more, hdr.ipv4.fragOffset, hdr.ipv4.protocol) {
            (4w0x4 &&& 4w0xf, 4w0x5 &&& 4w0xf, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 13w0x0 &&& 13w0x1fff, 8w0x2f &&& 8w0xff): parse_gre;
            (4w0x4 &&& 4w0xf, 4w0x5 &&& 4w0xf, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 13w0x0 &&& 13w0x1fff, 8w0x4 &&& 8w0xff): parse_ipv4_in_ip;
            (4w0x4 &&& 4w0xf, 4w0x5 &&& 4w0xf, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 13w0x0 &&& 13w0x1fff, 8w0x29 &&& 8w0xff): parse_ipv6_in_ip;
            (4w0x4 &&& 4w0xf, 4w0x5 &&& 4w0xf, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 13w0x0 &&& 13w0x1fff, 8w0x11 &&& 8w0xff): parse_udp;
            (4w0x4 &&& 4w0xf, 4w0x5 &&& 4w0xf, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 13w0x0 &&& 13w0x1fff, 8w0x1 &&& 8w0xff): parse_icmp;
            (4w0x4 &&& 4w0xf, 4w0x5 &&& 4w0xf, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 13w0x0 &&& 13w0x1fff, 8w0x6 &&& 8w0xff): parse_tcp;
            (4w0x4 &&& 4w0xf, 4w0x0 &&& 4w0x0, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 1w0x0 &&& 1w0x0, 13w0x0 &&& 13w0x0, 8w0x0 &&& 8w0x0): accept;
        }
    }
    state parse_ipv4_in_ip {
        meta.ig_tunnel.src_encap_pkt = TRUE;
        meta.ig_tunnel.src_encap_type = ENCAP_TYPE_IP_IN_IP;
        meta.ig_tunnel.src_l3_encap_type = L3_ENCAP_TYPE_IP;
        transition parse_inner_ipv4;
    }
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        meta.ipv6m.lkp_ipv6_sa = hdr.ipv6.srcAddr;
        meta.ipv6m.lkp_ipv6_da = hdr.ipv6.dstAddr;
        meta.l3.l3_type = L3TYPE_IPV6;
        meta.l3.l3_type_ip = TRUE;
        meta.l3.lkp_ip_proto = hdr.ipv6.nextHeader;
        meta.l3.lkp_ip_ttl = hdr.ipv6.hopLimit;
        meta.l3.lkp_ip_dscp = hdr.ipv6.dscp;
        meta.l3.lkp_ip_ecn = hdr.ipv6.ecn;
        meta.l3.lkp_ip_len = hdr.ipv6.payloadLen;
        transition select(hdr.ipv6.nextHeader) {
            IPV6_NEXT_HDR_TCP: parse_tcp;
            IPV6_NEXT_HDR_UDP: parse_udp;
            IPV6_NEXT_HDR_ICMPV6: parse_icmp;
            IPV6_NEXT_HDR_GRE: parse_gre;
            IPV6_NEXT_HDR_IPV4: parse_ipv4_in_ip;
            IPV6_NEXT_HDR_IPV6: parse_ipv6_in_ip;
            IPV6_NEXT_HDR_HBH: parse_ipv6_hop_by_hop;
            IPV6_NEXT_HDR_FRAG: parse_ipv6frag;
            default: accept;
        }
    }
    state parse_ipv6_hop_by_hop {
        packet.extract(hdr.ipv6_hop_by_hop);
        transition select(hdr.ipv6_hop_by_hop.protocol) {
            IPV6_HBH_HEL0_NEXT_ICMPV6: parse_icmpv6;
            IPV6_HBH_HEL0_NEXT_UDP: parse_udp;
            IPV6_HBH_HEL0_NEXT_TCP: parse_tcp;
            IPV6_HBH_HEL0_NEXT_FRAG: parse_ipv6frag;
            default: accept;
        }
    }
    state parse_ipv6_in_ip {
        meta.ig_tunnel.src_encap_pkt = TRUE;
        meta.ig_tunnel.src_encap_type = ENCAP_TYPE_IP_IN_IP;
        meta.ig_tunnel.src_l3_encap_type = L3_ENCAP_TYPE_IP;
        transition parse_inner_ipv6;
    }
    state parse_ipv6_nd {
        packet.extract(hdr.ipv6_nd);
        meta.l3.l4_type = L4TYPE_ND;
        transition accept;
    }
    state parse_ipv6frag {
        packet.extract(hdr.ipv6frag);
        meta.l3.lkp_ip_flag_more = hdr.ipv6frag.flag_more;
        meta.l3.lkp_ip_fragOffset = hdr.ipv6frag.fragOffset;
        transition select(hdr.ipv6frag.flag_more, hdr.ipv6frag.fragOffset, hdr.ipv6frag.protocol) {
            (1w0x0 &&& 1w0x0, 13w0x0 &&& 13w0x1fff, 8w0x3a &&& 8w0xff): parse_icmpv6;
            (1w0x0 &&& 1w0x0, 13w0x0 &&& 13w0x0, 8w0x11 &&& 8w0xff): parse_udp;
            (1w0x0 &&& 1w0x0, 13w0x0 &&& 13w0x0, 8w0x6 &&& 8w0xff): parse_tcp;
            default: accept;
        }
    }
    state parse_ivxlan {
        packet.extract(hdr.ivxlan);
        meta.ig_tunnel.src_encap_pkt = TRUE;
        meta.ig_tunnel.src_encap_type = ENCAP_TYPE_IVXLAN;
        meta.ig_tunnel.src_l3_encap_type = L3_ENCAP_TYPE_IP;
        meta.ig_tunnel.src_vnid = hdr.ivxlan.vni;
        transition parse_inner_ethernet;
    }
    state parse_llc_header {
        packet.extract(hdr.llc);
        transition select(hdr.llc.dsap, hdr.llc.ssap) {
            (8w0xaa, 8w0xaa): parse_snap_header;
            default: accept;
        }
    }
    state parse_nsh {
        packet.extract(hdr.nsh);
        packet.extract(hdr.nsh_context);
        transition select(hdr.nsh.next_proto) {
            NSH_NEXT_PROTO_IPV4: parse_inner_ipv4;
            NSH_NEXT_PROTO_IPV6: parse_inner_ipv6;
            NSH_NEXT_PROTO_ETHERNET: parse_inner_ethernet;
            default: accept;
        }
    }
    state parse_nvgre {
        packet.extract(hdr.nvgre);
        meta.ig_tunnel.src_encap_type = ENCAP_TYPE_NVGRE;
        meta.ig_tunnel.src_l3_encap_type = L3_ENCAP_TYPE_IP;
        meta.ig_tunnel.src_vnid = hdr.nvgre.tni;
        transition parse_inner_ethernet;
    }
    state parse_qinq {
        packet.extract(hdr.qtag0);
        meta.parse.qtag_valid = TRUE;
        transition select(hdr.qtag0.etherType) {
            ETHERTYPE_QTAG: parse_qtag1;
            default: accept;
        }
    }
    state parse_qtag0 {
        packet.extract(hdr.qtag0);
        meta.parse.qtag_valid = TRUE;
        transition select(hdr.qtag0.etherType) {
            ETHERTYPE_CMD: parse_cmd;
            ETHERTYPE_QTAG: parse_qtag1;
            ETHERTYPE_TIMESTAMP: parse_timestamp;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_RARP: parse_rarp;
            ETHERTYPE_FCOE: parse_fcoe;
            default: accept;
        }
    }
    state parse_qtag1 {
        packet.extract(hdr.qtag1);
        meta.parse.qinq_tag_valid = TRUE;
        transition select(hdr.qtag1.cfi, hdr.qtag1.etherType) {
            (1w0x1, ETHERTYPE_CMD): accept;
            (1w0x0, ETHERTYPE_CMD): parse_cmd;
            (1w0x0 &&& 1w0x0, ETHERTYPE_TIMESTAMP): parse_timestamp;
            (1w0x0 &&& 1w0x0, ETHERTYPE_IPV4): parse_ipv4;
            (1w0x0 &&& 1w0x0, ETHERTYPE_IPV6): parse_ipv6;
            (1w0x0 &&& 1w0x0, ETHERTYPE_ARP): parse_arp;
            (1w0x0 &&& 1w0x0, ETHERTYPE_RARP): parse_rarp;
            (1w0x0 &&& 1w0x0, ETHERTYPE_FCOE): parse_fcoe;
            default: accept;
        }
    }
    state parse_rarp {
        meta.l3.l3_type = L3TYPE_RARP;
        meta.l3.l3_type_ip = FALSE;
        packet.extract(hdr.arp_rarp);
        transition accept;
    }
    state parse_snap_header {
        packet.extract(hdr.snap);
        transition select(hdr.snap.type_) {
            ETHERTYPE_IETH: parse_ieth_tag;
            ETHERTYPE_VNTAG: parse_vntag;
            ETHERTYPE_QTAG: parse_qtag0;
            ETHERTYPE_STAG: parse_qinq;
            ETHERTYPE_CMD: parse_cmd;
            ETHERTYPE_TIMESTAMP: parse_timestamp;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_RARP: parse_rarp;
            ETHERTYPE_FCOE: parse_fcoe;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.l3.l4_type = L4TYPE_TCP;
        meta.l3.lkp_l4_sport = hdr.tcp.srcPort;
        meta.l3.lkp_l4_dport = hdr.tcp.dstPort;
        meta.l3.lkp_tcp_flags = hdr.tcp.flags;
        transition select(hdr.tcp.dstPort) {
            default: accept;
        }
    }
    state parse_timestamp {
        packet.extract(hdr.timestamp);
        transition select(hdr.timestamp.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_RARP: parse_rarp;
            ETHERTYPE_FCOE: parse_fcoe;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        meta.l3.l4_type = L4TYPE_UDP;
        meta.l3.lkp_l4_sport = hdr.udp.srcPort;
        meta.l3.lkp_l4_dport = hdr.udp.dstPort;
        transition select(hdr.udp.dstPort) {
            UDP_PORT_VXLAN: parse_vxlan;
            UDP_PORT_IVXLAN: parse_ivxlan;
            UDP_PORT_GENEVE: parse_geneve;
            UDP_PORT_VXLAN_GPE: parse_vxlan_gpe;
            // UDP_PORT_LISP      : parse_lisp;
            default: accept;
        }
    }
    state parse_vntag {
        packet.extract(hdr.vntag);
        transition select(hdr.vntag.etherType) {
            ETHERTYPE_QTAG: parse_qtag0;
            ETHERTYPE_STAG: parse_qinq;
            ETHERTYPE_CMD: parse_cmd;
            ETHERTYPE_TIMESTAMP: parse_timestamp;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_RARP: parse_rarp;
            ETHERTYPE_FCOE: parse_fcoe;
            default: accept;
        }
    }
    state parse_vxlan {
        packet.extract(hdr.vxlan);
        meta.ig_tunnel.src_encap_pkt = TRUE;
        meta.ig_tunnel.src_encap_type = ENCAP_TYPE_VXLAN;
        meta.ig_tunnel.src_l3_encap_type = L3_ENCAP_TYPE_IP;
        meta.ig_tunnel.src_vnid = hdr.vxlan.vni;
        transition parse_inner_ethernet;
    }
    state parse_vxlan_gpe {
        packet.extract(hdr.vxlan_gpe);
        meta.ig_tunnel.src_encap_type = ENCAP_TYPE_VXLAN_GPE;
        meta.ig_tunnel.src_l3_encap_type = L3_ENCAP_TYPE_IP;
        meta.ig_tunnel.src_vnid = hdr.vxlan_gpe.vni;
        transition select(hdr.vxlan_gpe.flags_p, hdr.vxlan_gpe.next_proto) {
            (1w0x1, 8w0x1): parse_inner_ipv4;
            (1w0x1, 8w0x2): parse_inner_ipv6;
            (1w0x1, 8w0x3): parse_inner_ethernet;
            (1w0x1, 8w0x4): parse_nsh;
            default: parse_inner_ethernet;
        }
    }
    state start {
        transition parse_ethernet;
    }
}

#else /*INCLUDE_PARSER*/

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

#endif /*INCLUDE_PARSER*/


#ifdef INCLUDE_INGRESS
#include "sug_ig.p4"
#else /*INCLUDE_INGRESS*/
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}
#endif /*INCLUDE_INGRESS*/

#ifdef INCLUDE_EGRESS
#include "sug_eg.p4"
#else /*INCLUDE_EGRESS*/
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}
#endif /*INCLUDE_EGRESS*/


control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.llc);
        packet.emit(hdr.snap);
        packet.emit(hdr.ieth);
        packet.emit(hdr.vntag);
        packet.emit(hdr.qtag0);
        packet.emit(hdr.qtag1);
        packet.emit(hdr.cmd);
        packet.emit(hdr.cmd_sgt);
        packet.emit(hdr.timestamp);
        packet.emit(hdr.fcoe);
        packet.emit(hdr.arp_rarp);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ipv6_hop_by_hop);
        packet.emit(hdr.ipv6frag);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ipv6_nd);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.vxlan_gpe);
        packet.emit(hdr.geneve);
        packet.emit(hdr.ivxlan);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.gre);
        packet.emit(hdr.nsh);
        packet.emit(hdr.nsh_context);
        packet.emit(hdr.erspan3);
        packet.emit(hdr.erspan2);
        packet.emit(hdr.nvgre);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_qtag0);
        packet.emit(hdr.inner_cmd);
        packet.emit(hdr.inner_cmd_sgt);
        packet.emit(hdr.inner_timestamp);
        packet.emit(hdr.inner_fcoe);
        packet.emit(hdr.inner_arp_rarp);
        packet.emit(hdr.inner_ipv6);
        packet.emit(hdr.inner_icmpv6);
        packet.emit(hdr.inner_ipv6_nd);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_udp);
        packet.emit(hdr.inner_tcp);
        packet.emit(hdr.inner_icmp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(hdr.inner_ipv4.ihl == 5,
            { hdr.inner_ipv4.version,
                hdr.inner_ipv4.ihl,
                hdr.inner_ipv4.dscp,
                hdr.inner_ipv4.ecn,
                hdr.inner_ipv4.totalLen,
                hdr.inner_ipv4.identification,
                hdr.inner_ipv4.flag_rsvd,
                hdr.inner_ipv4.flag_noFrag,
                hdr.inner_ipv4.flag_more,
                hdr.inner_ipv4.fragOffset,
                hdr.inner_ipv4.ttl,
                hdr.inner_ipv4.protocol,
                hdr.inner_ipv4.srcAddr,
                hdr.inner_ipv4.dstAddr },
            hdr.inner_ipv4.hdrChecksum, HashAlgorithm.csum16);
        verify_checksum(hdr.ipv4.ihl == 5,
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flag_rsvd,
                hdr.ipv4.flag_noFrag,
                hdr.ipv4.flag_more,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.inner_ipv4.ihl == 5,
            { hdr.inner_ipv4.version,
                hdr.inner_ipv4.ihl,
                hdr.inner_ipv4.dscp,
                hdr.inner_ipv4.ecn,
                hdr.inner_ipv4.totalLen,
                hdr.inner_ipv4.identification,
                hdr.inner_ipv4.flag_rsvd,
                hdr.inner_ipv4.flag_noFrag,
                hdr.inner_ipv4.flag_more,
                hdr.inner_ipv4.fragOffset,
                hdr.inner_ipv4.ttl,
                hdr.inner_ipv4.protocol,
                hdr.inner_ipv4.srcAddr,
                hdr.inner_ipv4.dstAddr },
            hdr.inner_ipv4.hdrChecksum, HashAlgorithm.csum16);
        update_checksum(hdr.ipv4.ihl == 5,
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flag_rsvd,
                hdr.ipv4.flag_noFrag,
                hdr.ipv4.flag_more,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         DeparserImpl()) main;
