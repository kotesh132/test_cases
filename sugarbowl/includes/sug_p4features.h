#ifndef ST_P4_FEATURES_H
#define ST_P4_FEATURES_H


//#define DISABLE_EGRESS_PIPELINE
//#define DISABLE_SUP_TX

//----------------------------
// ACI vs Standalone
//---------------------------

// BIG BIG TODO - I need to check with Ashu first, but I am pretty
// sure that to create a single chip that can function in standalone
// vs. ACI mode, we need a run-time config register for this mode, and
// everywhere the code currently has #ifdef ACI_TOR_MODE or #ifndef
// ACI_TOR_MODE, we need run-time selection of the two behaviors.

// Note that while there are many occurrences of such #ifdef and
// #ifndef of ACI_TOR_MODE in the current P4_16 code, there could
// easily be some in the original P4_14 code that did not get
// converted.  Best to search for all such occurrences in the original
// P4_14 and see if they got converted over.  Unfortunately there are
// 95 of these when I last counted, so it is a lot to go through.

// Also note that we should think carefully about _how_ to have these
// run-time conditions in the P4_16 code, if we are concerned about
// increasing chip area (which we should be).  I believe there are
// some physical tables in Tahoe family ASICs that are completely used
// for one purpose in ACI mode, vs. for a completely different purpose
// in standalone mode.  There could be partial overlays, too -- I
// don't know yet.

//#define ACI_TOR_MODE

#ifdef ACI_TOR_MODE
//#define DISABLE_MC_BRIDGE_LOOKUPS
//#define DISABLE_PORT_SECURITY
//#define DISABLE_L2_BIND_CHECK
//#define DISABLE_URPF_CHECK
//#define DISABLE_L3_SELF_FWD_CHECK

// Commenting out DISABLE_MPLS to enable MPLS has many affects spread
// throughout many places.
//#define DISABLE_MPLS
//#define DISABLE_MPLS_REWRITE // figure out how to implement swap + push

//#define DISABLE_FCF
//#define DISABLE_MODULAR_CHASIS
//#define DISABLE_L3_TUNNELS

// Enabling COPP_TCAM (by commenting out next line) enables a few more
// tables and their actions.
//#define DISABLE_COPP_TCAM

// DISABLE_SUBNET_NET enabled/disabled only makes a small difference
// in the parameters to one action of one table.  It might change the
// width of that one table, but that is all.
//#define DISABLE_SUBNET_NAT

//#define DISABLE_FTAG_OVERRIDE

// DISABLE_V6_VTEP enable/disable doesn't affect the original P4_14
// code at all, nor the converted P4_16 code.
//#define DISABLE_V6_VTEP

//#define DISABLE_SERVICE_BYPASS
//#define DISABLE_OUTER_SG
//#define DISABLE_NAT

//#define DISABLE_NAT_OVERLOAD
//#define DISABLE_IG_MTU_CHECK
//#define DISABLE_PKT_LEN_CALC

//#define DISABLE_OUTER_SRC_BD_STATS
// #define DISABLE_PT_STATS
// #define DISABLE_SRC_BD_STATS
// #define DISABLE_DST_BD_STATS
// #define DISABLE_SRC_TEP_STATS
// #define DISABLE_DST_TEP_STATS
// #define DISABLE_SRC_PORT_STATS
// #define DISABLE_DST_PORT_STATS

#endif /*ACI_TOR_MODE */

// Trying to enable IPv6 NAT by commenting out the next line fails
// right now, because the code tries to call a control block
// process_ipv6_nat_rewrite that is not yet implemented.
#define DISABLE_IPV6_NAT

//#define DISABLE_FEX

//----------------------------
// Misc
//---------------------------

//#define SEPARATE_BD_STATE_TABLE
//#define SEPARATE_SRC_IF_STATE_TABLE
//#define MERGE_2LAYER_VPC_RESOLUTION
//#define DISABLE_NVGRE
#define DISABLE_VIF_BYPASS

#define USE_TABLE_FOR_FWD_MODE
#define MERGE_HRT_AND_LPM

#define INS_ERSPAN_GRE_SEQ_NUM
//----------------------------
// Compiler/Hardware related
//---------------------------

#define SINGLE_LOOKUP_MODE
#define DISABLE_CFG_REGISTERS

// P4_16 is by definition always sequential semantics.  With P4_14
// there was a time when it was parallel semantics for executing the
// actions within a compound action, but that was later changed to
// sequential.  I believe the DISABLE_SEQUENTIAL_SEMANTICS was used to
// work around some older P4_14 sequential vs. parallel semantics
// issues in the language, which are gone in P4_16.
//#define DISABLE_SEQUENTIAL_SEMANTICS

#define DISABLE_UNEQUAL_WIDTH_OPS

// TODO - Look at occurrences of this symbol in the original P4_14
// code.  There are many in the sug_parser.p4 parser code that have
// *not* been translated and included in this P4_16 code yet.
#define DISABLE_METADATA_IN_PARSER

// TODO - Look at occurrences of this symbol in the original P4_14
// code.  There is one in the sug_parser.p4 parser code that has
// *not* been translated and included in this P4_16 code yet.
#define DISABLE_PARSER_EXCEPTIONS

#define USE_IETH_AS_L2_TAG

#define SHRINK_VLAN_MBR_TBL

#define SUPPORT_IPV6_EXT_HDRS

#define DISABLE_LCPU_INSERTION
//#define SUPPORT_IPV4_OPTIONS


// TODO
// ids checks
// ss_vrf tile and lookup logic
// v6_opt 64
// fp-nat
// flow hash
// FCoE logic (hashing, acls etc )
// igmp-mld table
// result merging and dst_idx/ptr - incomplete
// vpc fast conv
// double exception drop logic
// glean adjacency logic
// PT sampler
#endif
