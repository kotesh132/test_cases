#ifndef ST_SIZES_H
#define ST_SIZES_H

#include "sug_p4features.h"

#define MIN_SRAM_TABLE_SIZE                    1024
#define MIN_TCAM_TABLE_SIZE                    512

//Port
#define NUM_PORTS_PER_SLICE                      64 // Number of local ports on a slice including front-panel, cpu, loopback
#define NUM_PORTS_PER_CHIP                      128 // Number of ports on a chip across all slices including front-panel, cpu, loopback

#ifdef ACI_TOR_MODE
#define NUM_CHIPS_PER_CHASIS                   1
#define NUM_PORTS_PER_CHASIS                  NUM_PORTS_PER_CHIP
#else
#define NUM_CHIPS_PER_CHASIS                   128
#define NUM_PORTS_PER_CHASIS                  4096
#endif

#define NUM_L2_IF                             8192
#define NUM_MC_DVIF                          16384

//Vlan
//#define NUM_PV_MAP                           4096
//#define NUM_VNID_MAP                         4096
//#define NUM_EPG                              4096
//#define NUM_BD                               4096
//#define NUM_VNID                             4096
#define NUM_PV_MAP                           16384
#define NUM_VNID_MAP                         16384
#define NUM_EPG                              16384
#define NUM_BD                               16384
#define NUM_VNID                             16384

// CBL

//VTEP
#define NUM_REMOTE_IPV4_TEP                 4096
#define NUM_REMOTE_IPV6_TEP                 2048
#define NUM_LOCAL_IPV4_TEP                   256
#define NUM_LOCAL_IPV6_TEP                   128

//-----------------------------------------------------------------------------
// Table Sizes
//-----------------------------------------------------------------------------

// Misc
#define HASH_OF_TCAM_RATIO                     8
#define DECODE_ETHERNET_ADDR_SIZE             16
#define BYPASS_INFO_TABLE_SIZE                32
#define MTU_TABLE_SIZE                        128
#define FLOOD_INFO_TABLE_SIZE                 8192
#define EG_BYPASS_INFO_TABLE_SIZE             64

#define FWD_MODE_TABLE_SIZE MIN_TCAM_TABLE_SIZE

//#ifdef ACI_TOR_MODE
#define SPINE_PROXY_DST_TABLE_SIZE            32
//#endif /*ACI_TOR_MODE*/

// ~~~~~~ Port ~~~~~~ 
#define LOCAL_SRC_PORTMAP_TABLE_SIZE          NUM_PORTS_PER_SLICE
#define GLOBAL_SRC_PORTMAP_TABLE_SIZE         NUM_PORTS_PER_CHASIS
#define DST_PORTMAP_TABLE_SIZE                NUM_PORTS_PER_SLICE
#define SRC_CHIP_TABLE_SIZE                   NUM_CHIPS_PER_CHASIS

#define SRC_IF_HASH_TABLE_SIZE                NUM_L2_IF   // Number of L2 interfaces including FEX ports
#define SRC_IF_OF_TCAM_SIZE                   1024

#define SRC_IF_STATE_TABLE_SIZE               NUM_L2_IF
#define DST_IF_STATE_TABLE_SIZE               NUM_L2_IF

#define SRC_IF_PROFILE_TABLE_SIZE             1024

#define SVIF_HASH_TABLE_SIZE                  NUM_L2_IF
#define SVIF_OF_TCAM_SIZE                     1024
//#define SVIF_OF_TCAM_SIZE                     NUM_L2_IF/HASH_OF_TCAM_RATIO

#define UC_DVIF_HASH_TABLE_SIZE               NUM_L2_IF
#define UC_DVIF_OF_TCAM_SIZE                  1024

#define MC_DVIF_HASH_TABLE_SIZE               NUM_MC_DVIF
#define MC_DVIF_OF_TCAM_SIZE                  2048

#define VPC_MP_TABLE_SIZE                     NUM_L2_IF
#define PC_CFG_TABLE_SIZE                     NUM_PORTS_PER_CHASIS 
#define PC_MBR_TABLE_SIZE                     NUM_PORTS_PER_CHASIS 
#define PC_BIT_WIDTH                           8 
#define VPC_BIT_WIDTH                          1 

#define EG_SRC_PORT_STATE_TABLE_SIZE         NUM_PORTS_PER_CHIP

// ~~~~~~  Vlan ~~~~~~ 
#define SRC_VLAN_XLATE_HASH_TABLE_SIZE       NUM_PV_MAP
#define SRC_VLAN_XLATE_OF_TCAM_SIZE          2048
#define DST_VLAN_XLATE_HASH_TABLE_SIZE       NUM_PV_MAP
#define DST_VLAN_XLATE_OF_TCAM_SIZE          2048

#define SRC_EPG_STATE_TABLE_SIZE             NUM_EPG
#define DST_EPG_STATE_TABLE_SIZE             NUM_EPG

#define SRC_BD_STATE_TABLE_SIZE              NUM_BD
#define SRC_BD_PROFILE_TABLE_SIZE            1024
#define DST_BD_STATE_TABLE_SIZE              NUM_BD

#define INGRESS_VLAN_MBR_SEARCH_HASH_TABLE_SIZE 16384  //TODO
#define INGRESS_VLAN_MBR_SEARCH_TCAM_SIZE        1024
#ifdef SHRINK_VLAN_MBR_TBL
#define INGRESS_VLAN_MBR_TABLE_SIZE           16384
#define EGRESS_VLAN_MBR_TABLE_SIZE            4096
#else
#define INGRESS_VLAN_MBR_TABLE_SIZE           1048576
#define EGRESS_VLAN_MBR_TABLE_SIZE             262144
#endif

#define INNER_SRC_BD_STATE_TABLE_SIZE        NUM_VNID
#define INNER_SRC_BD_PROFILE_TABLE_SIZE      1024
#define INNER_DST_BD_STATE_TABLE_SIZE        NUM_VNID

#define SRC_VNID_XLATE_HASH_TABLE_SIZE       NUM_VNID_MAP
#define SRC_VNID_XLATE_OF_TCAM_SIZE          2048
#define DST_VNID_XLATE_HASH_TABLE_SIZE       NUM_VNID_MAP
#define DST_VNID_XLATE_OF_TCAM_SIZE          2048

// ~~~~~~  Tunnels ~~~~~~ 

#define IPV4_DST_TEP_TABLE_SIZE              NUM_LOCAL_IPV4_TEP
#define IPV4_SRC_TEP_TABLE_SIZE              NUM_REMOTE_IPV4_TEP
#define IPV6_DST_TEP_TABLE_SIZE              NUM_LOCAL_IPV6_TEP
#define IPV6_SRC_TEP_TABLE_SIZE              NUM_REMOTE_IPV6_TEP

#define IPV4_SRC_TEP_HASH_TABLE_SIZE         IPV4_SRC_TEP_TABLE_SIZE
#define IPV6_SRC_TEP_HASH_TABLE_SIZE         IPV6_SRC_TEP_TABLE_SIZE
#define IPV4_SRC_TEP_OF_TCAM_SIZE            512
#define IPV6_SRC_TEP_OF_TCAM_SIZE            256

#define IPV4_SIPO_REWRITE_TABLE_SIZE         NUM_LOCAL_IPV4_TEP
#define IPV6_SIPO_REWRITE_TABLE_SIZE         NUM_LOCAL_IPV6_TEP
#define IPV4_DIPO_REWRITE_TABLE_SIZE         NUM_REMOTE_IPV4_TEP
#define IPV6_DIPO_REWRITE_TABLE_SIZE         NUM_REMOTE_IPV6_TEP

#define OUTER_DMAC_REWRITE_TABLE_SIZE       4096
#define OUTER_SMAC_REWRITE_TABLE_SIZE       4096

#define TUNNEL_ECMP_GROUP_TABLE_SIZE  256 //TODO
#define TUNNEL_ECMP_MEMBER_TABLE_SIZE 256 //TODO

// ~~~~~~  Tunnel - Multicast ~~~~~~ 
#define IPV4_TUNNEL_MC_GROUP_HASH_TABLE_SIZE          4096
#define IPV4_TUNNEL_MC_SG_HASH_TABLE_SIZE             4096
#define IPV6_TUNNEL_MC_GROUP_HASH_TABLE_SIZE          2048
#define IPV6_TUNNEL_MC_SG_HASH_TABLE_SIZE             2048

#define IPV4_TUNNEL_MC_GROUP_OF_TCAM_SIZE          512
#define IPV4_TUNNEL_MC_SG_OF_TCAM_SIZE             256
#define IPV6_TUNNEL_MC_GROUP_OF_TCAM_SIZE          512
#define IPV6_TUNNEL_MC_SG_OF_TCAM_SIZE             256

#define TUNNEL_MC_RPF_HASH_TABLE_SIZE            1024
#define TUNNEL_MC_RPF_OF_TCAM_SIZE                256 // Logic is not same as Sugarbowl

#define TUNNEL_MC_RESOLUTION_TABLE_SIZE       16
#define TUNNEL_TERMINATION_TABLE_SIZE         16

#define TUNNEL_REWRITE_TABLE_SIZE           4096

// ~~~~~~~~ MPLS ~~~~~~~~  
#define MPLS_VPN_LABEL_OF_TCAM_SIZE          256
#define MPLS_VPN_LABEL_HASH_TABLE_SIZE      2048

#define MPLS_REWRITE_TABLE_SIZE             4096

// ~~~~~~~~  L3 ~~~~~~~~ 
#define SMAC_REWRITE_TABLE_SIZE             2048
#define DMAC_REWRITE_TABLE_SIZE             2048
#define ROUTER_MAC_TCAM_SIZE                1024
#define ROUTER_MAC_DIRMAP_SIZE              1024
#define INNER_ROUTER_MAC_TABLE_SIZE         4096
#define URPF_HASH_TABLE_SIZE                8192   // 
#define URPF_OF_TCAM_SIZE                   3548   //  TODO : Shared between multicast and unicast

#define L3_ECMP_GROUP_TABLE_SIZE  24576
#define L3_ECMP_MEMBER_TABLE_SIZE 32768

// ~~~~~~~~  NAT ~~~~~~~~ 
#define IPV4_TWICE_NAT_HASH_TABLE_SIZE 2048
#define IPV4_SRC_NAT_HASH_TABLE_SIZE 2048
#define IPV4_DST_NAT_HASH_TABLE_SIZE 2048
#define IPV6_SRC_NAT_HASH_TABLE_SIZE 256
#define IPV6_DST_NAT_HASH_TABLE_SIZE 256

#define IPV4_NAT_REWRITE_TABLE_SIZE 4096
#define IPV6_NAT_REWRITE_TABLE_SIZE 256

#define NAT_HIT_BITS_TABLE_SIZE 2048

// ~~~~~~~~  Multicast ~~~~~~~~ 
// Total 8K IPv4 equivalent
#ifdef DISABLE_MC_BRIDGE_LOOKUPS

#define IPV4_MC_ROUTE_GROUP_HASH_TABLE_SIZE 4096
#define IPV6_MC_ROUTE_GROUP_HASH_TABLE_SIZE 2048
// 1.5K IPv4 equivalent
#define IPV4_MC_ROUTE_GROUP_OF_TCAM_SIZE 512
#define IPV6_MC_ROUTE_GROUP_OF_TCAM_SIZE 256

// Total 8K IPv4 equivalent ( no tiles allocated in sugarbowl)
#define IPV4_MC_ROUTE_SG_HASH_TABLE_SIZE 4096
#define IPV6_MC_ROUTE_SG_HASH_TABLE_SIZE  2048
#define IPV4_MC_ROUTE_SG_OF_TCAM_SIZE  512
#define IPV6_MC_ROUTE_SG_OF_TCAM_SIZE  256

#else /*DISABLE_MC_BRIDGE_LOOKUPS*/

#define IPV4_MC_ROUTE_GROUP_HASH_TABLE_SIZE 2048
#define IPV6_MC_ROUTE_GROUP_HASH_TABLE_SIZE 1024
#define IPV4_MC_BRIDGE_GROUP_HASH_TABLE_SIZE 2048
#define IPV6_MC_BRIDGE_GROUP_HASH_TABLE_SIZE 1024
// 1.5K IPv4 equivalent
#define IPV4_MC_ROUTE_GROUP_OF_TCAM_SIZE 256
#define IPV6_MC_ROUTE_GROUP_OF_TCAM_SIZE 256
#define IPV4_MC_BRIDGE_GROUP_OF_TCAM_SIZE 256
#define IPV6_MC_BRIDGE_GROUP_OF_TCAM_SIZE 256

// Total 3.5K IPv4 equivalent ( no tiles allocated )

// TODO jafinger - I do not know what size these tables ought to be,
// but if they are 0, then the open source P4 compiler gives an error
// message when trying to define a register array with size 0.  Make
// them some arbitrary non-0 size for now.

#define IPV4_MC_ROUTE_SG_HASH_TABLE_SIZE 4096
#define IPV6_MC_ROUTE_SG_HASH_TABLE_SIZE  2048
#define IPV4_MC_BRIDGE_SG_HASH_TABLE_SIZE 4096
#define IPV6_MC_BRIDGE_SG_HASH_TABLE_SIZE  2048
#define IPV4_MC_ROUTE_SG_OF_TCAM_SIZE 1536
#define IPV6_MC_ROUTE_SG_OF_TCAM_SIZE  256
#define IPV4_MC_BRIDGE_SG_OF_TCAM_SIZE 1536
#define IPV6_MC_BRIDGE_SG_OF_TCAM_SIZE  256

#endif /*DISABLE_MC_BRIDGE_LOOKUPS*/

#define IPV4_FTAG_OVERRIDE_TABLE_SIZE 16
#define IPV6_FTAG_OVERRIDE_TABLE_SIZE 16
#define FTAG_OIF_INFO_TABLE_SIZE 16

#define MET_TABLE_SIZE 65536
#define MC_RPF_HASH_TABLE_SIZE 10240
#define MC_RPF_OF_TCAM_SIZE     3548

#define NON_IP_MC_GROUP_HASH_TABLE_SIZE 2048 // TODO : subtract this from mac table size
#define NON_IP_MC_GROUP_OF_TCAM_SIZE    256

#define MCAST_SUP_FILTER_TABLE_SIZE 16384

// ~~~~~~~~  Stats ~~~~~~~
#define SRC_TEP_STATS_TABLE_SIZE             8192
#define DST_TEP_STATS_TABLE_SIZE             8192

#define SRC_PORT_STATS_TABLE_SIZE            2048
#define DST_PORT_STATS_TABLE_SIZE            2048

#define SRC_PORT_CLASS_STATS_TABLE_SIZE      2048
#define DST_PORT_CLASS_STATS_TABLE_SIZE      2048

#define RX_FLOW_STATS_TABLE_SIZE             1024

#define BD_STATS_TABLE_SIZE                  4096 

// ~~~~~~~~  ACLs ~~~~~~~~ 
#define COPP_METER_TABLE_SIZE          256
#define STORM_CONTROL_METER_TABLE_SIZE 256
#define STORM_CONTROL_TABLE_SIZE       256

#define INGRESS_PACL_ACTION_TABLE_SIZE 256
#define INGRESS_VACL_ACTION_TABLE_SIZE 256
#define INGRESS_RACL_ACTION_TABLE_SIZE 256
#define INGRESS_OUTPUT_ACL_ACTION_TABLE_SIZE 256
#define INGRESS_FSTAT0_ACTION_TABLE_SIZE 256
#define INGRESS_FSTAT1_ACTION_TABLE_SIZE 256
#define INGRESS_FSTAT2_ACTION_TABLE_SIZE 256
#define INGRESS_FSTAT3_ACTION_TABLE_SIZE 256

#define INGRESS_PACL_STATS_TABLE_SIZE 256
#define INGRESS_VACL_STATS_TABLE_SIZE 256
#define INGRESS_RACL_STATS_TABLE_SIZE 256
#define INGRESS_OUTPUT_ACL_STATS_TABLE_SIZE 256
#define INGRESS_FSTAT0_STATS_TABLE_SIZE 1024
#define INGRESS_FSTAT1_STATS_TABLE_SIZE 1024
#define INGRESS_FSTAT2_STATS_TABLE_SIZE 1024
#define INGRESS_FSTAT3_STATS_TABLE_SIZE 1024

#define EGRESS_ACL_ACTION_TABLE_SIZE  256

#define INGRESS_MAC_PACL_TABLE_SIZE    256
#define INGRESS_IPV4_PACL_TABLE_SIZE   256
#define INGRESS_IPV6_PACL_TABLE_SIZE   256
#define INGRESS_MAC_VACL_TABLE_SIZE    256
#define INGRESS_IPV4_VACL_TABLE_SIZE   256
#define INGRESS_IPV6_VACL_TABLE_SIZE   256
#define INGRESS_MAC_RACL_TABLE_SIZE    256
#define INGRESS_IPV4_RACL_TABLE_SIZE   256
#define INGRESS_IPV6_RACL_TABLE_SIZE   256
#define INGRESS_MAC_OUTPUT_ACL_TABLE_SIZE    256
#define INGRESS_IPV4_OUTPUT_ACL_TABLE_SIZE   256
#define INGRESS_IPV6_OUTPUT_ACL_TABLE_SIZE   256
#define INGRESS_MAC_FSTAT0_TABLE_SIZE    256
#define INGRESS_IPV4_FSTAT0_TABLE_SIZE   256
#define INGRESS_IPV6_FSTAT0_TABLE_SIZE   256
#define INGRESS_MAC_FSTAT1_TABLE_SIZE    256
#define INGRESS_IPV4_FSTAT1_TABLE_SIZE   256
#define INGRESS_IPV6_FSTAT1_TABLE_SIZE   256
#define INGRESS_MAC_FSTAT2_TABLE_SIZE    256
#define INGRESS_IPV4_FSTAT2_TABLE_SIZE   256
#define INGRESS_IPV6_FSTAT2_TABLE_SIZE   256
#define INGRESS_MAC_FSTAT3_TABLE_SIZE    256
#define INGRESS_IPV4_FSTAT3_TABLE_SIZE   256
#define INGRESS_IPV6_FSTAT3_TABLE_SIZE   256

#define INGRESS_ACL_REDIRECT_TABLE_SIZE 4096
#define INGRESS_ACL_REDIRECT_L3_TABLE_SIZE 4096
#define INGRESS_ACL_REDIRECT_L2_TABLE_SIZE 2048


#define INGRESS_MAC_SUP_TABLE_SIZE    256
#define INGRESS_IPV4_SUP_TABLE_SIZE   256
#define INGRESS_IPV6_SUP_TABLE_SIZE   256

#define INGRESS_SUP_ACTION_TABLE_SIZE 256

#define INGRESS_MAC_COPP_TABLE_SIZE  256
#define INGRESS_IPV4_COPP_TABLE_SIZE  256
#define INGRESS_IPV6_COPP_TABLE_SIZE  256
#define INGRESS_COPP_METER_SIZE  256

#define INGRESS_SRC_MAC_COMPRESSION_HASH_TABLE_SIZE 4096
#define INGRESS_SRC_MAC_COMPRESSION_OF_TCAM_SIZE     512
#define INGRESS_DST_MAC_COMPRESSION_HASH_TABLE_SIZE 4096
#define INGRESS_DST_MAC_COMPRESSION_OF_TCAM_SIZE     512

//#define EGRESS_PACL_ACTION_TABLE_SIZE 256
#define EGRESS_VACL_ACTION_TABLE_SIZE 256
#define EGRESS_RACL_ACTION_TABLE_SIZE 256

//#define EGRESS_PACL_STATS_TABLE_SIZE 256
#define EGRESS_VACL_STATS_TABLE_SIZE 256
#define EGRESS_COPP_STATS_TABLE_SIZE 256
#define EGRESS_QOS_STATS_TABLE_SIZE 256

#define EGRESS_ACL_ACTION_TABLE_SIZE  256

//#define EGRESS_MAC_PACL_TABLE_SIZE    256
//#define EGRESS_IPV4_PACL_TABLE_SIZE   256
//#define EGRESS_IPV6_PACL_TABLE_SIZE   256
#define EGRESS_MAC_VACL_TABLE_SIZE    256
#define EGRESS_IPV4_VACL_TABLE_SIZE   256
#define EGRESS_IPV6_VACL_TABLE_SIZE   256
#define EGRESS_MAC_COPP_TABLE_SIZE    256
#define EGRESS_IPV4_COPP_TABLE_SIZE   256
#define EGRESS_IPV6_COPP_TABLE_SIZE   256

// SPAN
#define INGRESS_MAC_RX_SPAN_TABLE_SIZE     64
#define INGRESS_IPV4_RX_SPAN_TABLE_SIZE   128
#define INGRESS_IPV6_RX_SPAN_TABLE_SIZE    64
#define ERSPAN_TERM_TABLE_SIZE 16
#define SPAN_SESSION_TABLE_SIZE 32

// QoS TCAM
#define INGRESS_MAC_QOS_TABLE_SIZE     64
#define INGRESS_IPV4_QOS_TABLE_SIZE   128
#define INGRESS_IPV6_QOS_TABLE_SIZE    64
#define EGRESS_MAC_QOS_TABLE_SIZE    256
#define EGRESS_IPV4_QOS_TABLE_SIZE   256
#define EGRESS_IPV6_QOS_TABLE_SIZE   256

#define QOS_METER_TABLE_SIZE          256
#define QOS_IDX_CALC_TABLE_SIZE      2048
#define INGRESS_QOS_INFO_TABLE_SIZE  2048
#define EGRESS_QOS_INFO_TABLE_SIZE   2048

// ~~~~~~~~  Host Tables ~~~~~~~~
// 32k hosts - ipv4, ipv6 and mac
// 32k ipv4 and 32k ipv6 routes + 8K adjacency

#ifdef MERGE_HRT_AND_LPM

#ifdef SINGLE_LOOKUP_MODE
#define IPV4_LPM_SIZE                    40960 //
#define IPV6_LPM_SIZE                    40960 //
#else 
#define IPV4_LPM_SIZE                    65536 // 32k local + 32k remote
#define IPV6_LPM_SIZE                    65536 // 32k local + 32k remote
#endif /*SINGLE_LOOKUP_MODE*/

#else
// Total 16K IPv4 equivalent
#define IPV4_FIB_TCAM_SIZE                8192
#define IPV6_FIB_TCAM_SIZE                2048

// Total 80K IPv4 equivalent
#define IPV4_LPM_SIZE                    40960
#define IPV6_LPM_SIZE                    10240
#define IPV6_LL_LPM_SIZE                 10240

#define IPV4_HRT_SIZE                    24510
#define IPV6_HRT_SIZE                    16384
#define IPV6_LL_HRT_SIZE                  8192

// 16K IPv4 equivalent. v6 = 4 times v4
#define IPV4_OF_TCAM_SIZE                8192
#define IPV6_OF_TCAM_SIZE                1024
#define IPV6_LL_OF_TCAM_SIZE             1024

#endif /*MERGE_HRT_AND_LPM*/

#ifdef SINGLE_LOOKUP_MODE
#define MAC_HASH_TABLE_SIZE              20480 
#define ADJACENCY_TABLE_SiZE             25536
#else 
#define MAC_HASH_TABLE_SIZE              32768 
#define ADJACENCY_TABLE_SiZE             40960 // 32K shared with MAC + 8K L2 adjacencies
#endif /*SINGLE_LOOKUP_MODE*/

#define MAC_OF_TCAM_SIZE                  4096

#define LFIB_HASH_TABLE_SIZE  MIN_SRAM_TABLE_SIZE
#define LFIB_TCAM_TABLE_SIZE  MIN_TCAM_TABLE_SIZE


// ~~~~~~~~  ACI Policy Table ~~~~~~~~ 
#define SGT_TO_SCLASS_XLATE_HASH_TBL_SIZE 2048
#define SGT_TO_SCLASS_XLATE_OF_TCAM_SIZE   256

#define SCLASS_TO_SGT_XLATE_HASH_TBL_SIZE 2048
#define SCLASS_TO_SGT_XLATE_OF_TCAM_SIZE   256

#define PT_HASH_TABLE_SIZE 81920 // 40 tiles of 2k each
#define PT_INFO_TABLE_SIZE 81920 // 80K
#define PT_TCAM_SIZE 8192

#define SERVICE_MP_CFG_TABLE_SIZE 4096
#define SERVICE_MP_MBR_TABLE_SIZE 8192

#define SERVICE_RW_TABLE_SIZE 16384
/*
IPv6 Host (/128) Entries    24K
/29 TRIE for IPv4 Host/Mcast GIPI    32K
IPv4 and IPv6 LPM Table    80K

Trie Pointer    96K
ECMP Group    24K
ECMP Member    32K
IP Mcast Result (L2 Tile for Mcast Info)    16K
MAC DA Hash Lookup    32K
L3 Unicast Result (L2 Tile for Adjacency)    8K
L3 iFabric Info - Multicast/Unicast    112K
RPF    10K
L2 iFabric Info    64K
L3 iFabric Info Ext - Unicast    0
L2 iFabric Info Ext    0
Policy Key    80K
Policy Info    80K
Policy Extension Tile    80K
*/
#endif
