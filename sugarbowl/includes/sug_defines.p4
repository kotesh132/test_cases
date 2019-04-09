#ifndef ST_DEFINES_H
#define ST_DEFINES_H

#include "sug_sizes.p4"

/* Boolean */
#define FALSE                                  0
#define TRUE                                   1

//-----------------------------------------------------------------------------
/* port type */
//-----------------------------------------------------------------------------

#define PORT_TYPE_NORMAL                       0
#define PORT_TYPE_IETH                         1
#define PORT_TYPE_FC                           2
#define PORT_TYPE_DCE                          3

#define LCPU_PORT 64
#define FT_PORT   65

//-----------------------------------------------------------------------------
// Packet Types
//-----------------------------------------------------------------------------

#define L2_UNKNOWN                             0
#define L2_UNICAST                             1
#define L2_MULTICAST                           2
#define L2_BROADCAST                           3

#define IP_UNICAST                             0
#define IP_MULTICAST                           1
#define IP_UNICAST_LL                          2
#define IP_MULTICAST_LL                        3

#define L3TYPE_NONE                            0
#define L3TYPE_IPV4                            1
#define L3TYPE_IPV6                            2
#define L3TYPE_FCOE                            3
#define L3TYPE_ARP                             4
#define L3TYPE_RARP                            5
#define L3TYPE_MPLS                            6

#define L4TYPE_TCP        0
#define L4TYPE_UDP        1
#define L4TYPE_IVXLAN     2
#define L4TYPE_VXLAN      3
#define L4TYPE_NVGRE      4
#define L4TYPE_VXLANG     5
#define L4TYPE_ERSPAN2    6
#define L4TYPE_ERSPAN3    7
#define L4TYPE_ND         8
#define L4TYPE_GRE        9
#define L4TYPE_IP         10
#define L4TYPE_L4OTH      11
#define L4TYPE_IVXLANG    12
#define L4TYPE_GENEVE_L2  13
#define L4TYPE_GENEVE_IP  14
#define L4TYPE_ICMPV6     15

#define ARP_NONE 0
#define ARP_REQ 1
#define ARP_RES 2
#define RARP_REQ 3
#define RARP_RES 4
// Gratuitous ARP
#define GARP 5

#define ND_NONE 0
#define ND_SOL 1
#define ND_ADV 2
#define ND_GNA 3

#define TCP_FLAG_FIN_POS 0
#define TCP_FLAG_SYN_POS 1
#define TCP_FLAG_RST_POS 2
#define TCP_FLAG_PUSH_POS 3
#define TCP_FLAG_ACK_POS 4
#define TCP_FLAG_URG_POS 5
#define TCP_FLAG_ECN_POS 6
#define TCP_FLAG_CWR_POS 7


//-----------------------------------------------------------------------------
// Sizes
//-----------------------------------------------------------------------------

#define LOCAL_PORT_WIDTH     6
#define GLOBAL_PORT_WIDTH   11
#define IFINDEX_BIT_WIDTH   13
#define EPG_WIDTH           14
#define BD_WIDTH            14
#define VRF_WIDTH           14
#define L3_ECMP_BIT_WIDTH    8
#define TUNNEL_ECMP_BIT_WIDTH    8

//-----------------------------------------------------------------------------
// Forwarding modes
//-----------------------------------------------------------------------------

#define FWD_MODE_DROP         0

#define L2_FWD_MODE_UC           0
#define L2_FWD_MODE_MC           1
#define L2_FWD_MODE_BC           2
#define L2_FWD_MODE_FLOOD        3

#define L3_FWD_MODE_BRIDGE       0
#define L3_FWD_MODE_ROUTE        1
#define L3_FWD_MODE_MPLS         2
#define L3_FWD_MODE_FCF          3

#define DP_OPCODE_UCMC_DROP 0
#define DP_OPCODE_UCMC_UC   1
#define DP_OPCODE_UCMC_L2MC 2
#define DP_OPCODE_UCMC_L3MC 3

#define IETH_OPCODE_UC_BRIDGE         0
#define IETH_OPCODE_UC_ROUTE          1
#define IETH_OPCODE_UC_MPLS           7
#define IETH_OPCODE_UC_FCF            8
#define IETH_OPCODE_PRE_ROUTE_FLOOD   2
#define IETH_OPCODE_POST_ROUTE_FLOOD  3
#define IETH_OPCODE_BC                4
#define IETH_OPCODE_L2MC              5
#define IETH_OPCODE_L3MC              6

//-----------------------------------------------------------------------------
// Rewrite modes
//-----------------------------------------------------------------------------

#define RW_MODE_NORMAL     0
#define RW_MODE_CPU        1
#define RW_MODE_SPAN       2
#define RW_MODE_SERV_COPY  3
#define RW_MODE_SERV_REDIR 4

#define CMD_RW_MODE_NOP     0
#define CMD_RW_MODE_REMOVE  1
#define CMD_RW_MODE_INSERT  2


//-----------------------------------------------------------------------------
/* TUNNEL types */
//-----------------------------------------------------------------------------

#define L3_ENCAP_TYPE_NONE 0
#define L3_ENCAP_TYPE_IP   1
#define L3_ENCAP_TYPE_MPLS 3
#define L3_ENCAP_TYPE_DCE  4

#define ENCAP_TYPE_NONE               0
#define ENCAP_TYPE_VXLAN              1
#define ENCAP_TYPE_GRE                2
#define ENCAP_TYPE_IP_IN_IP           3
#define ENCAP_TYPE_GENEVE             4
#define ENCAP_TYPE_NVGRE              5
#define ENCAP_TYPE_MPLS_L2VPN         6
#define ENCAP_TYPE_MPLS_L3VPN         7
#define ENCAP_TYPE_VXLAN_GPE          8
#define ENCAP_TYPE_MPLS_OVER_GRE      9
#define ENCAP_TYPE_VPLS_OVER_GRE      10
#define ENCAP_TYPE_DCE                11
#define ENCAP_TYPE_ERSPAN2            12
#define ENCAP_TYPE_ERSPAN3            13
#define ENCAP_TYPE_IVXLAN             14

#define  IDS_01_IPV4_CSUM_ERR          0
#define  IDS_06_IP_VER                 1
#define  IDS_02_IPV4_HL_MIN            2 
#define  IP_5_V4_TOTAL_LENGTH_MIN      3
#define  IDS_04_FRAG_LEN_MAX           4
#define  IDS_05_UNEXP_FRAG             5
#define  IDS_07_PROT_MAX               6
#define  IDS_15_SA_LOOPBACK            7
#define  IDS_15_DA_LOOPBACK            8
#define  IDS_16_SA_DA_SAME             9
#define  IDS_14_SA_BCAST              10
#define  IDS_17_DA_ZERO               11
#define  IDS_18_SA_CLASS_D            12
#define  IDS_19_SA_CLASS_E            13
#define  IDS_19_DA_CLASS_E            14
#define  IDS_21_1ST_TCP_TINY_FRAG     15
#define  IDS_21_2ND_TCP_TINY_FRAG     16
#define  IDS_22_1ST_UDP_TINY_FRAG     17
#define  IDS_22_2ND_UDP_TINY_FRAG     18
#define  IDS_23_1ST_SCTP_TINY_FRAG    19
#define  IDS_23_2ND_SCTP_TINY_FRAG    20
#define  IDS_08_UDP_LENGTH_MAX        21

//-----------------------------------------------------------------------------
// VLAN modes 
//-----------------------------------------------------------------------------
#define VLAN_MODE_ACCESS   0
#define VLAN_MODE_TRUNK    1
#define VLAN_MODE_QINQ     2

//-----------------------------------------------------------------------------
// Unicast RPF Mode
//-----------------------------------------------------------------------------
#define uRPF_MODE_DISABLE             0
#define uRPF_MODE_STRICT              1
#define uRPF_MODE_LOOSE               2
#define uRPF_MODE_LOOSE_ALLOW_DEFAULT 3

//-----------------------------------------------------------------------------
// FIB Lookup modes
//-----------------------------------------------------------------------------

#define FIB_LKUP_TYPE_UC_IPV4        0 // {vrf, ipv4_da }
#define FIB_LKUP_TYPE_UC_IPV6        1 // {vrf, ipv6_da }
#define FIB_LKUP_TYPE_UC_IPV6_LL     2 // {bd, ipv6_da }
#define FIB_LKUP_TYPE_MC_IPV4        4 // {vrf, G}
#define FIB_LKUP_TYPE_MC_IPV6        5 // {VRF, G}
#define FIB_LKUP_TYPE_MC_IPV6_LL     6 // {BD,  G}

//-----------------------------------------------------------------------------
// ACL
//-----------------------------------------------------------------------------

#define MAC_ACL_KEY 0
#define IPV4_ACL_KEY 1
#define IPV6_ACL_KEY 2

#define ACL_REDIRECT_TYPE_L3_ECMP 0
#define ACL_REDIRECT_TYPE_L3_ADJ  1
#define ACL_REDIRECT_TYPE_L2      2
#define ACL_REDIRECT_TYPE_MC      3

#define PT_LOG_SUP_CODE 31
#define PT_LOG_SUP_QNUM 7
#define PT_LOG_SUP_DST  1

//-----------------------------------------------------------------------------
// Adjacency Type
//-----------------------------------------------------------------------------


#define ADJ_TYPE_L2_RW             0
#define ADJ_TYPE_IP_TUNNEL_ENCAP   1
#define ADJ_TYPE_IP_TUNNEL_DECAP   2
#define ADJ_TYPE_MPLS              3

//-----------------------------------------------------------------------------
// Misc
//-----------------------------------------------------------------------------

#define FLOWLET_INTERVAL 100000

#define TTL_MODE_UNIFORM 0
#define TTL_MODE_PIPE 1

#define MPLS_INITIAL_TTL 64

#define OCLASS_SPAN 9
#define OCLASS_CPU  8

#define PT_FRAG_SIZE0 1500
#define PT_FRAG_SIZE1 9000

#define CFG_IETH_QOS_MAP_GRP 1544
#define CFG_IETH_QOS_MAP_USE_DSCP 0
#define CFG_IETH_QOS_MAP_USE_TC 1

#define CFG_VPC_BOUNCE_DST_IF_IDX   0xABC
#define CFG_VPC_BOUNCE_ENCAP_VLD    1
#define CFG_VPC_BOUNCE_ENCAP_IDX    0xDEF
#define CFG_VPC_BOUNCE_ENCAP_L2_IDX 0xAAA
#define CFG_VPC_BOUNCE_OUTER_DST_BD 0xDDD

//-----------------------------------------------------------------------------
// ERSPAN
//-----------------------------------------------------------------------------

#define CFG_ERSPAN2_VER         1
#define CFG_ERSPAN3_VER         2
#define CFG_ERSPAN3_P           0
#define CFG_ERSPAN3_FT          0x1F
#define CFG_ERSPAN3_HWID        0x3F
#define CFG_ERSPAN3_OPT         1
#define CFG_ERSPAN3_PLATFID     0x3F

//-----------------------------------------------------------------------------
// NAT types
//-----------------------------------------------------------------------------

#define NAT_TYPE_DST 0
#define NAT_TYPE_SRC 1

//-----------------------------------------------------------------------------
// Egress Bypass Codes
//-----------------------------------------------------------------------------
#define EGRESS_BYPASS_CODE_ERSPAN_TERM      7
#define EGRESS_BYPASS_CODE_SPAN             1
#define EGRESS_BYPASS_CODE_UC_MY_CHIP       2
#define EGRESS_BYPASS_CODE_UC_TRANSIT       3
#define EGRESS_BYPASS_CODE_L2MC_TRANSIT     4
#define EGRESS_BYPASS_CODE_L3MC_TRANSIT     5
#define EGRESS_BYPASS_CODE_SUP_RX_LOCAL     7
#define EGRESS_BYPASS_CODE_SUP_RX_REMOTE    8
#define EGRESS_BYPASS_CODE_SERVICE          9
#define EGRESS_BYPASS_CODE_FEX_TO_HIF      10
#define EGRESS_BYPASS_CODE_FEX_TO_NIF      11
#define EGRESS_BYPASS_CODE_COPY_SERVICE    12

#define ETHERTYPE_CMD          0x8850
#define ETHERTYPE_VNTAG        0x8926

#endif
