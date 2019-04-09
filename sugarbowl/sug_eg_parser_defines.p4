// Include files
#include "includes/sug_p4features.h"
#include "includes/sug_defines.p4"
//#include "includes/sug_metadata.p4"
//#include "sug_drop_reasons.h"
//#include "includes/sug_pkt_headers.p4"
//#include "sug_sizes.p4"
//#include "includes/sug_intrinsic.p4"
//#include "sug_eg_headers.p4"

/* port type */
#define PORT_TYPE_NORMAL                       0
#define PORT_TYPE_IETH                         1
#define PORT_TYPE_FC                           2
#define PORT_TYPE_DCE                          3

/* Ethertypes */
#define ETHERTYPE_QTAG         0x8100
#define ETHERTYPE_STAG         0x88A8
#define ETHERTYPE_MPLS         0x8847
#define ETHERTYPE_IPV4         0x0800
#define ETHERTYPE_IPV6         0x86dd
#define ETHERTYPE_ARP          0x0806
#define ETHERTYPE_RARP         0x8035
#define ETHERTYPE_NSH          0x894f
#define ETHERTYPE_ETHERNET     0x6558
#define ETHERTYPE_FCOE         0x8906
#define ETHERTYPE_VNTAG        0x8926
#define ETHERTYPE_DCE          0x8903
#define ETHERTYPE_TIMESTAMP    0x8988
#define ETHERTYPE_MPLS_UPSTR   0x8848
#define ETHERTYPE_CMD          0x8850

#define ETHERTYPE_QTAG_WITH_MSB_SET         0x18100
#define ETHERTYPE_CMD_WITH_MSB_SET          0x18850

/* Multicast MAC */
#define IPV4_MULTICAST_MAC 0x01005E
#define IPV6_MULTICAST_MAC 0x3333

#define IP_PROTOCOLS_ICMP              1
#define IP_PROTOCOLS_IGMP              2
#define IP_PROTOCOLS_IPV4              4
#define IP_PROTOCOLS_TCP               6
#define IP_PROTOCOLS_UDP               17
#define IP_PROTOCOLS_IPV6              41
#define IP_PROTOCOLS_GRE               47
#define IP_PROTOCOLS_ICMPV6            58

#define IP_PROTOCOLS_IPHL_ICMP         0x501
#define IP_PROTOCOLS_IPHL_IPV4         0x504
#define IP_PROTOCOLS_IPHL_TCP          0x506
#define IP_PROTOCOLS_IPHL_UDP          0x511
#define IP_PROTOCOLS_IPHL_IPV6         0x529
#define IP_PROTOCOLS_IPHL_GRE          0x52f

#define UDP_PORT_LISP                  4341
#define UDP_PORT_VXLAN                 4789
#define UDP_PORT_VXLAN_GPE             4790
#define UDP_PORT_GENEVE                6081


#define GRE_PROTOCOLS_NVGRE            0x20006558
#define GRE_PROTOCOLS_ERSPAN2          0x88BE 
#define GRE_PROTOCOLS_ERSPAN3          0x22EB 

#define ARP_PROTOTYPES_ARP_RARP_IPV4 0x0800


//---------------------------------------------
// IPv4
//---------------------------------------------

#define IPV4_PROTOCOL_ICMP 0x45000001
#define IPV4_PROTOCOL_IP   0x45000004
#define IPV4_PROTOCOL_TCP  0x45000006
#define IPV4_PROTOCOL_UDP  0x45000011	/* protocol = 17 */
#define IPV4_PROTOCOL_IPV6 0x45000029	/* protocol = 41 */
#define IPV4_PROTOCOL_GRE  0x4500002f	/* protocol = 47 */
#define IPV4_PROTOCOL_AUTH 0x45000033	/* protocol = 51 */
#define IPV4_OPT01_ICMP    0x46000001 /* ihl = 6 */
#define IPV4_OPT01_TCP     0x46000006
#define IPV4_OPT01_UDP     0x46000011
#define IPV4_OPT02_ICMP    0x47000001 /* ihl = 7 */
#define IPV4_OPT02_TCP     0x47000006
#define IPV4_OPT02_UDP     0x47000011
#define IPV4_OPT03_ICMP    0x48000001 /* ihl = 8 */
#define IPV4_OPT03_TCP     0x48000006
#define IPV4_OPT03_UDP     0x48000011
// #define IPV4_OPT04_ICMP    0x49000001 /* ihl = 9 */
// #define IPV4_OPT04_TCP     0x49000006
// #define IPV4_OPT04_UDP     0x49000011
// #define IPV4_OPT05_ICMP    0x4a000001 /* ihl = 10 */
// #define IPV4_OPT05_TCP     0x4a000006
// #define IPV4_OPT05_UDP     0x4a000011
// #define IPV4_OPT06_ICMP    0x4b000001 /* ihl = 11 */
// #define IPV4_OPT06_TCP     0x4b000006
// #define IPV4_OPT06_UDP     0x4b000011
// #define IPV4_OPT07_ICMP    0x4c000001 /* ihl = 12 */
// #define IPV4_OPT07_TCP     0x4c000006
// #define IPV4_OPT07_UDP     0x4c000011
// #define IPV4_OPT08_ICMP    0x4d000001 /* ihl = 13 */
// #define IPV4_OPT08_TCP     0x4d000006
// #define IPV4_OPT08_UDP     0x4d000011
// #define IPV4_OPT09_ICMP    0x4e000001 /* ihl = 14 */
// #define IPV4_OPT09_TCP     0x4e000006
// #define IPV4_OPT09_UDP     0x4e000011
// #define IPV4_OPT10_ICMP    0x4f000001 /* ihl = 15 */
// #define IPV4_OPT10_TCP     0x4f000006
// #define IPV4_OPT10_UDP     0x4f000011

#define IPV4_NO_FRAG_MASK 0xff1fffff	/* mask out IP more, df and reserved flags. Match for first fragment but not the subsequent ones. */

//---------------------------------------------
// IPv6
//---------------------------------------------


#define IPV6_NEXT_HDR_TCP    0x06
#define IPV6_NEXT_HDR_UDP    0x11 	/* protocol 17 */
#define IPV6_NEXT_HDR_ICMPV6 0x3a 	/* protocol 58 */
#define IPV6_NEXT_HDR_GRE    0x2f 	/* protocol 47 */
#define IPV6_NEXT_HDR_IPV4   0x04
#define IPV6_NEXT_HDR_IPV6   0x29 	/* protocol 41 */
//#define IPV6_NEXT_HDR_ROUTE  0x2b 	/* protocol 43 */
#define IPV6_NEXT_HDR_FRAG   0x2c 	/* protocol 44 */
//#define IPV6_NEXT_HDR_AUTH   0x33 	/* protocol 51 */
//#define IPV6_NEXT_HDR_OPTS   0x3c	/* protocol 60 */
#define IPV6_NEXT_HDR_HBH    0x00


//---------------------------------------------
// IPv6 Hop-By-Hop
//---------------------------------------------

/* Code taken from Peter's Tahoe parser. There is probably a cleaner way */
#define IPV6_HBH_HEL0_NEXT_TCP         6
#define IPV6_HBH_HEL0_NEXT_UDP        17
#define IPV6_HBH_HEL0_NEXT_ICMPV6     58
#define IPV6_HBH_HEL0_NEXT_FRAG       44
#define IPV6_HBH_HEL1_NEXT_TCP    0x0106
#define IPV6_HBH_HEL1_NEXT_UDP    0x0111
#define IPV6_HBH_HEL1_NEXT_ICMPV6 0x013a
#define IPV6_HBH_HEL1_NEXT_FRAG   0x012c
#define IPV6_HBH_HEL2_NEXT_TCP    0x0206
#define IPV6_HBH_HEL2_NEXT_UDP    0x0211
#define IPV6_HBH_HEL2_NEXT_ICMPV6 0x023a
#define IPV6_HBH_HEL2_NEXT_FRAG   0x022c
#define IPV6_HBH_HEL3_NEXT_TCP    0x0306
#define IPV6_HBH_HEL3_NEXT_UDP    0x0311
#define IPV6_HBH_HEL3_NEXT_ICMPV6 0x033a
#define IPV6_HBH_HEL3_NEXT_FRAG   0x032c


//---------------------------------------------
// IPv6 Fragment
//---------------------------------------------

#define IPV6_OPT_MORE_FLAG_MASK 0x1fffff /* mask out IPv6 frag more flag */
#define IPV6_OPT_MORE_FRAG_MASK 0xff     /* mask out IPv6 frag more flag and fragOffset */

//---------------------------------------------
// Neighbor Discovery
//---------------------------------------------

#define ICMPV6_ND_SOLICITATION 135
#define ICMPV6_ND_ADVERTISEMENT 136

//---------------------------------------------
// GPE
//---------------------------------------------

#define GPE_NEXT_PROTO_IPV4     0x101
#define GPE_NEXT_PROTO_IPV6     0x102
#define GPE_NEXT_PROTO_ETHETNET 0x103
#define GPE_NEXT_PROTO_NSH      0x104
#define GPE_NEXT_PROTO_MPLS     0x105

//---------------------------------------------
// NSH
//---------------------------------------------

#define NSH_NEXT_PROTO_IPV4     0x01
#define NSH_NEXT_PROTO_IPV6     0x02
#define NSH_NEXT_PROTO_ETHERNET 0x03

//---------------------------------------------
// Inner VLAN
//---------------------------------------------

#ifdef SUPPORT_INNER_QINQ  
  #define INNER_VLAN_DEPTH 2
#else
  #define INNER_VLAN_DEPTH 1
#endif /*SUPPORT_INNER_QINQ*/


//---------------------------------------------
/* parse error status definitions */
//---------------------------------------------

#define ERR_ETHERTYPE_ZERO 1
#define ERR_UNSUPPORTED_CMD 2
#define ERR_FCOE_NO_QTAG 3
#define ERR_FCOE_VERSION 4
#define ERR_FC_EXT_HDR 5
#define ERR_IPV4_IHL_ERR 6
#define ERR_IPV4_VERSION_ERR 7
#define ERR_IPV6_VERSION_ERR 8

