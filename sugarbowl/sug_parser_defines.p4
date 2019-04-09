// Include files
#include "includes/sug_p4features.h"
#include "includes/sug_defines.p4"
//#include "includes/sug_metadata.p4"
//#include "sug_drop_reasons.h"
//#include "sug_sizes.p4"
//#include "includes/sug_intrinsic.p4"

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
#define ETHERTYPE_IETH         0xABCD

#define ETHERTYPE_QTAG_WITH_MSB_SET         0x18100
#define ETHERTYPE_CMD_WITH_MSB_SET          0x18850

// ARP Code
#define ARP_CODE_ARP_REQ  1
#define ARP_CODE_ARP_RES  2
#define ARP_CODE_RARP_REQ 3
#define ARP_CODE_RARP_RES 4

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
#define UDP_PORT_IVXLAN                0xBEEF


#define GRE_PROTOCOLS_NVGRE            0x20006558
#define GRE_PROTOCOLS_ERSPAN2          0x88BE 
#define GRE_PROTOCOLS_ERSPAN3          0x22EB 

#define ARP_PROTOTYPES_ARP_RARP_IPV4 0x0800
