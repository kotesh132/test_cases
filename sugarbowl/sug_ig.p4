
#ifndef DISABLE_MPLS

/*****************************************************************************/
/* Identify topmost non-null label                                           */
/*****************************************************************************/

control process_mpls_top_label(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action no_special_label_on_top() {
        meta.mplsm.topmost_non_null_label_val = hdr.mpls[0].label;
        meta.mplsm.topmost_non_null_label_ttl = hdr.mpls[0].ttl;
        meta.mplsm.topmost_non_null_label_exp = hdr.mpls[0].exp;
        meta.mplsm.entropy_label_vld = FALSE;
        meta.mplsm.entropy_label_val = 0;
        meta.mplsm.outermost_ttl = hdr.mpls[0].ttl;
    }

    action null_plus_el_on_top() {
        meta.mplsm.topmost_non_null_label_val = hdr.mpls[3].label;
        meta.mplsm.topmost_non_null_label_ttl = hdr.mpls[3].ttl;
        meta.mplsm.topmost_non_null_label_exp = hdr.mpls[3].exp;
        meta.mplsm.entropy_label_vld = TRUE;
        meta.mplsm.entropy_label_val = hdr.mpls[2].label;
        meta.mplsm.outermost_ttl = hdr.mpls[3].ttl;
    }

    action el_on_top() {
        meta.mplsm.topmost_non_null_label_val = hdr.mpls[2].label;
        meta.mplsm.topmost_non_null_label_ttl = hdr.mpls[2].ttl;
        meta.mplsm.topmost_non_null_label_exp = hdr.mpls[2].exp;
        meta.mplsm.entropy_label_vld = TRUE;
        meta.mplsm.entropy_label_val = hdr.mpls[1].label;
        meta.mplsm.outermost_ttl = hdr.mpls[2].ttl;
    }
    
    action null_on_top() {
        meta.mplsm.topmost_non_null_label_val = hdr.mpls[1].label;
        meta.mplsm.topmost_non_null_label_ttl = hdr.mpls[1].ttl;
        meta.mplsm.topmost_non_null_label_exp = hdr.mpls[1].exp;
        meta.mplsm.entropy_label_vld = FALSE;
        meta.mplsm.entropy_label_val = 0;
        meta.mplsm.outermost_ttl = hdr.mpls[1].ttl;
    }
    
    action null_only_on_top() {
        //l3_metadata.l3_type = L3_TYPE_IP; // TODO
        meta.mplsm.entropy_label_vld = FALSE;
        meta.mplsm.entropy_label_val = 0;
        meta.mplsm.outermost_ttl = hdr.mpls[0].ttl; //??????
    }
    
    apply {
        if (hdr.mpls[0].isValid() &&
            ((hdr.mpls[0].label == 0) || (hdr.mpls[0].label == 2)))
        {
            // Topmost is Null
            if (hdr.mpls[1].isValid()) {
                if (hdr.mpls[1].label == 7) {
                    // 2nd is EL
                    if (hdr.mpls[2].isValid() && hdr.mpls[3].isValid()) {
                        // Null + ELI + EL + some other label
                        null_plus_el_on_top();
                    } else {
                        // Error : ELI or fwd label missing
                    }
                } else {
                    // Null + some other label
                    null_on_top();
                }
            } else {
                null_only_on_top(); // TODO : 
                // Null +IP
            }
        } else if (hdr.mpls[1].isValid() && (hdr.mpls[0].label == 7)) {
            // Topmost is ELI
            if (hdr.mpls[2].isValid() && hdr.mpls[3].isValid()) {
                // ELI + EL + some other label
                el_on_top();
            } else {
                // Error : ELI or fwd label missing
            }
        } else {
            no_special_label_on_top();
        }
    }
}


/*****************************************************************************/
/* MPLS L2/L3VPN label lookup                                                */
/*****************************************************************************/

control process_mpls_vpn_label(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    
    action mpls_l2vpn_label_hit(bit<13> src_ptr) {
        meta.mplsm.l2vpn_term = TRUE;
        meta.src_tep.src_ptr = src_ptr;
    }

    action mpls_l3vpn_label_hit(bit<13> tunnel_id) {
        meta.ig_tunnel.l3_tunnel_decap = TRUE;
        meta.mplsm.l3vpn_term = TRUE;
        meta.mplsm.l3vpn_term_tunnel_id = tunnel_id;
    }

    table mpls_vpn_label_hash_table {
        key = {
            meta.outer_src_bd.vrf                : exact;
            meta.mplsm.topmost_non_null_label_val : exact;
        }
        actions = {
            mpls_l2vpn_label_hit;
            mpls_l3vpn_label_hit;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = MPLS_VPN_LABEL_HASH_TABLE_SIZE;
    }

    apply {
        mpls_vpn_label_hash_table.apply();
    }
}

#endif /*DISABLE_MPLS*/


control process_decode_outer_l2_da(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
	// Ethernet DA
        // all 1s is broadcast dest MAC
        // bit 40 is 1 for multicst
	if (hdr.ethernet.dstAddr == 0xFFFFFFFFFFFF) {
	    meta.l2.l2_da_type = L2_BROADCAST;
	} else if ((hdr.ethernet.dstAddr & 0x010000000000) == 0) {
            meta.l2.l2_da_type = L2_UNICAST;
        } else {
            meta.l2.l2_da_type = L2_MULTICAST;
        }
    }
}

control process_decode_outer_ip_da(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv4.isValid()) {
            // TBD: Why is bit 23 of the MAC DA special?
            // TBD: Why is meta.l2.lkp_mac_da used here, but
            // hdr.ethernet.dstAddr is used in
            // process_decode_outer_l2_da?
            if ((hdr.ipv4.dstAddr[31:28] == 0xE) &&
                (meta.l2.lkp_mac_da[47:24] == 0x01005E) &&
                (meta.l2.lkp_mac_da[23:23] == 0))
            {
                if (hdr.ipv4.dstAddr[31:24] == 0xE0) {
                    meta.l3.ip_da_type = IP_MULTICAST_LL;
                } else {
                    meta.l3.ip_da_type = IP_MULTICAST;
                }
            } else {
                meta.l3.ip_da_type = IP_UNICAST;
            }
        } else if (hdr.ipv6.isValid()) {
            if (hdr.ipv6.dstAddr[127:120] == 0xFF) {
                meta.l3.ip_da_type = IP_MULTICAST;
            } else {
                // TBD: The next line has to be a bug, since the
                // condition is always false.  Maybe it was meant to
                // be written ((x & 0xFFC) == 0xFE8) ?  Check against
                // original Sugarbowl code.
                if ((hdr.ipv6.dstAddr[127:116] & 0xFE8) == 0xFFC) {
                    meta.l3.ip_da_type = IP_UNICAST_LL;
                } else {
                    meta.l3.ip_da_type = IP_UNICAST;
                }
            }
        }
    }
}

control process_decode_outer_ip_sa(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.srcAddr[31:28] == 0xE) {
                meta.l3.ip_sa_type = IP_MULTICAST;
            } else {
                meta.l3.ip_sa_type = IP_UNICAST;
            }
        } else if (hdr.ipv6.isValid()) {
            if (hdr.ipv6.srcAddr[127:120] == 0xFF) {
                meta.l3.ip_sa_type = IP_MULTICAST;
            } else {
                // TBD: Same comment as similar condition in
                // process_decode_outer_ip_da.
                if ((hdr.ipv6.srcAddr[127:116] & 0xFE8) == 0xFFC) {
                    meta.l3.ip_sa_type = IP_UNICAST_LL;
                } else {
                    meta.l3.ip_sa_type = IP_UNICAST;
                }
            }
        }
        if (hdr.ipv6.srcAddr == 0) {
            meta.ipv6m.ipv6_sa_eq0 = 1;
        }
    }
}

control process_decode_outer_arp_rarp(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.l3.l3_type == L3TYPE_ARP) {
            if (hdr.arp_rarp.opcode == ARP_CODE_ARP_REQ) {
                meta.l3.arp_type = ARP_REQ;
            } else if (hdr.arp_rarp.opcode == ARP_CODE_ARP_RES) {
                meta.l3.arp_type = ARP_RES;
            }
            if (hdr.arp_rarp.srcProtoAddr == hdr.arp_rarp.dstProtoAddr) {
                meta.l3.arp_type = GARP;
            }
        } else if (meta.l3.l3_type == L3TYPE_RARP) {
            if (hdr.arp_rarp.opcode == ARP_CODE_RARP_REQ) {
                meta.l3.arp_type = RARP_REQ;
            } else if (hdr.arp_rarp.opcode == ARP_CODE_RARP_RES) {
                meta.l3.arp_type = RARP_RES;
            }
        }
    }
}

control process_decode_outer_nd(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.icmpv6.isValid()) {
            if (hdr.icmpv6.code == ICMPV6_ND_SOLICITATION) {
                meta.l3.nd_type = ND_SOL;
            } else if (hdr.icmpv6.code == ICMPV6_ND_ADVERTISEMENT) {
                meta.l3.nd_type = ND_ADV;
            }
        }
        // TBD: Same comment as similar condition in
        // process_decode_outer_ip_da.
        if ((hdr.ipv6_nd.targetAddr[127:116] & 0xFE8) == 0xFFC) {
            meta.l3.nd_ta_ll = TRUE;
        } else {
            meta.l3.nd_ta_ll = FALSE;
        }
    }
}

control process_decode_outer_headers(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("process_decode_outer_l2_da") process_decode_outer_l2_da() process_decode_outer_l2_da_0;
    @name("process_decode_outer_ip_da") process_decode_outer_ip_da() process_decode_outer_ip_da_0;
    @name("process_decode_outer_ip_sa") process_decode_outer_ip_sa() process_decode_outer_ip_sa_0;
    @name("process_decode_outer_arp_rarp") process_decode_outer_arp_rarp() process_decode_outer_arp_rarp_0;
    @name("process_decode_outer_nd") process_decode_outer_nd() process_decode_outer_nd_0;
#ifndef DISABLE_MPLS
    @name("process_mpls_top_label") process_mpls_top_label() process_mpls_top_label_0;
#endif /*DISABLE_MPLS*/
    apply {
        process_decode_outer_l2_da_0.apply(hdr, meta, standard_metadata);
        if (hdr.ipv4.isValid() || hdr.ipv6.isValid()) {
            process_decode_outer_ip_da_0.apply(hdr, meta, standard_metadata);
            process_decode_outer_ip_sa_0.apply(hdr, meta, standard_metadata);
            // TBD: Comment from original P4_14 version:
            // Use a dummy table to set "is_ipfrag" flag
            if (hdr.ipv4.isValid() &&
                (hdr.ipv4.flag_more == 1 ||
                 hdr.ipv4.fragOffset != 0))
            {
                meta.l3.ipfrag = TRUE;
            }
            // TBD: Shouldn't we also check for IPv6 fragment
            // extension header and set similar flags if it is a
            // non-first fragment?
        } else {
            if (hdr.arp_rarp.isValid()) {
                process_decode_outer_arp_rarp_0.apply(hdr, meta, standard_metadata);
            } else if (hdr.icmpv6.isValid()) {
                process_decode_outer_nd_0.apply(hdr, meta, standard_metadata);
#ifndef DISABLE_MPLS
            } else if (hdr.mpls[0].isValid()) {
                process_mpls_top_label_0.apply(hdr, meta, standard_metadata);
#endif /*DISABLE_MPLS*/
            }
        }
    }
}

control process_decode_inner_l2_da(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
	// Ethernet DA
	if (hdr.inner_ethernet.dstAddr == 0xFFFFFFFFFFFF) {
	    meta.l2.inner_l2_da_type = L2_BROADCAST;
	} else if ((hdr.inner_ethernet.dstAddr & 0x010000000000) == 0) {
            meta.l2.inner_l2_da_type = L2_UNICAST;
        } else {
            meta.l2.inner_l2_da_type = L2_MULTICAST;
        }
    }
}

control process_decode_inner_ip_da(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.inner_ipv4.isValid()) {
            if ((hdr.inner_ipv4.dstAddr[31:28] == 0xE) &&
                (meta.l2.lkp_mac_da[47:24] == 0x01005E) &&
                (meta.l2.lkp_mac_da[23:23] == 0))
            {
                if (hdr.inner_ipv4.dstAddr[31:24] == 0xE0) {
                    meta.l3.inner_ip_da_type = IP_MULTICAST_LL;
                } else {
                    meta.l3.inner_ip_da_type = IP_MULTICAST;
                }
            } else {
                meta.l3.inner_ip_da_type = IP_UNICAST;
            }
        } else if (hdr.inner_ipv6.isValid()) {
            if (hdr.inner_ipv6.dstAddr[127:120] == 0xFF) {
                meta.l3.inner_ip_da_type = IP_MULTICAST;
            } else {
                // TBD: Same comment as similar condition in
                // process_decode_outer_ip_da.
                if ((hdr.inner_ipv6.dstAddr[127:116] & 0xFE8) == 0xFFC) {
                    meta.l3.inner_ip_da_type = IP_UNICAST_LL;
                } else {
                    meta.l3.inner_ip_da_type = IP_UNICAST;
                }
            }
        }
    }
}

control process_decode_inner_ip_sa(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.inner_ipv4.isValid()) {
            if (hdr.inner_ipv4.srcAddr[31:28] == 0xE) {
                meta.l3.inner_ip_sa_type = IP_MULTICAST;
            } else {
                meta.l3.inner_ip_sa_type = IP_UNICAST;
            }
        }  else if (hdr.inner_ipv6.isValid()) {
            if (hdr.inner_ipv6.srcAddr[127:120] == 0xFF) {
                meta.l3.inner_ip_sa_type = IP_MULTICAST;
            } else {
                // TBD: Same comment as similar condition in
                // process_decode_outer_ip_da.
                if ((hdr.inner_ipv6.srcAddr[127:116] & 0xFE8) == 0xFFC) {
                    meta.l3.inner_ip_sa_type = IP_UNICAST_LL;
                } else {
                    meta.l3.inner_ip_sa_type = IP_UNICAST;
                }
            }
        }
        if (hdr.inner_ipv6.srcAddr == 0) {
            // TBD: Assigned but never used.  Compiler should be
            // written to detect and give a warning about this.
            meta.ipv6m.inner_ipv6_sa_eq0 = 1;
        }
    }
}

// TBD: This control block is so similar to
// process_decode_outer_arp_rarp, it seems that is could be written as
// an action that takes either hdr.arp_rarp or hdr.inner_arp_rarp as
// an in parameter, and assigns a value to a single out parameter for
// the arp_type.  Then it could be called twice with different
// arguments.  The same is probably true for most of the
// process_outer/inner_{foo} pairs of control blocks.  That would not
// improve the functionality at all -- just less duplicated code.

control process_decode_inner_arp_rarp(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.l3.inner_l3_type == L3TYPE_ARP) {
            if (hdr.inner_arp_rarp.opcode == ARP_CODE_ARP_REQ) {
                meta.l3.inner_arp_type = ARP_REQ;
            } else if (hdr.inner_arp_rarp.opcode == ARP_CODE_ARP_RES) {
                meta.l3.inner_arp_type = ARP_RES;
            }
            // TBD: Should hdr.arp_rarp on following line be
            // hdr.inner_arp_rarp?
            if (hdr.inner_arp_rarp.srcProtoAddr == hdr.arp_rarp.dstProtoAddr) {
                meta.l3.inner_arp_type = GARP;
            }
        } else if (meta.l3.inner_l3_type == L3TYPE_RARP) {
            if (hdr.inner_arp_rarp.opcode == ARP_CODE_RARP_REQ) {
                meta.l3.inner_arp_type = RARP_REQ;
            } else if (hdr.inner_arp_rarp.opcode == ARP_CODE_RARP_RES) {
                meta.l3.inner_arp_type = RARP_RES;
            }
        }
    }
}

control process_decode_inner_nd(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.icmpv6.isValid()) {
            if (hdr.icmpv6.code == ICMPV6_ND_SOLICITATION) {
                meta.l3.inner_nd_type = ND_SOL;
            } else if (hdr.icmpv6.code == ICMPV6_ND_ADVERTISEMENT) {
                meta.l3.inner_nd_type = ND_ADV;
            }
        }
        // TBD: Same comment as similar condition in
        // process_decode_outer_ip_da.  This condition should probably
        // be defined in one action somewhere and called from each of
        // these places.
        if ((hdr.inner_ipv6_nd.targetAddr[127:116] & 0xFE8) == 0xFFC) {
            meta.l3.inner_nd_ta_ll = TRUE;
        } else {
            meta.l3.inner_nd_ta_ll = FALSE;
        }
    }
}

control process_decode_inner_headers(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("process_decode_inner_l2_da") process_decode_inner_l2_da() process_decode_inner_l2_da_0;
    @name("process_decode_inner_ip_da") process_decode_inner_ip_da() process_decode_inner_ip_da_0;
    @name("process_decode_inner_ip_sa") process_decode_inner_ip_sa() process_decode_inner_ip_sa_0;
    @name("process_decode_inner_arp_rarp") process_decode_inner_arp_rarp() process_decode_inner_arp_rarp_0;
    @name("process_decode_inner_nd") process_decode_inner_nd() process_decode_inner_nd_0;
    apply {
        process_decode_inner_l2_da_0.apply(hdr, meta, standard_metadata);
        if (hdr.inner_ipv4.isValid() || hdr.inner_ipv6.isValid()) {
            process_decode_inner_ip_da_0.apply(hdr, meta, standard_metadata);
            process_decode_inner_ip_sa_0.apply(hdr, meta, standard_metadata);
            // Use a dummy table to set "is_ipfrag" flag
            if (hdr.inner_ipv4.isValid() &&
                (hdr.inner_ipv4.flag_more == 1 ||
                 hdr.inner_ipv4.fragOffset != 0))
            {
                meta.l3.inner_ipfrag = TRUE;
            }
            // TBD: Shouldn't we also check for IPv6 fragment
            // extension header and set similar flags if it is a
            // non-first fragment?
        }
        else if (hdr.arp_rarp.isValid()) {
            process_decode_inner_arp_rarp_0.apply(hdr, meta, standard_metadata);
        } else if (hdr.icmpv6.isValid()) {
            process_decode_inner_nd_0.apply(hdr, meta, standard_metadata);
#ifndef DISABLE_MPLS
#endif /*DISABLE_MPLS*/
        }
    }
}

control process_initial_bypass_code(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_initial_bypass_info")
    action set_initial_bypass_info(bit<1> outer_vlan_xlate_bypass,
                                   bit<1> rpf_bypass, bit<1> is_rmac_bypass,
                                   bit<1> pt_bypass, bit<1> fwd_lookup_bypass,
                                   bit<1> acl_bypass, bit<1> learn_bypass,
                                   bit<1> sup_rx_bypass,
                                   bit<1> eg_mtu_check_bypass)
    {
        meta.bypass_info.outer_vlan_xlate_bypass = outer_vlan_xlate_bypass;
        meta.bypass_info.rpf_bypass = rpf_bypass;
        meta.bypass_info.is_rmac_bypass = is_rmac_bypass;
        meta.bypass_info.pt_bypass = pt_bypass;
        meta.bypass_info.fwd_lookup_bypass = fwd_lookup_bypass;
        meta.bypass_info.acl_bypass = acl_bypass;
        meta.bypass_info.learn_bypass = learn_bypass;
        meta.bypass_info.sup_rx_bypass = sup_rx_bypass;
        meta.bypass_info.eg_mtu_check_bypass = eg_mtu_check_bypass;
    }
    @name("bypass_info_table") table bypass_info_table {
        actions = {
            set_initial_bypass_info;
            @default_only NoAction;
        }
        key = {
            meta.ingress.bypass_code: exact;
        }
        size = BYPASS_INFO_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        // TBD: Either there is a bug here, or the code is written to
        // assume that all header and packet metadata bits will be
        // initialized to 0.  I am OK with the latter, if we determine
        // that is reasonable to implement it in our system, but at
        // least the P4_16 language spec makes it clear that invalid
        // headers have undefined contents, not guaranteed to be
        // initialized to any particular values.
	if (hdr.ieth.sup_tx == 1) {
	    // Sup TX
	    meta.ingress.bypass_code = hdr.ieth.sup_code;
	}
        bypass_info_table.apply();
    }
}

control process_src_port_mapping(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_local_src_port_state")
    action set_local_src_port_state(bit<8> src_chip, bit<8> src_port,
                                    bit<1> ftag_mode
#ifdef DISABLE_MODULAR_CHASIS
                                    ,
                                    bit<2> vnic_if,
                                    bit<11> niv_idx, bit<1> storefwd,
                                    bit<6> iic_port_idx, bit<4> src_sh_group,
                                    bit<11> src_if_num, bit<1> ifabric_ingress,
                                    bit<1> ifabric_egress,
                                    bit<3> fabric_if_stats_idx
#endif
                                    )
    {
        meta.src_port.src_chip = src_chip;
        meta.src_port.src_port = src_port;
        meta.src_port.ftag_mode = ftag_mode;
#ifdef DISABLE_MODULAR_CHASIS
        meta.src_port.vnic_if = vnic_if;
        meta.src_port.niv_idx = niv_idx;
        meta.src_port.storefwd = storefwd;
        meta.src_port.iic_port_idx = iic_port_idx;
        meta.ig_tunnel.src_sh_group = src_sh_group;
        meta.src_port.src_if_num = src_if_num;
        meta.src_port.ifabric_ingress = ifabric_ingress;
        meta.src_port.ifabric_egress = ifabric_egress;
        meta.src_port.fabric_if_stats_idx = fabric_if_stats_idx;
        meta.ingress.ifabric_ingress = ifabric_ingress;
#endif
        //meta.ingress.ifabric_egress = ifabric_egress;
    }
    @name("local_src_port_state") table local_src_port_state {
        actions = {
            set_local_src_port_state;
            @default_only NoAction;
        }
        key = {
            meta.dp_ig_header.ingress_port: exact;
            meta.dp_ig_header.port_type   : exact;
        }
        size = LOCAL_SRC_PORTMAP_TABLE_SIZE;
        default_action = NoAction();
    }

#ifndef DISABLE_MODULAR_CHASIS
    action set_src_chip_state(bit<12> offset) {
        meta.local_ingress.src_chip_offset = offset;
    }
    table src_chip_state {
        key = {
	    meta.local_ingress.src_chip : exact;
        }
        actions = {
            set_src_chip_state;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = SRC_CHIP_TABLE_SIZE;
    }

    action set_global_src_port_state (bit<2>  vnic_if,
                                      bit<11> niv_idx,
                                      bit<1>  storefwd,
                                      bit<6>  iic_port_idx,
                                      bit<4>  src_sh_group,
                                      bit<11> src_if_num,
                                      bit<1>  ifabric_ingress,
                                      bit<1>  ifabric_egress,
                                      bit<3>  fabric_if_stats_idx)
    {
	meta.src_port.vnic_if = vnic_if;
	meta.src_port.niv_idx = niv_idx;
	meta.src_port.storefwd = storefwd;
	meta.src_port.iic_port_idx = iic_port_idx;
	meta.src_port.src_sh_group = src_sh_group;
	meta.src_port.src_if_num = src_if_num;
	meta.src_port.ifabric_ingress = ifabric_ingress;
	meta.src_port.ifabric_egress = ifabric_egress;
	meta.src_port.fabric_if_stats_idx = fabric_if_stats_idx;
        meta.ingress.ifabric_ingress = ifabric_ingress;
        //meta.ingress.ifabric_egress = ifabric_egress;
    }
    table global_src_port_state {
        key = {
	    meta.local_ingress.src_global_port : exact;
            //meta.standard.ingress_port : exact;
            //meta.intrinsic.port_type   : exact;
        }
        actions = {
            set_global_src_port_state;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = GLOBAL_SRC_PORTMAP_TABLE_SIZE;
    }
#endif /*SUPPORT_MODULAR_CHASIS*/

    apply {
        local_src_port_state.apply();
#ifndef DISABLE_MODULAR_CHASIS
        // jafinger - I replaced a couple of occurrences of
        // meta.intrinsic.port_type with meta.dp_ig_header.port_type
        // here, since the latter was already defined, and I think
        // might match the intent of the original P4_14 code, which
        // never defined an intrinsic struct.
        if (meta.dp_ig_header.port_type == PORT_TYPE_IETH) {
            // TODO maybe_wrong_cast
            meta.local_ingress.src_chip = (bit<7>) hdr.ieth.src_chip;
        } else {
            meta.local_ingress.src_chip = 1;
            //meta.local_ingress.src_chip = meta.src_port.src_chip;
        }
        src_chip_state.apply();
        if (meta.dp_ig_header.port_type == PORT_TYPE_IETH) {
            // TODO : fix it after intrinsic_metadata is supported by parser
            meta.local_ingress.src_port = hdr.ieth.src_port;
        } else {
            meta.local_ingress.src_port = 1;
            //local_ingress.src_port = meta.src_port.src_port;
        }
        meta.local_ingress.src_global_port =
            (meta.local_ingress.src_chip_offset +
             (bit<12>) meta.local_ingress.src_port);
        global_src_port_state.apply();
#endif /*SUPPORT_MODULAR_CHASIS*/
    }
}

#ifndef P4_DISABLE_FEX
control process_vntag_sanity_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.vntag.isValid() && meta.src_port.vnic_if == 0) {
            meta.ig_drop.illegal_vntag = 1;
	    //meta.ig_drop.inc_drop_counters = TRUE;
        } else if (!hdr.vntag.isValid() && meta.src_port.vnic_if == 1) {
            meta.ig_drop.missing_vntag = 1;
	    //meta.ig_drop.inc_drop_counters = TRUE;
        }
    }
}
#endif /* P4_DISABLE_FEX */

#ifndef P4_DISABLE_FEX
control process_src_if_mapping(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".src_if_miss")
    action src_if_miss() {
        meta.ig_drop.src_if_miss = TRUE;
        //meta.ig_drop.inc_drop_counters = TRUE;
    }
    @name(".set_src_if_state")
    action set_src_if_state(bit<12> acl_label, bit<13> bd_xlate_idx,
                            bit<10> profile_idx, bit<1> trust_frame_cos,
                            bit<1> default_de, bit<3> default_cos,
                            bit<1> vlan_mbr_chk_en, bit<10> vlan_mbr_chk_idx,
                            bit<1> l3_bind_check_en, bit<1> l2_bind_check_en,
                            bit<1> mac_pkt_classify, bit<1> vpc,
                            bit<1> mct, bit<1> analytics_en,
                            bit<1> flow_collect_en, bit<1> is_local,
                            bit<1> drop_on_smac_miss,
                            bit<1> drop_non_secure_mac,
                            bit<1> flowtbl_mac_pkt_classify,
                            bit<1> qinq_customer_port
#ifndef SEPARATE_SRC_IF_STATE_TABLE
                            , bit<13> src_if_idx
#endif /*SEPARATE_SRC_IF_STATE_TABLE*/
                            )
    {
        meta.src_if.acl_label = acl_label;
        meta.src_if.bd_xlate_idx = bd_xlate_idx;
        meta.src_if.profile_idx = profile_idx;
        meta.src_if.trust_frame_cos = trust_frame_cos;
        meta.src_if.default_de = default_de;
        meta.src_if.default_cos = default_cos;
        meta.src_if.vlan_mbr_chk_en = vlan_mbr_chk_en;
        meta.src_if.vlan_mbr_chk_idx = vlan_mbr_chk_idx;
        meta.src_if.l3_bind_check_en = l3_bind_check_en;
        meta.src_if.l2_bind_check_en = l2_bind_check_en;
        meta.src_if.mac_pkt_classify = mac_pkt_classify;
        meta.src_if.vpc = vpc;
        meta.src_if.mct = mct;
        meta.src_if.analytics_en = analytics_en;
        meta.src_if.flow_collect_en = flow_collect_en;
        meta.src_if.is_local = is_local;
        meta.src_if.drop_on_smac_miss = drop_on_smac_miss;
        meta.src_if.drop_non_secure_mac = drop_non_secure_mac;
        meta.src_if.flowtbl_mac_pkt_classify = flowtbl_mac_pkt_classify;
        meta.src_if.qinq_customer_port = qinq_customer_port;
#ifndef SEPARATE_SRC_IF_STATE_TABLE
        meta.ingress.src_if_idx = src_if_idx;
#endif /*SEPARATE_SRC_IF_STATE_TABLE*/
    }
    @name(".set_src_if_profile")
    action set_src_if_profile(bit<7> qos_map_grp, bit<1> qos_map_use_dscp,
                              bit<1> qos_map_use_tc, bit<1> mac_learn_en,
                              bit<1> ip_learn_en, bit<1> sclass_learn_en)
    {
        meta.src_if_profile.qos_map_grp = qos_map_grp;
        meta.src_if_profile.qos_map_use_dscp = qos_map_use_dscp;
        meta.src_if_profile.qos_map_use_tc = qos_map_use_tc;
        meta.src_if_profile.mac_learn_en = mac_learn_en;
        meta.src_if_profile.ip_learn_en = ip_learn_en;
        meta.src_if_profile.sclass_learn_en = sclass_learn_en;
    }
    @name("src_if_map_hash") table src_if_map_hash {
        actions = {
            src_if_miss;
            set_src_if_state;
            //set_src_if_idx;
            @default_only NoAction;
        }
        key = {
            hdr.vntag.srcVif       : exact;
            hdr.vntag.isValid()    : exact;
            //meta.rc_port.niv_idx          : exact;
            meta.dp_ig_header.ingress_port: exact;
            meta.dp_ig_header.port_type   : exact;
        }
        size = SRC_IF_HASH_TABLE_SIZE;
        default_action = NoAction();
        @name("src_if_stats") counters = direct_counter(CounterType.packets_and_bytes);
    }
    @name("src_if_profile") table src_if_profile {
        actions = {
            set_src_if_profile;
            @default_only NoAction;
        }
        key = {
            meta.src_if.profile_idx: exact;
        }
        size = SRC_IF_PROFILE_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
#ifndef DISABLE_VIF_BYPASS
        if (meta.bypass_info.vif_bypass == 0) {
#endif /*DISABLE_VIF_BYPASS*/
        if (!src_if_map_hash.apply().hit) {
            meta.ig_drop.src_if_miss = TRUE;
            //meta.ig_drop.inc_drop_counters = TRUE;
        }
#ifndef DISABLE_VIF_BYPASS
        } else {
        }
#endif /*DISABLE_VIF_BYPASS*/
#ifdef SEPARATE_SRC_IF_STATE_TABLE
        src_if_state.apply();
#endif
        src_if_profile.apply();
    }
}
#endif /* P4_DISABLE_FEX */

control process_outer_src_bd_derivation(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_outer_src_bd_state")
    action set_outer_src_bd_state(bit<14> vrf, bit<12> mbr_bitmap_idx,
                                  bit<10> rmac_index, bit<1> ipv4_ucast_en,
                                  bit<1> ipv6_ucast_en, bit<1> ipv4_mcast_en,
                                  bit<1> ipv6_mcast_en, bit<16> bd_stats_idx)
    {
        meta.outer_src_bd.vrf = vrf;
        meta.outer_src_bd.mbr_bitmap_idx = mbr_bitmap_idx;
        meta.outer_src_bd.rmac_index = rmac_index;
        meta.outer_src_bd.ipv4_ucast_en = ipv4_ucast_en;
        meta.outer_src_bd.ipv6_ucast_en = ipv6_ucast_en;
        meta.outer_src_bd.ipv4_mcast_en = ipv4_mcast_en;
        meta.outer_src_bd.ipv6_mcast_en = ipv6_mcast_en;
        meta.outer_src_bd.bd_stats_idx = bd_stats_idx;
    }
    @name(".port_vlan_mapping_miss") action port_vlan_mapping_miss() {
        meta.l2.port_vlan_mapping_miss = TRUE;
    }
    @name("src_vlan_xlate_map_hash") table src_vlan_xlate_map_hash {
        actions = {
#ifndef SEPARATE_BD_STATE_TABLE
            set_outer_src_bd_state;
#else
            set_outer_src_bd;
            //et_src_epg_or_bd;
#endif
            port_vlan_mapping_miss;
            @default_only NoAction;
        }
        key = {
            meta.src_if.bd_xlate_idx: exact;
            meta.src_if.skip_qtag0  : exact;
            //meta.ig_local.src_vlan_xlate_key_vlan0 : exact;
            //meta.ig_local.src_vlan_xlate_key_vlan1 : exact;
            hdr.qtag0.isValid()       : exact;
            hdr.qtag0.vid             : exact;
            hdr.qtag1.isValid()       : exact;
            hdr.qtag1.vid             : exact;
        }
        size = SRC_VLAN_XLATE_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        //if (hdr.qtag0.isValid() && (hdr.qtag0.vid != 0)) {
        //    meta.ig_local.vlan0_vld = TRUE;
        //    meta.ig_local.vlan0_vid = hdr.qtag0.vid;
        //} else {
        //    meta.ig_local.vlan0_vld = FALSE;
        //    meta.ig_local.vlan0_vid = hdr.qtag0.vid;
        //}
                
        if (meta.bypass_info.outer_vlan_xlate_bypass == 1) {
	    meta.ingress.outer_src_bd = hdr.ieth.outer_bd;
        } else {
	    // Form Lookup Key
            //if (hdr.qtag0.isValid() &&
            //    (meta.src_if.skip_qtag0 == 0))
            //{
            //    meta.ig_local.src_vlan_xlate_key_vlan0 = hdr.qtag0.vid;
            //} else {
            //    meta.ig_local.src_vlan_xlate_key_vlan0 = meta.src_if.default_vlan;
            //}

	    //if (hdr.qtag1.isValid()) {
            //    meta.ig_local.src_vlan_xlate_key_vlan1 = hdr.qtag1.vid;
	    //} else {
	    //    meta.ig_local.src_vlan_xlate_key_vlan1 = 0;
	    //}

	    // PV translation
            if (!src_vlan_xlate_map_hash.apply().hit) {
                meta.ig_drop.vlan_xlate_miss = TRUE;
                //meta.ig_drop.inc_drop_counters = TRUE;
            }
        }
#ifdef SEPARATE_BD_STATE_TABLE
	outer_src_bd_state.apply();
#endif /*SEPARATE_BD_STATE_TABLE*/
        //src_bd_profile.apply();
    }
}

control process_outer_src_bd_stats(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("outer_src_bd_stats") @min_width(48) counter(4096, CounterType.packets_and_bytes) outer_src_bd_stats;
    @name(".update_outer_src_bd_stats")
    action update_outer_src_bd_stats() {
        outer_src_bd_stats.count((bit<32>) meta.outer_src_bd.bd_stats_idx);
    }
    @name("outer_src_bd_stats") table outer_src_bd_stats_0 {
        actions = {
            update_outer_src_bd_stats;
            @default_only NoAction;
        }
	size = BD_STATS_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        outer_src_bd_stats_0.apply();
    }
}

control process_src_vlan_mbr_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_vlan_mbr_state")
    action set_vlan_mbr_state(bit<1> drop) {
        meta.ig_drop.src_vlan_mbr = drop;
        //meta.ig_drop.inc_drop_counters = TRUE;
    }
    @name("vlan_mbr_search_hash_table") table vlan_mbr_search_hash_table {
        actions = {
            set_vlan_mbr_state;
            @default_only NoAction;
        }
        key = {
            meta.ingress.src_if_idx  : exact;
            meta.ingress.outer_src_bd: exact;
        }
        size = INGRESS_VLAN_MBR_SEARCH_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    // 16K combinations of {bd, src_if_idx}
    @name("vlan_mbr_table") table vlan_mbr_table {
        actions = {
            set_vlan_mbr_state;
            @default_only NoAction;
        }
        key = {
            meta.outer_src_bd.mbr_bitmap_idx: exact;
            //meta.ingress.outer_src_bd       : exact;
            meta.src_if.vlan_mbr_chk_idx    : exact;
        }
        size = INGRESS_VLAN_MBR_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        switch (vlan_mbr_search_hash_table.apply().action_run) {
            NoAction: {
                vlan_mbr_table.apply();
            }
        }

    }
}

control process_rmac_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".rmac_hit") action rmac_hit() {
        meta.l3.rmac_hit = TRUE;
    }
    @name(".rmac_miss") action rmac_miss() {
        meta.l3.rmac_hit = FALSE;
    }
    @name("rmac_search") table rmac_search {
        actions = {
            rmac_hit;
            rmac_miss;
            @default_only NoAction;
        }
        key = {
            meta.outer_src_bd.rmac_index   : exact;
            hdr.ipv4.isValid()               : exact;
            hdr.ipv6.isValid()               : exact;
            meta.l2.lkp_mac_da             : exact;
            meta.bypass_info.is_rmac_bypass: ternary;
            //meta.ig_tunnel.l3_tunnel_decap : ternary;
            //meta.src_bd.route_bd : ternary;
        }
        size = ROUTER_MAC_TCAM_SIZE;
        default_action = NoAction();
    }
    apply {
        //if (meta.bypass_info.is_rmac_bypass == 1) {
	//    meta.l3.rmac_hit = FALSE;
	//} else if (meta.src_bd_metadata.route_bd == 1) {
	//    meta.l3.rmac_hit = TRUE;
	//} else if (meta.ig_tunnel_metadata.l3_tunnel_decap == 1) {
	//    meta.l3.rmac_hit = TRUE;
	//} else {

	/*
	rmac_dirmap.apply();
	if (meta.l3.src_bd_rmac == meta.l2.lkp_mac_da) {
	    dummy_rmac_hit.apply();
	}
	*/
        rmac_search.apply();
	/*
	apply(rmac_search) {
	    rmac_miss {
		apply(rmac_dirmap);
		if (meta.l3.src_bd_rmac == meta.l2.lkp_mac_da) {
		    apply(dummy_rmac_hit);
		}
	    }
	}
	*/
	/* Moved these conditions to rmac_search table 
	if (meta.bypass_info.is_rmac_bypass == 1) {
	    meta.l3.rmac_hit = FALSE;
	} else if (meta.src_bd.route_bd == 1) {
	    meta.l3.rmac_hit = TRUE;
	} else if (meta.ig_tunnel.l3_tunnel_decap == 1) {
	    meta.l3.rmac_hit = TRUE;
	}
	*/
	//    }
    }
}

control process_pre_tunnel_decap_fwd_mode(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

#ifdef USE_TABLE_FOR_FWD_MODE
    @name(".set_pre_tunnel_decap_l2_fwd_mode")
    action set_pre_tunnel_decap_l2_fwd_mode(bit<2> l2_mode
                                            //,
                                            //bit<8> encap_flood_fwd_lkup,
                                            //bit<8> arp_unicast_mode,
                                            //bit<8> rarp_unicast_mode,
                                            //bit<8> nd_unicast_mode
                                            )
    {
        meta.ingress.l2_fwd_mode = l2_mode;
    }
    @name(".set_pre_tunnel_decap_l3_fwd_mode")
    action set_pre_tunnel_decap_l3_fwd_mode(bit<2> l3_mode,
                                            bit<1> arp_unicast_mode,
                                            bit<1> rarp_unicast_mode,
                                            bit<1> nd_unicast_mode)
    {
        meta.ingress.l3_fwd_mode = l3_mode;
        meta.l3.arp_unicast_mode = arp_unicast_mode;
        meta.l3.rarp_unicast_mode = rarp_unicast_mode;
        meta.l3.nd_unicast_mode = nd_unicast_mode;
    }
    @name(".set_pre_tunnel_decap_l2_l3_fwd_mode")
    action set_pre_tunnel_decap_l2_l3_fwd_mode(bit<2> l2_mode,
                                               bit<2> l3_mode
                                               //,
                                               //bit<8> encap_flood_fwd_lkup,
                                               //bit<8> arp_unicast_mode,
                                               //bit<8> rarp_unicast_mode,
                                               //bit<8> nd_unicast_mode
                                               )
    {
        meta.ingress.l2_fwd_mode = l2_mode;
        meta.ingress.l3_fwd_mode = l3_mode;
    }
    @name(".set_pre_tunnel_decap_ttl_expired_drop")
    action set_pre_tunnel_decap_ttl_expired_drop() {
        meta.ig_drop.outer_ttl_expired = TRUE;
	//meta.ig_drop.inc_drop_counters = TRUE;
	//meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
    }

#ifndef DISABLE_MPLS
    @name(".set_pre_tunnel_decap_mpls_disabled_drop")
    action set_pre_tunnel_decap_mpls_disabled_drop() {
	meta.ig_drop.mpls_disabled = TRUE;
	//meta.ig_drop.inc_drop_counters = TRUE;
	//meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
    }
#endif /*DISABLE_MPLS*/

    action set_pre_tunnel_decap_routing_disabled_drop() {
	meta.ig_drop.routing_disabled = TRUE;
	//meta.ig_drop.inc_drop_counters = TRUE;
	//meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
    }

    @name("pre_tunnel_decap_fwd_mode") table pre_tunnel_decap_fwd_mode {
        actions = {
            set_pre_tunnel_decap_l2_fwd_mode;
            set_pre_tunnel_decap_l3_fwd_mode;
            set_pre_tunnel_decap_l2_l3_fwd_mode;
            set_pre_tunnel_decap_ttl_expired_drop;
#ifndef DISABLE_MPLS
	    set_pre_tunnel_decap_mpls_disabled_drop;
#endif /*DISABLE_MPLS*/
            set_pre_tunnel_decap_routing_disabled_drop;
            @default_only NoAction;
        }
        key = {
            meta.bypass_info.fwd_lookup_bypass: ternary;
            meta.l2.l2_da_type                : ternary;
            meta.l3.l3_type                   : ternary;
            meta.l3.ip_da_type                : ternary;
            meta.l3.rmac_hit                  : ternary;
            meta.l3.nd_type                   : ternary;
#ifndef DISABLE_MPLS
            meta.outer_src_bd.mpls_en         : ternary;
            meta.mplsm.topmost_non_null_label_ttl: ternary;
#endif /*DISABLE_MPLS*/
            meta.outer_src_bd.ipv4_ucast_en   : ternary;
            meta.outer_src_bd.ipv4_mcast_en   : ternary;
            meta.outer_src_bd.ipv6_ucast_en   : ternary;
            meta.outer_src_bd.ipv6_mcast_en   : ternary;
            meta.l3.lkp_ip_ttl                : ternary;
        }
	size = FWD_MODE_TABLE_SIZE;
        default_action = NoAction();
    }
#endif /*USE_TABLE_FOR_FWD_MODE*/

    apply {
#ifdef USE_TABLE_FOR_FWD_MODE
        pre_tunnel_decap_fwd_mode.apply();
#else /*USE_TABLE_FOR_FWD_MODE*/

        if (meta.bypass_info.fwd_lookup_bypass == 0) {
            meta.ingress.l2_fwd_mode = hdr.ieth.l2_fwd_mode;
            meta.ingress.l3_fwd_mode = hdr.ieth.l3_fwd_mode;
            // combine 8-bit dstchip and dst-port values to form
            // 16-bit met pointer
        }
        else 
#ifndef DISABLE_MPLS
        if (meta.l3.l3_type == L3TYPE_MPLS) {
	    if (meta.l3.rmac_hit == 1) {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
		if (meta.outer_src_bd.mpls_en == 1) {
		    if (meta.mplsm.topmost_non_null_label_ttl < 1 ) {
			// Note : TTL == 1 is allowed here because we
			// want to decap. For non-termination cases,
			// we can either drop it later in ingress
			// pipeline or on egress.
			meta.ig_drop.ttl_expired = TRUE;
			//meta.ig_drop.inc_drop_counters = TRUE;
			meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		    } else {
			meta.ingress.l3_fwd_mode = L3_FWD_MODE_MPLS;
		    }
		} else {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		    meta.ig_drop.mpls_disabled = TRUE;
		    //meta.ig_drop.inc_drop_counters = TRUE;
		}
	    } else {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
		meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
	    }
	}
	else 
#endif /*DISABLE_MPLS*/
	if (meta.l3.l3_type == L3TYPE_IPV4) {
	    if (meta.l3.ip_da_type == IP_MULTICAST) {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_MC;
		if ((meta.l3.ip_da_type == IP_MULTICAST_LL) ||
                    (meta.outer_src_bd.ipv4_mcast_en == 0))
                {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		} else {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
		}
	    } else {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
		if (meta.l3.rmac_hit == 1) {
		    if (meta.outer_src_bd.ipv4_ucast_en == 1) {
			if (meta.l3.lkp_ip_ttl < 1) {
			    meta.ig_drop.ttl_expired = TRUE;
			    //meta.ig_drop.inc_drop_counters = TRUE;
			    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
			} else {
			    meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
			}
		    } else {
			meta.ig_drop.routing_disabled = TRUE;
			//meta.ig_drop.inc_drop_counters = TRUE;
			meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		    }
		} else {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		}
	    }
	} else if (meta.l3.l3_type == L3TYPE_IPV6) {
	    if (meta.l3.ip_da_type == IP_MULTICAST) {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_MC;
		if ((meta.l3.ip_da_type == IP_MULTICAST_LL) ||
                    (meta.outer_src_bd.ipv6_mcast_en == 0))
                {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		} else {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
		}
	    } else {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
		if (meta.l3.rmac_hit == 1) {
		    if (meta.outer_src_bd.ipv6_ucast_en == 1) {
			if (meta.l3.lkp_ip_ttl < 1) {
			    meta.ig_drop.ttl_expired = TRUE;
			    //meta.ig_drop.inc_drop_counters = TRUE;
			    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
			} else {
			    meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
			}
		    } else {
			meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
			meta.ig_drop.routing_disabled = TRUE;
			//meta.ig_drop.inc_drop_counters = TRUE;
		    }
		} else {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		}
	    }
	} else {
	    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
	    if (meta.l2.l2_da_type == L2_MULTICAST) {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_MC;
	    } else if (meta.l2.l2_da_type == L2_BROADCAST) {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_BC;
	    } else {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
	    }
	}
#endif /*USE_TABLE_FOR_FWD_MODE*/
    }
}

control process_aci_ftag(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
#ifndef DISABLE_FTAG_OVERRIDE
    /************************************************************************/
    /* FTAG Override */
    /************************************************************************/

    action set_ipv4_ftag_override_hit(bit<1> ftag_mode) {
	meta.ig_tunnel.ftag_mode = ftag_mode;
    }
    table ipv4_ftag_override_table {
	key = {
	    meta.outer_src_bd.vrf : ternary;
            meta.ipv4m.lkp_ipv4_da : ternary;
	}
	actions = {
	    set_ipv4_ftag_override_hit;
            @default_only NoAction;
	}
        default_action = NoAction();
	size = IPV4_FTAG_OVERRIDE_TABLE_SIZE;
    }

    action set_ipv6_ftag_override_hit(bit<1> ftag_mode) {
	meta.ig_tunnel.ftag_mode = ftag_mode;
    }
    table ipv6_ftag_override_table {
	key = {
	    meta.outer_src_bd.vrf : ternary;
            meta.ipv6m.lkp_ipv6_da : ternary;
	}
	actions = {
	    set_ipv6_ftag_override_hit;
            @default_only NoAction;
	}
        default_action = NoAction();
	size = IPV6_FTAG_OVERRIDE_TABLE_SIZE;
    }
#endif /*DISABLE_FTAG_OVERRIDE*/

    /************************************************************************/
    /* FTAG OIF List */
    /************************************************************************/

    action set_ftag_oif_info(bit<128> oif_list) {
        meta.ig_tunnel.ftag_oif_list = oif_list;
    }
    table ftag_oif_table {
        key = {
	    meta.ig_tunnel.ifabric_ftag : exact;
        }
        actions = {
            set_ftag_oif_info;
            @default_only NoAction;
        }
        size = FTAG_OIF_INFO_TABLE_SIZE;
        default_action = NoAction();
    }

    apply {
        // ~~~~~~ ACI FTAG override lookup ~~~~~~
        // First take default from port
        meta.ig_tunnel.ftag_mode = meta.src_port.ftag_mode;
        // then check if ftag mode needs to be overwritten
#ifndef DISABLE_FTAG_OVERRIDE
        if (meta.l3.l3_type == L3TYPE_IPV4) {
            ipv4_ftag_override_table.apply();
        } else {
            ipv6_ftag_override_table.apply();
        }
#endif /*DISABLE_FTAG_OVERRIDE*/
        
        // ~~~~~ Extract FTAG ~~~~~
        if (meta.l3.l3_type == L3TYPE_IPV4) {
            meta.ig_tunnel.ifabric_ftag[3:0] = meta.ipv4m.lkp_ipv4_da[3:0];
        } else {
            meta.ig_tunnel.ifabric_ftag[3:0] = meta.ipv6m.lkp_ipv6_da[3:0];
        }

        // ~~~~~ Read FTAG OIF Info Table ~~~~~
        ftag_oif_table.apply();
        
        // ~~~~~~ ACI FTAG IIC Check ~~~~~~
        //bit_slc(ig_tunnel.ftag_iic_result, ig_tunnel.ftag_oif_list, src_port.iic_port_idx, src_port.iic_port_idx);
        meta.ig_tunnel.ftag_iic_result =
            (bit<1>) (meta.ig_tunnel.ftag_oif_list >>
                      meta.src_port.iic_port_idx);
        
        if ((meta.ingress.ifabric_ingress == 0) &&
            (meta.ig_tunnel.ftag_mode == 1))
        {
            // Zero out last 4-bits of Group Address
            if (meta.l3.l3_type == L3TYPE_IPV4) {
                meta.ig_local.lkp_outer_ipv4_ga = (meta.ipv4m.lkp_ipv4_da &
                                                   0xFFFFFFF0);
            } else {
                meta.ig_local.lkp_outer_ipv6_ga =
                    (meta.ipv6m.lkp_ipv6_da &
                     0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0);
            }
            
            // IIC check drop
            if (meta.ig_tunnel.ftag_iic_result == 0) {
                meta.ig_drop.iic_check_failure = 1;
                //meta.ig_drop.inc_drop_counters = TRUE;
            }
        }
    }
}

control process_ipv4_tunnel_mcast(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // Tunnel {*,G}
    @name(".set_tunnel_ipv4_mc_group_state")
    action set_tunnel_ipv4_mc_group_state(bit<1> rpf_en, bit<1> bidir,
                                          bit<14> rpf_bd_or_group,
                                          bit<16> met1_ptr,
                                          bit<1> sup_copy,
                                          bit<1> no_dc_sup_redirect,
                                          bit<1> rpf_fail_send_to_sup,
                                          bit<16> hit_addr)
    {
        meta.ig_tunnel.mc_group_lookup_hit = TRUE;
        meta.ig_tunnel.mc_group_hit_addr = hit_addr;
        meta.ig_tunnel.mc_group_rpf_en = rpf_en;
        meta.ig_tunnel.mc_group_bidir = bidir;
        meta.ig_tunnel.mc_group_rpf_bd_or_group = rpf_bd_or_group;
        meta.ingress.met1_vld = 1;
        meta.ingress.met1_ptr = met1_ptr;
        meta.ig_tunnel.sup_copy = sup_copy;
        meta.ig_tunnel.rpf_fail_send_to_sup = rpf_fail_send_to_sup;
        meta.ig_tunnel.no_dc_sup_redirect = no_dc_sup_redirect;
	//meta.ig_tunnel.mc_group_rpf_bd_match = meta.ingress.src_bd ^ rpf_bd_or_group; 
    }
    @name("tunnel_ipv4_mc_group_hash_table")
    table tunnel_ipv4_mc_group_hash_table {
        actions = {
            set_tunnel_ipv4_mc_group_state;
            @default_only NoAction;
        }
        key = {
            meta.outer_src_bd.vrf          : exact;
            meta.ig_local.lkp_outer_ipv4_ga: exact;
        }
        size = IPV4_TUNNEL_MC_GROUP_HASH_TABLE_SIZE;
        default_action = NoAction();
    }

    @name(".set_tunnel_ipv4_mc_sg_state")
    action set_tunnel_ipv4_mc_sg_state(bit<1> rpf_en, bit<14> rpf_bd,
                                       bit<16> met1_ptr, bit<1> sup_copy,
                                       bit<1> no_dc_sup_redirect,
                                       bit<1> rpf_fail_send_to_sup,
                                       bit<16> hit_addr)
    {
        meta.ig_tunnel.mc_sg_lookup_hit = TRUE;
        meta.ig_tunnel.mc_sg_hit_addr = hit_addr;
        meta.ig_tunnel.mc_sg_rpf_en = rpf_en;
        meta.ig_tunnel.mc_sg_rpf_bd = rpf_bd;
        meta.ingress.met1_vld = 1;
        meta.ingress.met1_ptr = met1_ptr;
        meta.ig_tunnel.sup_copy = sup_copy;
        meta.ig_tunnel.rpf_fail_send_to_sup = rpf_fail_send_to_sup;
        meta.ig_tunnel.no_dc_sup_redirect = no_dc_sup_redirect;
	//meta.ig_tunnel.mc_sg_rpf_bd_match = meta.ingress.src_bd ^ rpf_bd; 
    }
    @name("tunnel_ipv4_mc_sg_hash_table")
    table tunnel_ipv4_mc_sg_hash_table {
        actions = {
            set_tunnel_ipv4_mc_sg_state;
            @default_only NoAction;
        }
        key = {
            meta.outer_src_bd.vrf: exact;
            meta.ipv4m.lkp_ipv4_sa: exact;
            meta.ipv4m.lkp_ipv4_da: exact;
        }
        size = IPV4_TUNNEL_MC_SG_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
//#ifdef ACI_TOR_MODE
        //if (meta.CFG_aci_tor_mode.enable == 1) {
        //if (meta.ig_tunnel.src_encap_type == ENCAP_TYPE_IVXLAN) {
        //    // ACI FTAG mode. 
        //    meta.ig_tunnel.ftag_mode = meta.src_if_profile.ftag_mode;
        //    ipv4_ftag_override_table.apply();
        //    if ((meta.ingress.ifabric_egress == 1) &&
        //        (meta.ig_tunnel.ftag_mode == 1))
        //    {
        //        // Extract FTAG
        //        meta.ig_tunnel.ifabric_ftag = meta.ipv4m.lkp_ipv4_da & 0xF;
        //        
        //        // FTAG IIC check
        //        meta.ig_tunnel.ftag_iic_result =
        //            (bit<1>) (meta.ig_tunnel.ftag_oif_list >>
        //                      meta.src_port.iic_port_idx);
        //        
        //        if (meta.ig_tunnel.ftag_iic_result == 0) {
        //            meta.ig_drop.iic_check_failure = 1;
        //        }
        //        
        //        // Zero out last 4-bits of Group Address
	//	// //ppp if ($ip_ver eq "ipv4") {
        //        meta.ipv4m.lkp_ipv4_da = meta.ipv4m.lkp_ipv4_da & 0xFFFFFFF0;
        //        // //ppp } else {
        //        //meta.ipv4m.lkp_ipv4_da = meta.ipv4m.lkp_ipv4_da & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0;
        //        //ppp }
        //    }
        //}
        //}
//#endif /*ACI_TOR_MODE*/

        tunnel_ipv4_mc_group_hash_table.apply();
        //if ((meta.ig_tunnel.mc_group_lookup_hit == 1) &&
        //    (meta.ig_tunnel.mc_group_bidir == 0))
        //{
        tunnel_ipv4_mc_sg_hash_table.apply();
        //}
        //tunnel_ipv4_mc_sg_hash_table.apply() {
        //    NoAction: {
        //        apply(tunnel_ipv4_mc_group_hash_table);
        //    }
        //}
    }
}

control process_ipv6_tunnel_mcast(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_tunnel_ipv6_mc_sg_state")
    action set_tunnel_ipv6_mc_sg_state(bit<1> rpf_en, bit<14> rpf_bd,
                                       bit<16> met1_ptr, bit<1> sup_copy,
                                       bit<1> no_dc_sup_redirect,
                                       bit<1> rpf_fail_send_to_sup,
                                       bit<16> hit_addr)
    {
        meta.ig_tunnel.mc_sg_lookup_hit = TRUE;
        meta.ig_tunnel.mc_sg_hit_addr = hit_addr;
        meta.ig_tunnel.mc_sg_rpf_en = rpf_en;
        meta.ig_tunnel.mc_sg_rpf_bd = rpf_bd;
        meta.ingress.met1_vld = 1;
        meta.ingress.met1_ptr = met1_ptr;
        meta.ig_tunnel.sup_copy = sup_copy;
        meta.ig_tunnel.rpf_fail_send_to_sup = rpf_fail_send_to_sup;
        meta.ig_tunnel.no_dc_sup_redirect = no_dc_sup_redirect;
        //meta.ig_tunnel.mc_sg_rpf_bd_match = meta.ingress.src_bd ^ rpf_bd;
    }
    @name("tunnel_ipv6_mc_sg_hash_table")
    table tunnel_ipv6_mc_sg_hash_table {
        actions = {
            set_tunnel_ipv6_mc_sg_state;
            @default_only NoAction;
        }
        key = {
            meta.outer_src_bd.vrf: exact;
            meta.ipv6m.lkp_ipv6_sa: exact;
            meta.ipv6m.lkp_ipv6_da: exact;
        }
        size = IPV6_TUNNEL_MC_SG_HASH_TABLE_SIZE;
        default_action = NoAction();
    }

    @name(".set_tunnel_ipv6_mc_group_state")
    action set_tunnel_ipv6_mc_group_state(bit<1> rpf_en, bit<1> bidir,
                                          bit<14> rpf_bd_or_group,
                                          bit<16> met1_ptr, bit<1> sup_copy,
                                          bit<1> no_dc_sup_redirect,
                                          bit<1> rpf_fail_send_to_sup,
                                          bit<16> hit_addr)
    {
        meta.ig_tunnel.mc_group_lookup_hit = TRUE;
        meta.ig_tunnel.mc_group_hit_addr = hit_addr;
        meta.ig_tunnel.mc_group_rpf_en = rpf_en;
        meta.ig_tunnel.mc_group_bidir = bidir;
        meta.ig_tunnel.mc_group_rpf_bd_or_group = rpf_bd_or_group;
        meta.ingress.met1_vld = 1;
        meta.ingress.met1_ptr = met1_ptr;
        meta.ig_tunnel.sup_copy = sup_copy;
        meta.ig_tunnel.rpf_fail_send_to_sup = rpf_fail_send_to_sup;
        meta.ig_tunnel.no_dc_sup_redirect = no_dc_sup_redirect;
	//meta.ig_tunnel.mc_group_rpf_bd_match = meta.ingress.src_bd ^ rpf_bd_or_group;
    }
    @name("tunnel_ipv6_mc_group_hash_table")
    table tunnel_ipv6_mc_group_hash_table {
        actions = {
            set_tunnel_ipv6_mc_group_state;
            @default_only NoAction;
        }
        key = {
            meta.outer_src_bd.vrf          : exact;
            meta.ig_local.lkp_outer_ipv6_ga: exact;
        }
        size = IPV6_TUNNEL_MC_GROUP_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
//#ifdef ACI_TOR_MODE
        //if (meta.CFG_aci_tor_mode.enable == 1) {
        //if (meta.ig_tunnel.src_encap_type == ENCAP_TYPE_IVXLAN) {
        //    // ACI FTAG mode. 
        //    meta.ig_tunnel.ftag_mode = meta.src_if_profile.ftag_mode;
        //    apply(ipv6_ftag_override_table);
        //    if ((meta.ingress.ifabric_egress == 1) &&x
        //        (meta.ig_tunnel.ftag_mode == 1))
        //    {
        //        // Extract FTAG
        //        meta.ig_tunnel.ifabric_ftag = meta.ipv6m.lkp_ipv6_da & 0xF;
        //        
        //        // FTAG IIC check
        //        meta.ig_tunnel.ftag_iic_result =
        //            (bit<1>) (meta.ig_tunnel.ftag_oif_list >>
        //                      meta.src_port.iic_port_idx);
        //        
        //        if (meta.ig_tunnel.ftag_iic_result == 0) {
        //            meta.ig_drop.iic_check_failure = 1;
        //        }
        //        
        //        // Zero out last 4-bits of Group Address
        //        //ppp if ($ip_ver eq "ipv4") {
        //        meta.ipv6m.lkp_ipv6_da = meta.ipv6m.lkp_ipv6_da & 0xFFFFFFF0;
        //        //ppp } else {
        //        meta.ipv6m.lkp_ipv6_da = meta.ipv6m.lkp_ipv6_da & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0;
        //        //ppp }
        //    }
        //}
        //}
//#endif /*ACI_TOR_MODE*/
        tunnel_ipv6_mc_group_hash_table.apply();

        //if ((meta.ig_tunnel.mc_group_lookup_hit == 1) &&
        //    (meta.ig_tunnel.mc_group_bidir == 0))
        //{
        tunnel_ipv6_mc_sg_hash_table.apply();
        //}
	//
        //apply(tunnel_ipv6_mc_sg_hash_table) {
        //    on_miss {
        //        apply(tunnel_ipv6_mc_group_hash_table);
        //    }
        //}
    }
}

/*****************************************************************************/
/* Multicast RPF Check */
/*****************************************************************************/

control process_tunnel_mcast_rpf_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_tunnel_mc_group_bidir_rpf_pass")
    action set_tunnel_mc_group_bidir_rpf_pass() {
        meta.ig_tunnel.mc_rpf_pass = TRUE;
        meta.ig_tunnel.mc_group_rpf_pass = TRUE;
    }
    @name("tunnel_mc_bidir_rpf_hash_table")
    table tunnel_mc_bidir_rpf_hash_table {
        actions = {
            set_tunnel_mc_group_bidir_rpf_pass;
            @default_only NoAction;
        }
        key = {
            meta.ig_tunnel.mc_group_rpf_en         : exact;
            meta.ig_tunnel.mc_group_bidir          : exact;
            meta.ig_tunnel.mc_group_rpf_bd_or_group: exact;
            meta.ingress.outer_src_bd              : exact;
        }
	size = TUNNEL_MC_RPF_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        if (meta.ig_tunnel.mc_group_lookup_hit == 1) {
            if (meta.ig_tunnel.mc_group_bidir == 1) {
                // Bidir RPF
                tunnel_mc_bidir_rpf_hash_table.apply();
            } else if (meta.ig_tunnel.mc_sg_lookup_hit == 1 &&
                       meta.ig_tunnel.mc_sg_rpf_bd == meta.ingress.outer_src_bd)
            {
                // S,G hit + S,G RPF Pass
                meta.ig_tunnel.mc_rpf_pass = TRUE;
                meta.ig_tunnel.mc_sg_rpf_pass = TRUE;
            } else if (meta.ig_tunnel.mc_group_rpf_bd_or_group ==
                       meta.ingress.outer_src_bd)
            {
                // *,G RPF pass
                meta.ig_tunnel.mc_rpf_pass = TRUE;
                meta.ig_tunnel.mc_group_rpf_pass = TRUE;
            }
        }
    }
}

control process_outer_pim_sup_key(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("outer_mcast_sup_filter_table0")
    register<bit<1>>(MCAST_SUP_FILTER_TABLE_SIZE) outer_mcast_sup_filter_table0;
    @name("outer_mcast_sup_filter_table1")
    register<bit<1>>(MCAST_SUP_FILTER_TABLE_SIZE) outer_mcast_sup_filter_table1;

    @name(".set_CFG_outer_mcast_sup_filter")
    action set_CFG_outer_mcast_sup_filter(bit<8> fixed0, bit<8> fixed1) {
        meta.outer_mcast_filter.fixed0 = fixed0;
        meta.outer_mcast_filter.fixed1 = fixed1;
    }
    @name("CFG_outer_mcast_sup_filter")
    table CFG_outer_mcast_sup_filter {
        actions = {
            set_CFG_outer_mcast_sup_filter;
            @default_only NoAction;
        }
        default_action = NoAction();
    }

    @name(".outer_pim_sup_action")
    action outer_pim_sup_action(bit<4> pim_bloom_filter_rcode,
                                bit<1> pim_bloom_filter_en,
                                bit<4> pim_acl_key)
    {
        meta.ig_tunnel.pim_bloom_filter_rcode = pim_bloom_filter_rcode;
        meta.ig_tunnel.pim_bloom_filter_en = pim_bloom_filter_en;
        meta.ig_tunnel.pim_acl_key = pim_acl_key;
    }
    @name("outer_pim_sup_conditions")
    table outer_pim_sup_conditions {
        actions = {
            outer_pim_sup_action;
            @default_only NoAction;
        }
        key = {
            meta.ig_tunnel.sup_copy            : ternary;
            meta.ig_tunnel.mc_group_lookup_hit : ternary;
            meta.ig_tunnel.mc_sg_lookup_hit    : ternary;
            meta.ig_tunnel.mc_rpf_pass         : ternary;
            meta.ig_tunnel.mc_sg_rpf_pass      : ternary;
            meta.src_tep.dcs                   : ternary;
            meta.ig_tunnel.rpf_fail_send_to_sup: ternary;
            meta.ig_tunnel.no_dc_sup_redirect  : ternary;
        }
        size = 32;
        default_action = NoAction();
    }
    apply {
        if (meta.ig_tunnel.decap == 1 && meta.ig_tunnel.mc_tunnel_decap == 1) {
            // Filter conditions
            outer_pim_sup_conditions.apply();
            // Bloom filter keys
            meta.outer_mcast_filter.rcode =
                meta.ig_tunnel.pim_bloom_filter_rcode;
            if (meta.ig_tunnel.mc_rpf_pass == 0) {
                meta.outer_mcast_filter.bd = meta.ingress.outer_src_bd;
            }
            if (meta.ig_tunnel.mc_sg_lookup_hit == 1) {
                meta.outer_mcast_filter.hit_addr =
                    meta.ig_tunnel.mc_sg_hit_addr;
            } else if (meta.ig_tunnel.mc_group_lookup_hit == 1) { // default_entry is not used here
                meta.outer_mcast_filter.hit_addr =
                    meta.ig_tunnel.mc_group_hit_addr;
            }
            // Config table
            CFG_outer_mcast_sup_filter.apply();
            // Hash generation
            hash(meta.outer_mcast_filter.hash0, HashAlgorithm.crc16,
                 (bit<14>) 0,
                 { meta.outer_mcast_filter.fixed0,
                   meta.outer_mcast_filter.rcode,
                   meta.outer_mcast_filter.bd,
                   meta.outer_mcast_filter.hit_addr },
                 (bit<28>) 16384);
            hash(meta.hash.hash1, HashAlgorithm.crc16,
                 (bit<14>) 0,
                 { meta.outer_mcast_filter.fixed1,
                   meta.outer_mcast_filter.rcode,
                   meta.outer_mcast_filter.bd,
                   meta.outer_mcast_filter.hit_addr },
                 (bit<28>) 16384);
            // Read Hit bits
            outer_mcast_sup_filter_table0.read(meta.outer_mcast_filter.hit0,
                                               (bit<32>) meta.outer_mcast_filter.hash0);
            outer_mcast_sup_filter_table1.read(meta.outer_mcast_filter.hit1,
                                               (bit<32>) meta.outer_mcast_filter.hash1);
            // Check if bloom filter was hit
            if (meta.outer_mcast_filter.hit0 == 1 &&
                meta.outer_mcast_filter.hit1 == 1 &&
                meta.ig_tunnel.pim_bloom_filter_en == 1)
            {
                // update hit bits
                outer_mcast_sup_filter_table0.write((bit<32>) meta.outer_mcast_filter.hash0,
                                                    (bit<1>) 1);
                outer_mcast_sup_filter_table1.write((bit<32>) meta.outer_mcast_filter.hash1,
                                                    (bit<1>) 1);
            } else {
                meta.ig_tunnel.pim_acl_key = 0;
            }
            // Zero out sup acl key field
        }
    }
}

/*****************************************************************************/
/* Replace outer metadata fields with inner */
/*****************************************************************************/

/* Termination Cases */
/* L2 -> non-ip, ipv4, ipv6, fcoe */
/* L3 -> v4, v6, mpls */

//action set_tunnel_l2_payload() {
    //    copy_header(ethernet_header, inner_ethernet_header);
    //    copy_header(cmd_header, inner_cmd_header);
    //    
    //    modify_field(l2_metadata.lkp_mac_sa, inner_ethernet_header.srcAddr);
    //    modify_field(l2_metadata.lkp_mac_da, inner_ethernet_header.dstAddr);
    //    //    modify_field(l2_metadata.lkp_mac_type, inner_ethernet_header.etherType);
    //}
//
//table dummy_tunnel_decap_l2_header {
    //    actions {
	//	/* Termination Cases */
	//	/* L2 -> non-ip, ipv4, ipv6, fcoe */
	//	/* L3 -> v4, v6, mpls */
	//	set_tunnel_l2_payload;
	//	/*TODO l3_mpls */
	//    }
    //    size = 0;
    //}
//

action set_tunnel_decap_non_ip_payload(inout headers hdr, inout metadata meta) {
    meta.l3.l3_type = L3TYPE_NONE;
}

action set_tunnel_decap_fcoe_payload(inout headers hdr, inout metadata meta) {
    /* TODO */
}

action set_tunnel_decap_ipv4_payload(inout headers hdr, inout metadata meta) {
    //meta.qos.outer_dscp = meta.l3.lkp_ip_tc;
    meta.l3.l3_type = L3TYPE_IPV4;
    meta.ipv4m.lkp_ipv4_sa = hdr.inner_ipv4.srcAddr;
    meta.ipv4m.lkp_ipv4_da = hdr.inner_ipv4.dstAddr;
    meta.l3.lkp_ip_version = hdr.inner_ipv4.version;
    meta.ig_qos.inner_dscp = hdr.inner_ipv4.dscp;
    meta.ig_qos.inner_ecn = hdr.inner_ipv4.ecn;
    // // Copy and store outer DSCP for later use
    //meta.ig_qos.outer_dscp = hdr.ipv4.dscp;
    //meta.ig_qos.outer_ecn = hdr.ipv4.ecn;
    meta.l3.lkp_ip_proto = hdr.inner_ipv4.protocol;
    meta.l3.lkp_ip_ttl = hdr.inner_ipv4.ttl;
    meta.ig_tunnel.encap_ip_len = hdr.inner_ipv4.totalLen;
    /*TODO    meta.l3.lkp_ip_tc = hdr.inner_ipv4.diffserv; */
    meta.l3.lkp_l4_sport = meta.l3.lkp_inner_l4_sport;
    meta.l3.lkp_l4_dport = meta.l3.lkp_inner_l4_dport;
}

action set_tunnel_decap_ipv6_payload(inout headers hdr, inout metadata meta) {
    //meta.qos.outer_dscp = meta.l3.lkp_ip_tc;
    meta.l3.l3_type = L3TYPE_IPV6;
    meta.ipv6m.lkp_ipv6_sa = hdr.inner_ipv6.srcAddr;
    meta.ipv6m.lkp_ipv6_da = hdr.inner_ipv6.dstAddr;
    meta.l3.lkp_ip_version = hdr.inner_ipv6.version;
    meta.ig_qos.inner_dscp = hdr.inner_ipv6.dscp;
    meta.ig_qos.inner_ecn = hdr.inner_ipv6.ecn;
    /// Copy and store outer DSCP for later use
    //meta.ig_qos.outer_dscp = hdr.ipv6.dscp;
    //meta.ig_qos.outer_ecn = hdr.ipv6.ecn;
    meta.l3.lkp_ip_proto = hdr.inner_ipv6.nextHeader;
    meta.l3.lkp_ip_ttl = hdr.inner_ipv6.hopLimit;
    meta.ig_tunnel.encap_ip_len = hdr.inner_ipv6.payloadLen;
    /*TODO    meta.l3.lkp_ip_tc = hdr.inner_ipv6.diffserv; */
    meta.l3.lkp_l4_sport = meta.l3.lkp_inner_l4_sport;
    meta.l3.lkp_l4_dport = meta.l3.lkp_inner_l4_dport;
}

// TBDP416 - currently not called from anywhere.  It is not called
// from anywhere in the original P4_14 code, either.  Should it be?
control process_ig_tunnel_decap_ops(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("process_outer_pim_sup_key") process_outer_pim_sup_key() process_outer_pim_sup_key_1;
    apply {
	// ~~~~~~~~~~~~ Decap rewrite  ~~~~~~~~~~~~~~~ 
        if (meta.ig_tunnel.decap == 1) {
	    /* Replace outer with inner */
            if (hdr.inner_ethernet.isValid()) {
		//hdr.ethernet = hdr.inner_ethernet;
		meta.l2.lkp_mac_sa = hdr.inner_ethernet.srcAddr;
		meta.l2.lkp_mac_da = hdr.inner_ethernet.dstAddr;
		if (hdr.inner_qtag0.isValid()) {
                    hdr.qtag0 = hdr.inner_qtag0;
                }
		if (hdr.inner_qtag1.isValid()) {
                    hdr.qtag1 = hdr.inner_qtag1;
                }
		if (hdr.inner_cmd.isValid()) {
                    hdr.cmd = hdr.inner_cmd;
                }
		if (hdr.inner_cmd_sgt.isValid()) {
                    hdr.cmd_sgt = hdr.inner_cmd_sgt;
                }
		//TODO : timestamp
            }
	    if (hdr.inner_ipv4.isValid()) {
                set_tunnel_decap_ipv4_payload(hdr, meta);
            } else if (hdr.inner_ipv6.isValid()) {
                set_tunnel_decap_ipv6_payload(hdr, meta);
            } else if (hdr.inner_fcoe.isValid()) {
                set_tunnel_decap_fcoe_payload(hdr, meta);
            } else {
                set_tunnel_decap_non_ip_payload(hdr, meta);
            }

	    // Copy inner header information to outer
	    //	modify_field(l3.l3_type,    l3.inner_l3_type);
	    meta.l3.ip_da_type = meta.l3.inner_ip_da_type;
	    meta.l3.ip_sa_type = meta.l3.inner_ip_sa_type;
	    meta.l3.nd_type = meta.l3.inner_nd_type;
	    meta.l3.arp_type = meta.l3.inner_arp_type;
	    meta.l3.nd_ta_ll = meta.l3.inner_nd_ta_ll;
	    meta.l2.l2_da_type = meta.l2.inner_l2_da_type;

	    meta.ig_tunnel.src_sh_group = meta.src_tep.src_sh_group;

	    /* Handle Multicast sup cases, if needed */
            if (meta.l3.ip_da_type == IP_MULTICAST) {
                process_outer_pim_sup_key_1.apply(hdr, meta, standard_metadata);
            }

	    /* ~~~~~ check for outer gipo, inner uc ~~~~~~~ */
	    if ((meta.ig_tunnel.decap == 1) &&
                (meta.ig_tunnel.mc_tunnel_decap == 1) &&
                (meta.l2.l2_da_type == L2_UNICAST))
            {
		meta.ig_tunnel.encap_flood = TRUE;
	    } else {
		meta.ig_tunnel.encap_flood = FALSE;
	    }
        }
    }
}

/*****************************************************************************/
/* Decide on Tunnel termination */
/*****************************************************************************/

action set_uc_l2_tunnel_decap(inout metadata meta) {
    meta.ig_tunnel.decap = TRUE;
    meta.ig_tunnel.l3_tunnel_decap = FALSE;
    meta.ig_tunnel.mc_tunnel_decap = FALSE;
}

action set_uc_l3_tunnel_decap(inout metadata meta) {
    meta.ig_tunnel.decap = TRUE;
    meta.ig_tunnel.l3_tunnel_decap = TRUE;
    meta.ig_tunnel.mc_tunnel_decap = FALSE;
}

action set_mc_l2_tunnel_decap(inout metadata meta) {
    meta.ig_tunnel.decap = TRUE;
    meta.ig_tunnel.l3_tunnel_decap = FALSE;
    meta.ig_tunnel.mc_tunnel_decap = TRUE;
}

action set_mc_l3_tunnel_decap(inout metadata meta) {
    meta.ig_tunnel.decap = TRUE;
    meta.ig_tunnel.l3_tunnel_decap = TRUE;
    meta.ig_tunnel.mc_tunnel_decap = TRUE;
}

/* TODO : Add src_tep_miss drop and sup_redirect actions */
//action set_src_tep_miss_sup_redirect() {
//}

action set_src_tep_miss_drop(inout metadata meta) {
    meta.ig_drop.src_tep_miss = TRUE;
    //meta.ig_drop.inc_drop_counters = TRUE;
}

control process_ig_tunnel_decap_decision(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".erspan_term_decap") action erspan_term_decap(bit<13> dst_idx) {
        meta.ingress.dst_ptr_or_idx = dst_idx;
        meta.ingress.dst_is_ptr = FALSE;
        meta.ig_tunnel.erspan_term = TRUE;
        meta.ig_tunnel.erspan_term_decap = TRUE;
    }
    @name(".erspan_term") action erspan_term(bit<13> dst_idx) {
        meta.ingress.dst_ptr_or_idx = dst_idx;
        meta.ingress.dst_is_ptr = FALSE;
        meta.ig_tunnel.erspan_term = TRUE;
        meta.ig_tunnel.erspan_term_decap = FALSE;
        //TODO : apply bypass logic here
    }
    @name(".ipv4_dst_tep_hit") action ipv4_dst_tep_hit() {
        meta.ig_tunnel.dst_tep_hit = TRUE;
    }
    @name(".ipv4_src_tep_hit")
    action ipv4_src_tep_hit(bit<1> lkup_hit,
//#ifdef ACI_TOR_MODE
                            bit<1> trust_sclass,
                            bit<1> trust_dl, bit<1> rw_mark,
                            bit<1> keep_mark, bit<1> analytics_en,
                            bit<1> flow_collect_en, bit<1> ip_learn_en,
                            bit<1> sclass_learn_en, bit<1> ivxlan_dl,
                            bit<1> trust_tstmp,
//#else  /*ACI_TOR_MODE*/
                            bit<13> if_idx,
                            bit<1> l3_tunnel,
                            bit<1> pop_2_labels,
                            bit<1> force_hash_df,
                            bit<14> inner_bd,
//#endif /*ACI_TOR_MODE*/
                            bit<1> is_vpc_peer,
                            bit<1> mac_learn_en, bit<1> trust_cos,
                            bit<1> tstats_path, bit<1> dcs,
                            bit<1> drop, bit<4> src_sh_group, bit<13> src_ptr)
    {
        meta.src_tep.lkup_hit = lkup_hit;
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.src_tep.trust_sclass = trust_sclass;
            meta.src_tep.trust_dl = trust_dl;
            meta.src_tep.rw_mark = rw_mark;
            meta.src_tep.keep_mark = keep_mark;
            meta.src_tep.analytics_en = analytics_en;
            meta.src_tep.flow_collect_en = flow_collect_en;
            meta.src_tep.ip_learn_en = ip_learn_en;
            meta.src_tep.sclass_learn_en = sclass_learn_en;
            meta.src_tep.ivxlan_dl = ivxlan_dl;
            meta.src_tep.trust_tstmp = trust_tstmp;
//#else  /*ACI_TOR_MODE*/
        } else {
            meta.src_tep.if_idx = if_idx;
            meta.src_tep.l3_tunnel = l3_tunnel;
            meta.src_tep.pop_2_labels = pop_2_labels;
            meta.src_tep.force_hash_df = force_hash_df;
            meta.src_tep.inner_bd = inner_bd;
        }
//#endif /*ACI_TOR_MODE*/
        meta.src_tep.is_vpc_peer = is_vpc_peer;
        meta.src_tep.mac_learn_en = mac_learn_en;
        meta.src_tep.trust_cos = trust_cos;
        meta.src_tep.tstats_path = tstats_path;
        meta.src_tep.dcs = dcs;
        meta.src_tep.drop = drop;
        meta.src_tep.src_sh_group = src_sh_group;
        meta.src_tep.src_ptr = src_ptr;
    }
    @name(".ipv6_dst_tep_hit") action ipv6_dst_tep_hit() {
        meta.ig_tunnel.dst_tep_hit = TRUE;
    }
    @name(".ipv6_src_tep_hit")
    action ipv6_src_tep_hit(bit<1> lkup_hit,
//#ifdef ACI_TOR_MODE
                            bit<1> trust_sclass,
                            bit<1> trust_dl, bit<1> rw_mark,
                            bit<1> keep_mark, bit<1> analytics_en,
                            bit<1> flow_collect_en, bit<1> ip_learn_en,
                            bit<1> sclass_learn_en, bit<1> ivxlan_dl,
                            bit<1> trust_tstmp,
//#else  /*ACI_TOR_MODE*/
                            bit<13> if_idx,
                            bit<1> l3_tunnel,
                            bit<1> pop_2_labels,
                            bit<1> force_hash_df,
                            bit<14> inner_bd,
//#endif /*ACI_TOR_MODE*/
                            bit<1> is_vpc_peer,
                            bit<1> mac_learn_en, bit<1> trust_cos,
                            bit<1> tstats_path, bit<1> dcs,
                            bit<1> drop, bit<4> src_sh_group,
                            bit<13> src_ptr)
    {
        meta.src_tep.lkup_hit = lkup_hit;
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.src_tep.trust_sclass = trust_sclass;
            meta.src_tep.trust_dl = trust_dl;
            meta.src_tep.rw_mark = rw_mark;
            meta.src_tep.keep_mark = keep_mark;
            meta.src_tep.analytics_en = analytics_en;
            meta.src_tep.flow_collect_en = flow_collect_en;
            meta.src_tep.ip_learn_en = ip_learn_en;
            meta.src_tep.sclass_learn_en = sclass_learn_en;
            meta.src_tep.ivxlan_dl = ivxlan_dl;
            meta.src_tep.trust_tstmp = trust_tstmp;
//#else  /*ACI_TOR_MODE*/
        } else {
            meta.src_tep.if_idx = if_idx;
            meta.src_tep.l3_tunnel = l3_tunnel;
            meta.src_tep.pop_2_labels = pop_2_labels;
            meta.src_tep.force_hash_df = force_hash_df;
            meta.src_tep.inner_bd = inner_bd;
//#endif /*ACI_TOR_MODE*/
        }
        meta.src_tep.is_vpc_peer = is_vpc_peer;
        meta.src_tep.mac_learn_en = mac_learn_en;
        meta.src_tep.trust_cos = trust_cos;
        meta.src_tep.tstats_path = tstats_path;
        meta.src_tep.dcs = dcs;
        meta.src_tep.drop = drop;
        meta.src_tep.src_sh_group = src_sh_group;
        meta.src_tep.src_ptr = src_ptr;
    }
    @name(".src_vnid_xlate_hit")
    action src_vnid_xlate_hit(bit<14> src_vnid_bd) {
        meta.ig_tunnel.src_vnid_xlate_hit = TRUE;
        meta.ig_local.inner_src_bd = src_vnid_bd;
    }
    @name(".src_vnid_xlate_miss")
    action src_vnid_xlate_miss() {
        meta.ig_tunnel.src_vnid_xlate_hit = FALSE;
    }
    @name("erspan_term") table erspan_term_0 {
        actions = {
            erspan_term_decap;
            erspan_term;
            @default_only NoAction;
        }
        key = {
            meta.ig_tunnel.erspan_session: ternary;
            meta.src_tep.src_ptr         : ternary;
        }
        size = ERSPAN_TERM_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("ipv4_dst_vtep") table ipv4_dst_vtep {
        actions = {
            ipv4_dst_tep_hit;
            @default_only NoAction;
        }
        key = {
            meta.outer_src_bd.vrf        : ternary;
            meta.ipv4m.lkp_ipv4_da        : ternary;
            meta.ig_tunnel.src_encap_type: ternary;
        }
	size = IPV4_DST_TEP_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("ipv4_src_vtep_hash_table") table ipv4_src_vtep_hash_table {
        actions = {
            ipv4_src_tep_hit;
            @default_only NoAction;
        }
        key = {
            meta.outer_src_bd.vrf: exact;
            meta.ipv4m.lkp_ipv4_sa: exact;
        }
	size = IPV4_SRC_TEP_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("ipv6_dst_vtep") table ipv6_dst_vtep {
        actions = {
            ipv6_dst_tep_hit;
            @default_only NoAction;
        }
        key = {
            meta.outer_src_bd.vrf        : ternary;
            meta.ipv6m.lkp_ipv6_da        : ternary;
            meta.ig_tunnel.src_encap_type: ternary;
        }
	size = IPV6_DST_TEP_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("ipv6_src_vtep_hash_table") table ipv6_src_vtep_hash_table {
        actions = {
            ipv6_src_tep_hit;
            @default_only NoAction;
        }
        key = {
            meta.outer_src_bd.vrf: exact;
            meta.ipv6m.lkp_ipv6_sa: exact;
        }
	size = IPV6_SRC_TEP_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("src_vnid_xlate_hash_table") table src_vnid_xlate_hash_table {
        actions = {
            src_vnid_xlate_hit;
            src_vnid_xlate_miss;
            @default_only NoAction;
        }
        key = {
            meta.ig_tunnel.src_vnid      : exact;
            meta.ig_tunnel.src_encap_type: exact;
//#ifdef ACI_TOR_MODE
            meta.outer_src_bd.vrf        : exact;
//#else  /*ACI_TOR_MODE*/
            meta.src_tep.bd_xlate_idx    : exact;
//#endif /*ACI_TOR_MODE*/
        }
	size = SRC_VNID_XLATE_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("process_aci_ftag") process_aci_ftag() process_aci_ftag_0;
//#ifdef ACI_TOR_MODE
    @name("process_outer_pim_sup_key") process_outer_pim_sup_key() process_outer_pim_sup_key_0;
//#endif /*ACI_TOR_MODE*/
    @name("process_ipv4_tunnel_mcast") process_ipv4_tunnel_mcast() process_ipv4_tunnel_mcast_0;
    @name("process_ipv6_tunnel_mcast") process_ipv6_tunnel_mcast() process_ipv6_tunnel_mcast_0;
    @name("process_tunnel_mcast_rpf_check") process_tunnel_mcast_rpf_check() process_tunnel_mcast_rpf_check_0;
#ifndef DISABLE_MPLS
    @name("process_mpls_vpn_label") process_mpls_vpn_label() process_mpls_vpn_label_0;
#endif /*DISABLE_MPLS*/
    apply {
        if (meta.CFG_aci_tor_mode.enable == 1) {
            process_aci_ftag_0.apply(hdr, meta, standard_metadata);
        }

        // ~~~~~~ IP tunnel source address lookup ~~~~~~
        if (meta.l3.l3_type == L3TYPE_IPV4) {
            ipv4_src_vtep_hash_table.apply();
        } else if (meta.l3.l3_type == L3TYPE_IPV6) {
            ipv6_src_vtep_hash_table.apply();
        }

        // ~~~~~~ IP tunnel destination address lookup ~~~~~~
        //if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) {
        if (meta.l3.l3_type == L3TYPE_IPV4) {
            ipv4_dst_vtep.apply();
        } else if (meta.l3.l3_type == L3TYPE_IPV6) {
            ipv6_dst_vtep.apply();
        }
	//} else {
        if (meta.l3.l3_type == L3TYPE_IPV4) {
            process_ipv4_tunnel_mcast_0.apply(hdr, meta, standard_metadata);
        }
        else if (meta.l3.l3_type == L3TYPE_IPV6) {
            process_ipv6_tunnel_mcast_0.apply(hdr, meta, standard_metadata);
        }
        process_tunnel_mcast_rpf_check_0.apply(hdr, meta, standard_metadata);
	//}

        // ~~~~~~~ MPLS label lookup for L2/L3VPN ~~~~~~
#ifndef DISABLE_MPLS
        if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_MPLS) {
            // L2/L3 VPN. If TTL is zero, packet is not decapsulated
            process_mpls_vpn_label_0.apply(hdr, meta, standard_metadata);
        }
#endif /*DISABLE_MPLS*/

        if (meta.ig_tunnel.src_encap_type == ENCAP_TYPE_VXLAN ||
            meta.ig_tunnel.src_encap_type == ENCAP_TYPE_IVXLAN ||
            meta.ig_tunnel.src_encap_type == ENCAP_TYPE_VXLAN_GPE ||
            meta.ig_tunnel.src_encap_type == ENCAP_TYPE_GENEVE)
        {
            /* derive bd from vnid */
            if (!src_vnid_xlate_hash_table.apply().hit) {
		meta.ig_drop.vlan_xlate_miss = TRUE;
		//meta.ig_drop.inc_drop_counters = TRUE;
            }
        }

        /* ~~~~~~~~~ erspan termination ~~~~~~~ */
        erspan_term_0.apply();

        /* ~~~~~~~ Decide if IP tunnel is terminated here ~~~~~ */
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {

            if ((meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE &&
                 meta.ingress.met1_vld == 1 &&
                 meta.ig_tunnel.src_vnid_xlate_hit == 1) ||
                (meta.ig_tunnel.dst_tep_hit == 1 &&
                 meta.src_tep.lkup_hit == 1))
            {
                meta.ig_tunnel.decap = TRUE;
                meta.ingress.src_bd = meta.ig_local.inner_src_bd;
                /* Replace outer with inner */
                if (hdr.inner_ethernet.isValid()) {
                    //hdr.ethernet = hdr.inner_ethernet;
                    meta.l2.lkp_mac_sa = hdr.inner_ethernet.srcAddr;
                    meta.l2.lkp_mac_da = hdr.inner_ethernet.dstAddr;
                    if (hdr.inner_qtag0.isValid()) {
                        hdr.qtag0 = hdr.inner_qtag0;
                    }
                    if (hdr.inner_qtag1.isValid()) {
                        hdr.qtag1 = hdr.inner_qtag1;
                    }
                    if (hdr.inner_cmd.isValid()) {
                        hdr.cmd = hdr.inner_cmd;
                    }
                    if (hdr.inner_cmd_sgt.isValid()) {
                        hdr.cmd_sgt = hdr.inner_cmd_sgt;
                    }
                    //TODO : timestamp
                }
                if (hdr.inner_ipv4.isValid()) {
                    set_tunnel_decap_ipv4_payload(hdr, meta);
                } else if (hdr.inner_ipv6.isValid()) {
                    set_tunnel_decap_ipv6_payload(hdr, meta);
                } else if (hdr.inner_fcoe.isValid()) {
                    set_tunnel_decap_fcoe_payload(hdr, meta);
                } else {
                    set_tunnel_decap_non_ip_payload(hdr, meta);
                }
                
                // Copy inner header information to outer
                //meta.l3.l3_type = meta.l3.inner_l3_type;
                meta.l3.ip_da_type = meta.l3.inner_ip_da_type;
                meta.l3.ip_sa_type = meta.l3.inner_ip_sa_type;
                meta.l3.nd_type = meta.l3.inner_nd_type;
                meta.l3.arp_type = meta.l3.inner_arp_type;
                meta.l3.nd_ta_ll = meta.l3.inner_nd_ta_ll;
                meta.l2.l2_da_type = meta.l2.inner_l2_da_type;
                
                meta.ig_tunnel.src_sh_group = meta.src_tep.src_sh_group;
                
                /* Handle Multicast sup cases, if needed */
                if (meta.l3.ip_da_type == IP_MULTICAST) {
                    process_outer_pim_sup_key_0.apply(hdr, meta, standard_metadata);
                }
                
                /* ~~~~~ check for outer gipo, inner uc ~~~~~~~ */
                if ((meta.ig_tunnel.decap == 1) &&
                    (meta.ig_tunnel.mc_tunnel_decap == 1) &&
                    (meta.l2.l2_da_type == L2_UNICAST))
                {
                    meta.ig_tunnel.encap_flood = TRUE;
                } else {
                    meta.ig_tunnel.encap_flood = FALSE;
                }
                
                // Unicast or multicast tunnel
                if (meta.l3.ip_da_type == IP_MULTICAST) {
                    meta.ig_tunnel.mc_tunnel_decap = FALSE;
                } else {
                    meta.ig_tunnel.mc_tunnel_decap = TRUE;
                }
            }
//#else  /*ACI_TOR_MODE*/
        } else {
            if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) {
                if (meta.l3.ip_da_type == IP_MULTICAST) {
                    // if ((meta.l3.ip_da_type == IP_MULTICAST) && (meta.bypass_info.outer_mc_bypass == 0)) {
                    if (meta.ingress.met1_vld == 1) {
                        if (meta.ig_tunnel.l3_tunnel_decap == 1) {
                            set_mc_l3_tunnel_decap(meta);
                        } else {
                            if (meta.ig_tunnel.src_vnid_xlate_hit == 1) {
                            } else {
                                set_mc_l2_tunnel_decap(meta);
                            }
                        }
                    }
                } else if ((meta.ig_tunnel.dst_tep_hit == 1) ||
                           (meta.ig_tunnel.erspan_term == 1))
                {
                    if (meta.src_tep.lkup_hit == 1) {
                        if (meta.ig_tunnel.l3_tunnel_decap == 1) {
                            set_uc_l3_tunnel_decap(meta);
                        } else {
                            set_uc_l2_tunnel_decap(meta);
                        }
                    } else {
                        set_src_tep_miss_drop(meta);
                    }
                }
            }
//#endif /*ACI_TOR_MODE*/
        }
    }
}

/*****************************************************************************/
/* Post-tunnel decap BD derivation and BD properties */
/*****************************************************************************/

control process_src_bd_derivation(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_src_bd_profile") action set_src_bd_profile() {
//#ifdef ACI_TOR_MODE
//#endif /*ACI_TOR_MODE*/
    }
    @name("src_bd_profile") table src_bd_profile {
        actions = {
            set_src_bd_profile;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.bd_profile_idx: exact;
        }
	size = SRC_BD_PROFILE_TABLE_SIZE;
        default_action = NoAction();
    }

    @name(".set_src_bd_state")
    action set_src_bd_state(bit<14> bd, bit<14> vrf,
                            bit<16> acl_label, bit<10> rmac_index,
                            bit<1> ipv4_ucast_en, bit<1> ipv6_ucast_en,
                            bit<1> ipv4_mcast_en, bit<1> ipv6_mcast_en,
                            bit<1> igmp_snp_en, bit<1> mld_snp_en,
                            bit<2> ipv4_rpf_type, bit<2> ipv6_rpf_type,
                            bit<1> nat_inside_if, bit<1> nat_outside_if,
                            bit<1> nat_overload_fwd, bit<1> l3_bind_check_en,
                            bit<1> enforce_v6_link_local_uc,
                            bit<1> enforce_v6_link_local_mc,
                            bit<1> v4_omf, bit<1> v6_omf,
                            bit<1> route_bd, bit<1> qos_vld,
                            bit<7> qos_map_grp, bit<1> qos_map_use_dscp,
                            bit<1> qos_map_use_tc, bit<1> force_mac_sa_lkup,
                            bit<1> l2_bind_check_en, bit<1> is_l3_if,
                            bit<10> bd_profile_idx, bit<1> ecn_mark_en,
                            bit<2> ids_mask_sel, bit<1> fib_force_rpf_pass_en,
                            bit<1> encap_flood_fwd_lkup_en,
                            bit<1> encap_flood_fwd_rslt_en,
                            bit<1> encap_flood_outer_only_on_miss,
                            bit<1> flow_collect_en,
//#ifdef ACI_TOR_MODE
                            bit<1> unknown_uc_proxy,
                            bit<1> unknown_uc_flood, bit<5> spine_proxy_idx,
                            bit<1> normal_arp_nd_learn, bit<1> analytics_en,
                            bit<1> arp_nd_bd_crossing_dis, bit<14> epg,
                            bit<12> sg_label, bit<1> src_policy_applied,
                            bit<1> dst_policy_applied,
                            bit<1> src_policy_incomplete,
                            bit<1> dst_policy_incomplete,
                            bit<16> src_class, bit<16> service_idx,
                            bit<1> service_redir, bit<2> service_redir_pri,
                            bit<1> mac_learn_en, bit<1> ip_learn_en,
                            bit<1> sclass_learn_en, bit<1> ivxlan_dl,
                            bit<2> src_class_pri,
                            bit<1> arp_req_unicast_mode_dis,
                            bit<1> arp_res_unicast_mode_dis,
                            bit<1> garp_unicast_mode_dis,
                            bit<1> rarp_req_unicast_mode_dis,
                            bit<1> rarp_res_unicast_mode_dis,
                            bit<1> uc_nd_sol_unicast_mode_dis,
                            bit<1> mc_nd_adv_unicast_mode_dis,
//#else  /*ACI_TOR_MODE*/
                            bit<14> fid,
                            bit<1> ftag_uu_flood_ctl_v4_en,
                            bit<1> ftag_uu_flood_ctl_v6_en,
                            bit<1> mpls_ignore_self_fwd_check,
                            bit<1> allow_fc_l4_multi_path,
                            bit<1> enabled_on_mct,
                            bit<1> fabric_copy_en,
                            bit<1> qinq_core,
                            bit<1> drop_mpls
//#endif /*ACI_TOR_MODE*/
                            )
    {
        meta.ingress.src_bd = bd;
        meta.src_bd.vrf = vrf;
        meta.src_bd.acl_label = acl_label;
        meta.src_bd.rmac_index = rmac_index;
        meta.src_bd.ipv4_ucast_en = ipv4_ucast_en;
        meta.src_bd.ipv6_ucast_en = ipv6_ucast_en;
        meta.src_bd.ipv4_mcast_en = ipv4_mcast_en;
        meta.src_bd.ipv6_mcast_en = ipv6_mcast_en;
        meta.src_bd.igmp_snp_en = igmp_snp_en;
        meta.src_bd.mld_snp_en = mld_snp_en;
        meta.src_bd.ipv4_rpf_type = ipv4_rpf_type;
        meta.src_bd.ipv6_rpf_type = ipv6_rpf_type;
        meta.src_bd.nat_inside_if = nat_inside_if;
        meta.src_bd.nat_outside_if = nat_outside_if;
        meta.src_bd.nat_overload_fwd = nat_overload_fwd;
        meta.src_bd.l3_bind_check_en = l3_bind_check_en;
        meta.src_bd.enforce_v6_link_local_uc = enforce_v6_link_local_uc;
        meta.src_bd.enforce_v6_link_local_mc = enforce_v6_link_local_mc;
        meta.src_bd.v4_omf = v4_omf;
        meta.src_bd.v6_omf = v6_omf;
        meta.src_bd.route_bd = route_bd;
        meta.src_bd.qos_vld = qos_vld;
        meta.src_bd.qos_map_grp = qos_map_grp;
        meta.src_bd.qos_map_use_dscp = qos_map_use_dscp;
        meta.src_bd.qos_map_use_tc = qos_map_use_tc;
        meta.src_bd.force_mac_sa_lkup = force_mac_sa_lkup;
        meta.src_bd.l2_bind_check_en = l2_bind_check_en;
        meta.src_bd.is_l3_if = is_l3_if;
        meta.src_bd.bd_profile_idx = bd_profile_idx;
        meta.src_bd.ecn_mark_en = ecn_mark_en;
        meta.src_bd.ids_mask_sel = ids_mask_sel;
        meta.src_bd.fib_force_rpf_pass_en = fib_force_rpf_pass_en;
        meta.src_bd.encap_flood_fwd_lkup_en = encap_flood_fwd_lkup_en;
        meta.src_bd.encap_flood_fwd_rslt_en = encap_flood_fwd_rslt_en;
        meta.src_bd.encap_flood_outer_only_on_miss = encap_flood_outer_only_on_miss;
        meta.src_bd.flow_collect_en = flow_collect_en;
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.src_bd.unknown_uc_proxy = unknown_uc_proxy;
            meta.src_bd.unknown_uc_flood = unknown_uc_flood;
            meta.src_bd.spine_proxy_idx = spine_proxy_idx;
            meta.src_bd.normal_arp_nd_learn = normal_arp_nd_learn;
            meta.src_bd.analytics_en = analytics_en;
            meta.src_bd.arp_nd_bd_crossing_dis = arp_nd_bd_crossing_dis;
            meta.ingress.src_epg = epg;
            meta.src_bd.sg_label = sg_label;
            meta.src_bd.src_policy_applied = src_policy_applied;
            meta.src_bd.dst_policy_applied = dst_policy_applied;
            meta.src_bd.src_policy_incomplete = src_policy_incomplete;
            meta.src_bd.dst_policy_incomplete = dst_policy_incomplete;
            meta.src_bd.src_class = src_class;
            // TODO maybe_wrong_cast
            meta.src_bd.service_idx = (bit<12>) service_idx;
            meta.src_bd.service_redir = service_redir;
            meta.src_bd.service_redir_pri = service_redir_pri;
            meta.src_bd.mac_learn_en = mac_learn_en;
            meta.src_bd.ip_learn_en = ip_learn_en;
            meta.src_bd.sclass_learn_en = sclass_learn_en;
            meta.src_bd.ivxlan_dl = ivxlan_dl;
            meta.src_bd.src_class_pri = src_class_pri;
            meta.src_bd.arp_req_unicast_mode_dis = arp_req_unicast_mode_dis;
            meta.src_bd.arp_res_unicast_mode_dis = arp_res_unicast_mode_dis;
            meta.src_bd.garp_unicast_mode_dis = garp_unicast_mode_dis;
            meta.src_bd.rarp_req_unicast_mode_dis = rarp_req_unicast_mode_dis;
            meta.src_bd.rarp_res_unicast_mode_dis = rarp_res_unicast_mode_dis;
            meta.src_bd.uc_nd_sol_unicast_mode_dis = uc_nd_sol_unicast_mode_dis;
            meta.src_bd.mc_nd_adv_unicast_mode_dis = mc_nd_adv_unicast_mode_dis;
            meta.pt_key.dst_class = src_class;
            meta.pt_key.dst_policy_applied = dst_policy_applied;
            meta.pt_key.dst_policy_incomplete = dst_policy_incomplete;
            meta.service_redir.vld = service_redir;
            meta.service_redir.idx = service_idx;
            meta.service_redir.pri = service_redir_pri;
            //meta.service_redir.override_route = 0;
//#else  /*ACI_TOR_MODE*/
        } else {
            meta.src_bd.fid = fid;
            meta.src_bd.ftag_uu_flood_ctl_v4_en = ftag_uu_flood_ctl_v4_en;
            meta.src_bd.ftag_uu_flood_ctl_v6_en = ftag_uu_flood_ctl_v6_en;
            meta.src_bd.mpls_ignore_self_fwd_check = mpls_ignore_self_fwd_check;
            meta.src_bd.allow_fc_l4_multi_path = allow_fc_l4_multi_path;
            meta.src_bd.enabled_on_mct = enabled_on_mct;
            meta.src_bd.fabric_copy_en = fabric_copy_en;
            meta.src_bd.qinq_core = qinq_core;
            meta.src_bd.drop_mpls = drop_mpls;
//#endif /*ACI_TOR_MODE*/
        }
    }
    @name("src_bd_state") table src_bd_state {
        actions = {
            set_src_bd_state;
            @default_only NoAction;
        }
        key = {
            meta.ingress.src_bd: exact;
        }
	size = SRC_BD_STATE_TABLE_SIZE;
        default_action = NoAction();
    }

    apply {
        if (meta.ig_tunnel.decap == 1) {
//#ifdef ACI_TOR_MODE
            if (meta.CFG_aci_tor_mode.enable == 1) {
                //meta.ingress.src_bd = meta.ig_local.inner_src_bd; // done in tunnel_decap.p4
//#else  /*ACI_TOR_MODE*/
            } else {
                if ((meta.ig_tunnel.src_encap_type == ENCAP_TYPE_ERSPAN2) || 
                    (meta.ig_tunnel.src_encap_type == ENCAP_TYPE_ERSPAN3))
                {
                    /* no need to derive bd */
                    meta.ingress.src_bd = 0;
                    //meta.ig_tunnel.inner_src_bd = 0;
                } else {
                    if ((meta.ig_tunnel.src_encap_type == ENCAP_TYPE_GRE) || 
                        (meta.ig_tunnel.src_encap_type == ENCAP_TYPE_IP_IN_IP) || 
                        (meta.ig_tunnel.src_encap_type == ENCAP_TYPE_MPLS_L3VPN) || 
                        (meta.ig_tunnel.src_encap_type == ENCAP_TYPE_MPLS_OVER_GRE))
                    {
                        /* derive inner bd from src_tep */
                        meta.ingress.src_bd = meta.src_tep.inner_bd;
                        //meta.ig_tunnel.inner_src_bd = meta.src_tep.inner_bd;
                    }
                    
                    if ((meta.ig_tunnel.src_encap_type == ENCAP_TYPE_DCE) || 
                        (meta.ig_tunnel.src_encap_type == ENCAP_TYPE_MPLS_L2VPN) || 
                        (meta.ig_tunnel.src_encap_type == ENCAP_TYPE_VPLS_OVER_GRE))
                    {
                        /* derive inner bd from inner {inner_vlan, [vc_label]} */
                        /* TODO     inner_vlan_xlate.apply(); */
                    }
                    // TBD - the original P4_14 code had the following
                    // 'else' after the 'else' at the same nesting level
                    // above, which is not a legal program.  I'm not sure
                    // what these two cases should be yet, so for now just
                    // commenting out the one below.
                    //} else {
                    //    meta.ingress.src_bd = meta.ig_local.inner_src_bd;
                }
//#endif /*ACI_TOR_MODE*/
            }
        }

	/* Derive inner BD state */
        src_bd_state.apply();

	// per-BD/EPG packet counters
#ifndef DISABLE_SRC_BD_STATS
	//count(src_bd_stats, meta.src_bd.bd_stats_idx);
#endif /*DISABLE_SRC_BD_STATS*/

        src_bd_profile.apply();
    }
}

control process_post_tunnel_decap_fwd_mode(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

#ifdef USE_TABLE_FOR_FWD_MODE
    @name(".set_post_tunnel_decap_l2_fwd_mode")
    action set_post_tunnel_decap_l2_fwd_mode(bit<2> l2_mode,
                                             bit<1> encap_flood_fwd_lkup,
                                             bit<1> arp_unicast_mode,
                                             bit<1> rarp_unicast_mode,
                                             bit<1> nd_unicast_mode)
    {
        meta.ingress.l2_fwd_mode = l2_mode;
        meta.ig_tunnel.encap_flood_fwd_lkup = encap_flood_fwd_lkup;
        meta.l3.arp_unicast_mode = arp_unicast_mode;
        meta.l3.rarp_unicast_mode = rarp_unicast_mode;
        meta.l3.nd_unicast_mode = nd_unicast_mode;
    }
    @name(".set_post_tunnel_decap_l3_fwd_mode")
    action set_post_tunnel_decap_l3_fwd_mode(bit<2> l3_mode,
                                             bit<1> arp_unicast_mode,
                                             bit<1> rarp_unicast_mode,
                                             bit<1> nd_unicast_mode)
    {
        meta.ingress.l3_fwd_mode = l3_mode;
        meta.l3.arp_unicast_mode = arp_unicast_mode;
        meta.l3.rarp_unicast_mode = rarp_unicast_mode;
        meta.l3.nd_unicast_mode = nd_unicast_mode;
    }
    @name(".set_post_tunnel_decap_l2_l3_fwd_mode")
    action set_post_tunnel_decap_l2_l3_fwd_mode(bit<2> l2_mode,
                                                bit<2> l3_mode,
                                                bit<1> encap_flood_fwd_lkup,
                                                bit<1> arp_unicast_mode,
                                                bit<1> rarp_unicast_mode,
                                                bit<1> nd_unicast_mode)
    {
        meta.ingress.l2_fwd_mode = l2_mode;
        meta.ingress.l3_fwd_mode = l3_mode;
        meta.ig_tunnel.encap_flood_fwd_lkup = encap_flood_fwd_lkup;
        meta.l3.arp_unicast_mode = arp_unicast_mode;
        meta.l3.rarp_unicast_mode = rarp_unicast_mode;
        meta.l3.nd_unicast_mode = nd_unicast_mode;
    }
    @name(".set_post_tunnel_decap_ttl_expired_drop")
    action set_post_tunnel_decap_ttl_expired_drop() {
        meta.ig_drop.ttl_expired = TRUE;
	//meta.ig_drop.inc_drop_counters = TRUE;
	//meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
    }
#ifndef DISABLE_MPLS
    @name(".set_post_tunnel_decap_mpls_disabled_drop")
    action set_post_tunnel_decap_mpls_disabled_drop() {
	meta.ig_drop.mpls_disabled = TRUE;
	//meta.ig_drop.inc_drop_counters = TRUE;
	//meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
    }
#endif /*DISABLE_MPLS*/
    @name(".set_post_tunnel_decap_routing_disabled_drop")
    action set_post_tunnel_decap_routing_disabled_drop() {
        meta.ig_drop.routing_disabled = TRUE;
	//meta.ig_drop.inc_drop_counters = TRUE;
	//meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
    }
    @name("post_tunnel_decap_fwd_mode") table post_tunnel_decap_fwd_mode {
        actions = {
            set_post_tunnel_decap_l2_fwd_mode;
            set_post_tunnel_decap_l3_fwd_mode;
            set_post_tunnel_decap_l2_l3_fwd_mode;
            set_post_tunnel_decap_ttl_expired_drop;
#ifndef DISABLE_MPLS
	    set_post_tunnel_decap_mpls_disabled_drop;
#endif /*DISABLE_MPLS*/
            set_post_tunnel_decap_routing_disabled_drop;
            @default_only NoAction;
        }
        key = {
            meta.bypass_info.fwd_lookup_bypass    : ternary;
            meta.l2.l2_da_type                    : ternary;
            meta.l3.l3_type                       : ternary;
            meta.l3.ip_da_type                    : ternary;
            meta.l3.rmac_hit                      : ternary;
            meta.l3.nd_type                       : ternary;
            meta.src_bd.arp_req_unicast_mode_dis  : ternary;
            meta.src_bd.arp_res_unicast_mode_dis  : ternary;
            meta.src_bd.garp_unicast_mode_dis     : ternary;
            meta.src_bd.rarp_req_unicast_mode_dis : ternary;
            meta.src_bd.rarp_res_unicast_mode_dis : ternary;
            meta.src_bd.uc_nd_sol_unicast_mode_dis: ternary;
            meta.src_bd.mc_nd_adv_unicast_mode_dis: ternary;
            //meta.src_bd.arp_unicast_mode          : ternary;
            //meta.src_bd.rarp_unicast_mode         : ternary;
            //meta.src_bd.nd_unicast_mode           : ternary;
            ////meta.l3.arp_unicast_mode              : ternary;
            //meta.l3.rarp_unicast_mode             : ternary;
            //meta.l3.nd_unicast_mode               : ternary;
            meta.ig_tunnel.mc_tunnel_decap        : ternary;
            meta.ig_tunnel.encap_flood            : ternary;
            meta.src_bd.encap_flood_fwd_lkup_en   : ternary;
#ifndef DISABLE_MPLS
            meta.src_bd.mpls_en                   : ternary;
            meta.mplsm.topmost_non_null_label_ttl  : ternary;
#endif /*DISABLE_MPLS*/
            meta.src_bd.ipv4_ucast_en             : ternary;
            meta.src_bd.ipv4_mcast_en             : ternary;
            meta.src_bd.ipv6_ucast_en             : ternary;
            meta.src_bd.ipv6_mcast_en             : ternary;
            meta.l3.lkp_ip_ttl                    : ternary;
        }
	size = FWD_MODE_TABLE_SIZE;
        default_action = NoAction();
    }
#endif /*USE_TABLE_FOR_FWD_MODE*/

    apply {
#ifdef USE_TABLE_FOR_FWD_MODE
        post_tunnel_decap_fwd_mode.apply();
#else /*USE_TABLE_FOR_FWD_MODE*/

        if (meta.l3.l3_type == L3TYPE_MPLS) {
            if (meta.l3.rmac_hit == 1) {
                meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
		if (meta.src_bd.mpls_en == 1) {
		    if (meta.mplsm.topmost_non_null_label_ttl < 1 ) {
			// Note : TTL == 1 is allowed here because we
			// want to decap. For non-termination cases,
			// we can either drop it later in ingress
			// pipeline or on egress.
			meta.ig_drop.ttl_expired = TRUE;
			//meta.ig_drop.inc_drop_counters = TRUE;
			meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		    } else {    
			meta.ingress.l3_fwd_mode = L3_FWD_MODE_MPLS;
		    }
		} else {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		    meta.ig_drop.mpls_disabled = TRUE;
		    //meta.ig_drop.inc_drop_counters = TRUE;
		}
	    } else {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
		meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
	    }
//#ifdef ACI_TOR_MODE
	} else if (meta.CFG_aci_tor_mode.enable == 1 &&
                   (meta.l3.nd_unicast_mode == 1) ||
                   (meta.l3.arp_unicast_mode == 1))
        {
            meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
            meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
            // TODO : why was it marked as bridged packet	    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
        } else if (meta.CFG_aci_tor_mode.enable == 1 &&
                   meta.l3.rarp_unicast_mode == 1)
        {
            meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
            meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
//#endif /*ACI_TOR_MODE*/
        } else if (meta.l3.l3_type == L3TYPE_IPV4) {
	    if (meta.l3.ip_da_type == IP_MULTICAST) {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_MC;
		if ((meta.l3.ip_da_type == IP_MULTICAST_LL) ||
                    (meta.src_bd.ipv4_mcast_en == 0))
                {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		} else {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
		}
	    } else {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
		if (meta.l3.rmac_hit == 1) {
		    if (meta.src_bd.ipv4_ucast_en == 1) {
			if (meta.l3.lkp_ip_ttl < 1) {
			    meta.ig_drop.ttl_expired = TRUE;
			    //meta.ig_drop.inc_drop_counters = TRUE;
			    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
			} else {
			    meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
			}
		    } else {
			meta.ig_drop.routing_disabled = TRUE;
			//meta.ig_drop.inc_drop_counters = TRUE;
			meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		    }
		} else {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		}
	    }
	} else if (meta.l3.l3_type == L3TYPE_IPV6) {
	    if (meta.l3.ip_da_type == IP_MULTICAST) {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_MC;
		if ((meta.l3.ip_da_type == IP_MULTICAST_LL) ||
                    (meta.src_bd.ipv6_mcast_en == 0))
                {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		} else {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
		}
	    } else {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
		if (meta.l3.rmac_hit == 1) {
		    if (meta.src_bd.ipv6_ucast_en == 1) {
			if (meta.l3.lkp_ip_ttl < 1) {
			    meta.ig_drop.ttl_expired = TRUE;
			    //meta.ig_drop.inc_drop_counters = TRUE;
			    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
			} else {
			    meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
			}
		    } else {
			meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
			meta.ig_drop.routing_disabled = TRUE;
			//meta.ig_drop.inc_drop_counters = TRUE;
		    }
		} else {
		    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
		}
	    }
	} else {
	    meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
	    if (meta.l2.l2_da_type == L2_MULTICAST) {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_MC;
	    } else if (meta.l2.l2_da_type == L2_BROADCAST) {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_BC;
	    } else {
		meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
	    }
	}
#endif /*USE_TABLE_FOR_FWD_MODE*/
    }
}

control process_hashes(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    // TBD There are other ways of doing flowlets that need far fewer
    // bits of lasttime stored in a memory.  Should change this
    // implementation of flowlets to something better than this.
    register<bit<32>>(8192) flowlet_lasttime;
    register<bit<13>>(8192) flowlet_id;

    @name(".compute_ipv4_hash")
    action compute_ipv4_hash() {
        hash(meta.hash.hash1, HashAlgorithm.crc16,
             (bit<16>) 0,
             { meta.ipv4m.lkp_ipv4_sa,
               meta.ipv4m.lkp_ipv4_da,
               meta.l3.lkp_ip_proto,
               meta.l3.lkp_l4_sport,
               meta.l3.lkp_l4_dport },
             (bit<32>) 65536);
        hash(meta.hash.hash2, HashAlgorithm.crc16,
             (bit<16>) 0,
             { meta.l2.lkp_mac_sa,
               meta.l2.lkp_mac_da,
               meta.ipv4m.lkp_ipv4_sa,
               meta.ipv4m.lkp_ipv4_da,
               meta.l3.lkp_ip_proto,
               meta.l3.lkp_l4_sport,
               meta.l3.lkp_l4_dport },
             (bit<32>) 65536);
    }
    @name(".compute_ipv6_hash") action compute_ipv6_hash() {
        hash(meta.hash.hash1, HashAlgorithm.crc16,
             (bit<16>) 0,
             { meta.ipv6m.lkp_ipv6_sa,
               meta.ipv6m.lkp_ipv6_da,
               meta.l3.lkp_ip_proto,
               meta.l3.lkp_l4_sport,
               meta.l3.lkp_l4_dport },
             (bit<32>) 65536);
        hash(meta.hash.hash2, HashAlgorithm.crc16,
             (bit<16>) 0,
             { meta.l2.lkp_mac_sa,
               meta.l2.lkp_mac_da,
               meta.ipv6m.lkp_ipv6_sa,
               meta.ipv6m.lkp_ipv6_da,
               meta.l3.lkp_ip_proto,
               meta.l3.lkp_l4_sport,
               meta.l3.lkp_l4_dport },
             (bit<32>) 65536);
    }
    @name(".compute_non_ip_hash")
    action compute_non_ip_hash() {
        hash(meta.hash.hash2, HashAlgorithm.crc16,
             (bit<16>) 0,
             { meta.l2.lkp_mac_sa,
               meta.l2.lkp_mac_da },
             (bit<32>) 65536);
    }

    apply {
        bit<32> now;
        now = (bit<32>) meta.dp_ig_header.ingress_global_tstamp;

        if (meta.l3.l3_type == L3TYPE_IPV4) {
            compute_ipv4_hash();
        } else if (meta.l3.l3_type == L3TYPE_IPV6) {
            compute_ipv6_hash();
        } else {
            compute_non_ip_hash();
        }

        // Use flow hash to calculate index for flowlet id table
        // TODO : take care of non-ipv4 cases
        //hash(meta.hash.flowlet_map_index, HashAlgorithm.identity,
        //     0, { meta.hash.hash1 }, 8192);
        meta.hash.flowlet_map_index = meta.hash.hash1[12:0];
        
        // Read Flowlet ID
        flowlet_id.read(meta.hash.flowlet_id,
                        (bit<32>) meta.hash.flowlet_map_index);
        
        // Read timstamp of last packet for this flowlet ID
        flowlet_lasttime.read(meta.hash.flowlet_lasttime,
                              (bit<32>) meta.hash.flowlet_map_index);
        
        // Calculate time elapsed since last packet
        // TODO : take care of rollover case
        meta.hash.flow_ipg = now - meta.hash.flowlet_lasttime;
        
        // Update timestamp of last packet received for this flowlet
        flowlet_lasttime.write((bit<32>) meta.hash.flowlet_map_index, now);
        
        // Create new flowlet
        if (meta.hash.flow_ipg > FLOWLET_INTERVAL) {
            meta.hash.flowlet_id = meta.hash.flowlet_id + 1;
            flowlet_id.write((bit<32>) meta.hash.flowlet_map_index,
                             meta.hash.flowlet_id);
        }
    }
}

control process_vpc_df(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
	if (hdr.ieth.isValid()) {
	    if (hdr.ieth.src_is_peer == 0) {
		meta.ingress.vpc_df = 1;
	    } else {
		meta.ingress.vpc_df = 0;
	    }
	} else if (meta.ig_tunnel.decap == 1) {
	    if (meta.src_if.is_local == 1) {
		meta.ingress.vpc_df = 1;
	    } else if (meta.src_tep.is_vpc_peer == 1) {
		meta.ingress.vpc_df = 0;
//#ifndef ACI_TOR_MODE
	    } else if (meta.CFG_aci_tor_mode.enable == 0 && meta.src_if.mct == 1) {
		meta.ingress.vpc_df = 0;
//#endif /*ACI_TOR_MODE*/
	    } else {
		if ((meta.hash.hash1 & 0x1) == 1) {//TODO
		    meta.ingress.vpc_df = 1;
		} else {
		    meta.ingress.vpc_df = 0;
		}
	    }
	} else {
	    if (meta.src_if.mct == 1) {
		meta.ingress.vpc_df = 0;
	    } else {
		meta.ingress.vpc_df = 1;
	    }
	}
    }
}

control process_ipv4_twice_nat_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".ipv4_twice_nat_hit")
    action ipv4_twice_nat_hit(bit<12> nat_ptr) {
        meta.l3.twice_nat_hit = TRUE;
        meta.l3.nat_ptr = nat_ptr;
    }
    @name(".ipv4_twice_nat_sup_copy")
    action ipv4_twice_nat_sup_copy() {
        meta.l3.twice_nat_sup_copy = TRUE;
    }
    @name(".ipv4_twice_nat_sup_redirect")
    action ipv4_twice_nat_sup_redirect() {
        meta.l3.twice_nat_sup_redirect = TRUE;
    }
    @name(".ipv4_twice_nat_drop")
    action ipv4_twice_nat_drop() {
        meta.ig_drop.twice_nat_drop = TRUE;
        //meta.ig_drop.inc_drop_counters = TRUE;
    }
    @name("ipv4_twice_nat_hash_table")
    table ipv4_twice_nat_hash_table {
        actions = {
            ipv4_twice_nat_hit;
            ipv4_twice_nat_sup_copy;
            ipv4_twice_nat_sup_redirect;
            ipv4_twice_nat_drop;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.vrf             : exact;
            meta.ipv4m.lkp_ipv4_da       : exact;
            meta.l3.lkp_l4_dport        : exact;
            meta.ipv4m.lkp_ipv4_sa       : exact;
            meta.l3.lkp_l4_sport        : exact;
            hdr.tcp.isValid()             : exact;
            hdr.udp.isValid()             : exact;
            meta.src_bd.nat_inside_if   : exact;
            meta.src_bd.nat_outside_if  : exact;
            meta.src_bd.nat_overload_fwd: exact;
        }
        size = IPV4_TWICE_NAT_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        ipv4_twice_nat_hash_table.apply();
    }
}

control process_ipv4_dst_nat_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".ipv4_dst_nat_hit")
    action ipv4_dst_nat_hit(bit<12> nat_ptr) {
        meta.l3.dst_nat_hit = TRUE;
        meta.l3.nat_ptr = nat_ptr;
    }
    @name(".ipv4_dst_nat_sup_copy")
    action ipv4_dst_nat_sup_copy() {
        meta.l3.dst_nat_sup_copy = TRUE;
    }
    @name(".ipv4_dst_nat_sup_redirect")
    action ipv4_dst_nat_sup_redirect() {
        meta.l3.dst_nat_sup_redirect = TRUE;
    }
    @name(".ipv4_dst_nat_drop")
    action ipv4_dst_nat_drop() {
        meta.ig_drop.dst_nat_drop = TRUE;
        //meta.ig_drop.inc_drop_counters = TRUE;
    }
    @name(".ipv4_dst_nat_overload")
    action ipv4_dst_nat_overload(bit<12> nat_ptr, bit<14> vrf,
                                 bit<32> addr_mask, bit<32> addr)
    {
        meta.l3.dst_nat_hit = TRUE;
        meta.l3.nat_ptr = nat_ptr;
        meta.l3.nat_overload = TRUE;
        meta.l3.nat_overload_vrf = vrf;
        meta.ipv4m.nat_overload_addr =
            (meta.ipv4m.nat_overload_addr & ~addr_mask) | (addr & addr_mask);
    }
    @name("ipv4_dst_nat_hash_table")
    table ipv4_dst_nat_hash_table {
        actions = {
            ipv4_dst_nat_hit;
            ipv4_dst_nat_sup_copy;
            ipv4_dst_nat_sup_redirect;
            ipv4_dst_nat_drop;
            ipv4_dst_nat_overload;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.vrf             : exact;
            meta.ipv4m.lkp_ipv4_da       : exact;
            meta.l3.lkp_l4_dport        : exact;
            hdr.tcp.isValid()             : exact;
            hdr.udp.isValid()             : exact;
            meta.src_bd.nat_inside_if   : exact;
            meta.src_bd.nat_outside_if  : exact;
            meta.src_bd.nat_overload_fwd: exact;
        }
        size = IPV4_DST_NAT_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        ipv4_dst_nat_hash_table.apply();
    }
}

control process_ipv4_src_nat_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".ipv4_src_nat_hit")
    action ipv4_src_nat_hit(bit<12> nat_ptr) {
        meta.l3.src_nat_hit = TRUE;
        meta.l3.nat_ptr = nat_ptr;
    }
    @name(".ipv4_src_nat_sup_copy")
    action ipv4_src_nat_sup_copy() {
        meta.l3.src_nat_sup_copy = TRUE;
    }
    @name(".ipv4_src_nat_sup_redirect")
    action ipv4_src_nat_sup_redirect() {
        meta.l3.src_nat_sup_redirect = TRUE;
    }
    @name(".ipv4_src_nat_drop")
    action ipv4_src_nat_drop() {
        meta.ig_drop.src_nat_drop = TRUE;
    }
    @name("ipv4_src_nat_hash_table")
    table ipv4_src_nat_hash_table {
        actions = {
            ipv4_src_nat_hit;
            ipv4_src_nat_sup_copy;
            ipv4_src_nat_sup_redirect;
            ipv4_src_nat_drop;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.vrf             : exact;
            meta.ipv4m.lkp_ipv4_sa       : exact;
            meta.l3.lkp_l4_sport        : exact;
            hdr.tcp.isValid()             : exact;
            hdr.udp.isValid()             : exact;
            meta.src_bd.nat_inside_if   : exact;
            meta.src_bd.nat_outside_if  : exact;
            meta.src_bd.nat_overload_fwd: exact;
        }
        size = IPV4_SRC_NAT_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        ipv4_src_nat_hash_table.apply();
    }
}

control process_nat_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("nat_hit_bits_table")
    register<bit<1>>(NAT_HIT_BITS_TABLE_SIZE) nat_hit_bits_table;

    @name("process_ipv4_twice_nat_lookup") process_ipv4_twice_nat_lookup() process_ipv4_twice_nat_lookup_0;
    @name("process_ipv4_dst_nat_lookup") process_ipv4_dst_nat_lookup() process_ipv4_dst_nat_lookup_0;
    @name("process_ipv4_src_nat_lookup") process_ipv4_src_nat_lookup() process_ipv4_src_nat_lookup_0;
    apply {
        if (meta.l3.l3_type == L3TYPE_IPV4) {
            process_ipv4_twice_nat_lookup_0.apply(hdr, meta, standard_metadata);
            if (meta.l3.twice_nat_hit == 0) {
                process_ipv4_dst_nat_lookup_0.apply(hdr, meta, standard_metadata);
                if (meta.l3.dst_nat_hit == 0) {
                    process_ipv4_src_nat_lookup_0.apply(hdr, meta, standard_metadata);
                }
            }
        }
        // TBD nat_ptr is 12 bits wide, but the register is only
        // defined to be 2048 entries deep.  Make it 4096 entries
        // deep?
        nat_hit_bits_table.write((bit<32>) meta.l3.nat_ptr, (bit<1>) 1);
    }
}

control process_ipv4_fib_sa_key(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (((meta.l3.l3_type == L3TYPE_ARP) ||
             (meta.l3.l3_type == L3TYPE_RARP)) &&
            ((meta.src_bd.normal_arp_nd_learn == 0) &&
             ((meta.l3.arp_type == ARP_REQ) ||
              (meta.l3.arp_type == ARP_RES) ||
              (meta.l3.arp_type == RARP_RES))))
        {
            // ~~~~ IP learning from ARP/RARP frames ~~~~
            meta.l3.fib_sa_lookup_en = 1;
            meta.l3.fib_sa_key_vrf = meta.src_bd.vrf;
            meta.ipv4m.fib_sa_key_addr = hdr.arp_rarp.srcProtoAddr;
            meta.l3.urpf_type = uRPF_MODE_DISABLE;
        } else if (meta.l3.l3_type == L3TYPE_IPV4) {
            // ~~~~ Normal Source IP lookup ~~~~
            meta.l3.fib_sa_lookup_en = 1;
            meta.ipv4m.fib_sa_key_addr = meta.ipv4m.lkp_ipv4_da;
            meta.l3.urpf_type = meta.src_bd.ipv4_rpf_type;
            if (meta.l3.ip_sa_type == IP_UNICAST_LL) { // only v6
                meta.l3.fib_sa_key_vrf = meta.ingress.src_bd;
            } else {
                // Note : no support for {BD,S} lookup for link-local multicast
                meta.l3.fib_sa_key_vrf = meta.src_bd.vrf;
            }
        } else {
            meta.l3.fib_sa_lookup_en = 0;
            meta.l3.fib_sa_key_vrf = meta.src_bd.vrf;
            meta.ipv4m.fib_sa_key_addr = meta.ipv4m.lkp_ipv4_da;
            meta.l3.urpf_type = uRPF_MODE_DISABLE;
        }
    }
}

action src_fib_hit_adj(inout metadata meta,
//#ifdef ACI_TOR_MODE
                       //bit<8> ep_bounce,
                       bit<2> class_pri,
                       bit<16> class,
                       //bit<8> epg,
                       bit<1> policy_incomplete, bit<1> bind_notify_en,
                       bit<1> class_notify_en, bit<1> addr_notify_en,
                       bit<1> ivxlan_dl, bit<1> policy_applied,
                       //bit<8> shared_service,
                       //bit<8> sg_label,
                       //bit<8> dst_local,
                       //bit<8> preserve_vrf,
                       //bit<8> spine_proxy,
//#else  /*ACI_TOR_MODE*/
                       bit<16> sgt,
//#endif /*ACI_TOR_MODE*/
                       //bit<8> sup_copy,
                       bit<1> sa_sup_redirect,
                       //bit<8> da_sup_redirect,
                       bit<1> sa_direct_connect,
                       //bit<8> ttl_decrement_bypass,
                       bit<1> default_entry, bit<16> adj_ptr)
{
    meta.l3.src_fib_hit = TRUE;
    meta.l3.src_ecmp_vld = FALSE;
    meta.l3.src_adj_ptr = adj_ptr;
//#ifdef ACI_TOR_MODE
    if (meta.CFG_aci_tor_mode.enable == 1) {
        //meta.src_fib.ep_bounce = ep_bounce;
        meta.src_fib.class_pri = class_pri;
        meta.src_fib.class = class;
        //meta.src_fib.epg = epg;
        meta.src_fib.policy_incomplete = policy_incomplete;
        meta.src_fib.bind_notify_en = bind_notify_en;
        meta.src_fib.class_notify_en = class_notify_en;
        meta.src_fib.addr_notify_en = addr_notify_en;
        meta.src_fib.ivxlan_dl = ivxlan_dl;
        meta.src_fib.policy_applied = policy_applied;
        //meta.src_fib.shared_service = shared_service;
        //meta.src_fib.sg_label = sg_label;
        //meta.src_fib.dst_local = dst_local;
        //meta.src_fib.preserve_vrf = preserve_vrf;
//#else  /*ACI_TOR_MODE*/
    } else {
        meta.src_fib.sgt = sgt;
//#endif /*ACI_TOR_MODE*/
    }
    //meta.src_fib.sup_copy = sup_copy;
    meta.src_fib.sa_sup_redirect = sa_sup_redirect;
    //meta.src_fib.da_sup_redirect = da_sup_redirect;
    meta.src_fib.sa_direct_connect = sa_direct_connect;
    //meta.src_fib.ttl_decrement_bypass = ttl_decrement_bypass;
    meta.src_fib.default_entry = default_entry;
}

action src_fib_hit_ecmp(inout metadata meta,
//#ifdef ACI_TOR_MODE
                        //bit<8> ep_bounce,
                        bit<2> class_pri,
                        bit<16> class,
                        //bit<8> epg,
                        bit<1> policy_incomplete, bit<1> bind_notify_en,
                        bit<1> class_notify_en, bit<1> addr_notify_en,
                        bit<1> ivxlan_dl, bit<1> policy_applied,
                        //bit<8> shared_service,
                        //bit<8> sg_label,
                        //bit<8> dst_local,
                        //bit<8> preserve_vrf,
                        //bit<8> spine_proxy,
//#else  /*ACI_TOR_MODE*/
                        bit<16> sgt,
//#endif /*ACI_TOR_MODE*/
                        //bit<8> sup_copy,
                        bit<1> sa_sup_redirect,
                        //bit<8> da_sup_redirect,
                        bit<1> sa_direct_connect,
                        //bit<8> ttl_decrement_bypass,
                        bit<1> default_entry, bit<16> ecmp_ptr)
{
    meta.l3.src_fib_hit = TRUE;
    meta.l3.src_ecmp_vld = TRUE;
    meta.l3.src_ecmp_ptr = ecmp_ptr;
//#ifdef ACI_TOR_MODE
    if (meta.CFG_aci_tor_mode.enable == 1) {
        //meta.src_fib.ep_bounce = ep_bounce;
        meta.src_fib.class_pri = class_pri;
        meta.src_fib.class = class;
        //meta.src_fib.epg = epg;
        meta.src_fib.policy_incomplete = policy_incomplete;
        meta.src_fib.bind_notify_en = bind_notify_en;
        meta.src_fib.class_notify_en = class_notify_en;
        meta.src_fib.addr_notify_en = addr_notify_en;
        meta.src_fib.ivxlan_dl = ivxlan_dl;
        meta.src_fib.policy_applied = policy_applied;
        //meta.src_fib.shared_service = shared_service;
        //meta.src_fib.sg_label = sg_label;
        //meta.src_fib.dst_local = dst_local;
        //meta.src_fib.preserve_vrf = preserve_vrf;
//#else  /*ACI_TOR_MODE*/
    } else {
        meta.src_fib.sgt = sgt;
//#endif /*ACI_TOR_MODE*/
    }
    //meta.src_fib.sup_copy = sup_copy;
    meta.src_fib.sa_sup_redirect = sa_sup_redirect;
    //meta.src_fib.da_sup_redirect = da_sup_redirect;
    meta.src_fib.sa_direct_connect = sa_direct_connect;
    //meta.src_fib.ttl_decrement_bypass = ttl_decrement_bypass;
    meta.src_fib.default_entry = default_entry;
}

control process_ipv4_src_fib_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("ipv4_fib_src_lpm") table ipv4_fib_src_lpm {
        actions = {
            src_fib_hit_adj(meta);
            src_fib_hit_ecmp(meta);
            @default_only NoAction;
        }
        key = {
            meta.l3.fib_sa_key_vrf   : exact;
            meta.ipv4m.fib_sa_key_addr: lpm;
        }
        size = IPV4_LPM_SIZE;
        default_action = NoAction();
    }
    apply {
        // TBDP416 - see original P4_14 code for options that have
        // separate HRT and LPM tables.  Do we want that level of
        // detail here, or save it for the implmentation, outside of
        // P4 code?
        ipv4_fib_src_lpm.apply();
    }
}

control process_ipv6_fib_sa_key(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if ((meta.l3.nd_type == ND_ADV) &&
            (meta.src_bd.normal_arp_nd_learn == 0))
        {
            // ~~~~ IP learning from ND Advertisement ~~~~
            meta.l3.fib_sa_lookup_en = 1;
            meta.ipv6m.fib_sa_key_addr = hdr.ipv6_nd.targetAddr;
            if (meta.l3.nd_ta_ll == 1) {
                meta.l3.fib_sa_key_vrf = meta.ingress.src_bd;
            } else {
                meta.l3.fib_sa_key_vrf = meta.src_bd.vrf;
            }
        } else if ((meta.l3.nd_type == ND_SOL) &&
                   (meta.src_bd.normal_arp_nd_learn == 0) &&
                   (meta.ipv6m.ipv6_sa_eq0 == 0))
        {
            // ~~~~ IP learning from ND Solicitation ~~~~
            meta.l3.fib_sa_lookup_en = 1;
            meta.ipv6m.fib_sa_key_addr = meta.ipv6m.lkp_ipv6_sa;
            if (meta.l3.ip_sa_type == IP_UNICAST_LL) {
                meta.l3.fib_sa_key_vrf = meta.ingress.src_bd;
            } else {
                meta.l3.fib_sa_key_vrf = meta.src_bd.vrf;
            }
        } else if (meta.l3.l3_type == L3TYPE_IPV6) {
            // ~~~~ Normal Source IP Lookup ~~~~
            meta.l3.fib_sa_lookup_en = 1;
            meta.ipv6m.fib_sa_key_addr = meta.ipv6m.lkp_ipv6_sa;
            meta.l3.urpf_type = meta.src_bd.ipv6_rpf_type;
            if (meta.l3.ip_sa_type == IP_UNICAST_LL) {
                meta.l3.fib_sa_key_vrf = meta.ingress.src_bd;
            } else {
                meta.l3.fib_sa_key_vrf = meta.src_bd.vrf;
            }
        }
    }
}

control process_ipv6_src_fib_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("ipv6_fib_src_lpm") table ipv6_fib_src_lpm {
        actions = {
            src_fib_hit_adj(meta);
            src_fib_hit_ecmp(meta);
            @default_only NoAction;
        }
        key = {
            meta.l3.fib_sa_key_vrf   : exact;
            meta.ipv6m.fib_sa_key_addr: lpm;
        }
        size = IPV6_LPM_SIZE;
        default_action = NoAction();
    }
    apply {
        // TBDP416 - see original P4_14 code for options that have
        // separate HRT and LPM tables.  Do we want that level of
        // detail here, or save it for the implmentation, outside of
        // P4 code?
        ipv6_fib_src_lpm.apply();
    }
}

control process_src_mac_key_gen(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // This looks like it is related to these lines in the C++
        // model: ins-asic/sugarbowl/model/top/sug_lux.cc

        // Starting at line 6504:
        //  // RARP with source hardware address
        //  else if ( lkup_pkt_is_rarp_req && !bd_state_info.info.leaf.normal_arp_nd_learn() )
        //    {
        //      // No FIB Lookup
        //      fib_sa_key.valid               =  0 ;
        //      // Mac Lookup on Source Hardware Address
        //      mac_sa_key.mac                 =  l3v[sa_layer].arp.sha() ;

        if (meta.CFG_aci_tor_mode.enable == 1 &&
            (meta.l3.l3_type == L3TYPE_RARP) &&
            (meta.l3.arp_type == RARP_REQ) &&
            (meta.src_bd.normal_arp_nd_learn == 0))
        {
            meta.src_mac_key.addr = hdr.arp_rarp.srcHwAddr;
        } else {
            meta.src_mac_key.addr = meta.l2.lkp_mac_sa;
        }
    }
}

control process_src_mac_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".src_mac_miss")
    action src_mac_miss() {
	meta.l2.l2_src_hit = FALSE;
    }
    @name(".src_mac_hit")
    action src_mac_hit(bit<1> is_ptr, bit<14> ptr_or_idx,
                       //bit<8> sup_copy,
                       //bit<8> sup_redirect,
//#ifdef ACI_TOR_MODE
                       //bit<8> ep_bounce,
                       bit<2> class_pri,
                       bit<16> class,
                       //bit<8> epg,
                       bit<1> policy_incomplete, bit<1> bind_notify_en,
                       bit<1> class_notify_en, bit<1> addr_notify_en,
                       bit<1> ivxlan_dl, bit<1> policy_applied,
                       bit<1> shared_service,
                       //bit<8> vnid_use_bd,
                       //bit<8> dst_local,
                       //bit<8> dst_vpc,
//#endif /*ACI_TOR_MODE*/
                       bit<1> secure_mac)
    {
        meta.l2.l2_src_hit = TRUE;
        meta.src_mac.ptr_or_idx = ptr_or_idx;
        meta.src_mac.is_ptr = is_ptr;
        meta.l2.src_secure_mac = secure_mac;
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.src_mac.policy_applied = policy_applied;
            meta.src_mac.shared_service = shared_service;
            meta.src_mac.class_pri = class_pri;
            meta.src_mac.class = class;
            meta.src_mac.policy_incomplete = policy_incomplete;
            meta.src_mac.bind_notify_en = bind_notify_en;
            meta.src_mac.class_notify_en = class_notify_en;
            meta.src_mac.addr_notify_en = addr_notify_en;
            meta.src_mac.ivxlan_dl = ivxlan_dl;
//#endif /*ACI_TOR_MODE*/
        }
    }
    @name("src_mac_hash") table src_mac_hash {
        actions = {
	    src_mac_miss;
            src_mac_hit;
            @default_only NoAction;
        }
        key = {
            meta.ingress.src_bd: exact;
            //meta.src_mac_key.bd : ternary;
            meta.src_mac_key.addr       : exact;
        }
	size = MAC_OF_TCAM_SIZE;
        default_action = NoAction();
    }
    @name("process_src_mac_key_gen") process_src_mac_key_gen() process_src_mac_key_gen_0;
    apply {
        process_src_mac_key_gen_0.apply(hdr, meta, standard_metadata);
        if (meta.ig_tunnel.decap == 0 || meta.ig_tunnel.l3_tunnel_decap == 0) {
            src_mac_hash.apply();
        }
    }
}

control process_ipv4_fib_da_key(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if ((meta.l3.l3_type == L3TYPE_ARP)) {
            // ~~~~ ARP unicast mode/ Target-IP lookup for sup  ~~~~
            meta.l3.fib_da_lookup_en = 1;
            meta.l3.fib_da_key_vrf = meta.src_bd.vrf;
            meta.ipv4m.fib_da_key_addr = hdr.arp_rarp.dstProtoAddr;
        } else if ((meta.l3.l3_type == L3TYPE_IPV4) &&
                   (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE))
        {
            meta.l3.fib_da_lookup_en = 1;
#ifdef DISABLE_NAT_OVERLOAD
            if (meta.l3.nat_overload == 1) {
                // ~~~~ NAT overload ~~~~
                meta.l3.fib_da_key_vrf = meta.l3.nat_overload_vrf;
                meta.ipv4m.fib_da_key_addr = meta.ipv4m.nat_overload_addr;
            } else {
#endif /*DISABLE_NAT_OVERLOAD*/
                meta.l3.fib_da_key_vrf = meta.src_bd.vrf;
                meta.ipv4m.fib_da_key_addr = meta.ipv4m.lkp_ipv4_da;
#ifdef DISABLE_NAT_OVERLOAD
            }
#endif /*DISABLE_NAT_OVERLOAD*/
        } else {
            meta.l3.fib_da_lookup_en = 0;
            meta.l3.fib_da_key_vrf = meta.src_bd.vrf;
            meta.ipv4m.fib_da_key_addr = meta.ipv4m.lkp_ipv4_da;
        }
    }
}

action dst_fib_hit_adj(inout metadata meta,
//#ifdef ACI_TOR_MODE
                       bit<1> ep_bounce,
                       //bit<8> class_pri,
                       bit<16> class, bit<16> epg,
                       bit<1> policy_incomplete,
                       //bit<8> bind_notify_en,
                       //bit<8> class_notify_en,
                       //bit<8> addr_notify_en,
                       //bit<8> ivxlan_dl,
                       bit<1> policy_applied,
                       bit<1> shared_service,
                       //bit<8> sg_label,
                       bit<1> dst_local, bit<1> preserve_vrf,
                       bit<1> spine_proxy,
//#else  /*ACI_TOR_MODE*/
                       bit<16> sgt,
//#endif /*ACI_TOR_MODE*/
                       bit<1> sup_copy,
                       //bit<8> sa_sup_redirect,
                       bit<1> da_sup_redirect,
                       //bit<8> sa_direct_connect,
                       bit<1> ttl_decrement_bypass, bit<1> default_entry,
                       bit<16> adj_ptr)
{
    meta.l3.dst_fib_hit = TRUE;
    meta.l3.dst_ecmp_vld = FALSE;
    meta.l3.dst_adj_ptr = adj_ptr;
//#ifdef ACI_TOR_MODE
    if (meta.CFG_aci_tor_mode.enable == 1) {
        meta.dst_fib.ep_bounce = ep_bounce;
        //meta.dst_fib.class_pri = class_pri;
        //meta.dst_fib.class = class;
        meta.dst_fib.epg = epg;
        //meta.dst_fib.policy_incomplete = policy_incomplete;
        //meta.dst_fib.bind_notify_en = bind_notify_en;
        //meta.dst_fib.class_notify_en = class_notify_en;
        //meta.dst_fib.addr_notify_en = addr_notify_en;
        //meta.dst_fib.ivxlan_dl = ivxlan_dl;
        //meta.dst_fib.policy_applied = policy_applied;
        meta.dst_fib.shared_service = shared_service;
        //meta.dst_fib.sg_label = sg_label;
        meta.dst_fib.dst_local = dst_local;
        meta.dst_fib.preserve_vrf = preserve_vrf;
        meta.dst_fib.spine_proxy = spine_proxy;
        meta.pt_key.dst_class = class;
        meta.pt_key.dst_policy_applied = policy_applied;
        meta.pt_key.dst_policy_incomplete = policy_incomplete;
//#else  /*ACI_TOR_MODE*/
    } else {
        meta.dst_fib.sgt = sgt;
//#endif /*ACI_TOR_MODE*/
    }
    meta.dst_fib.sup_copy = sup_copy;
    //meta.dst_fib.sa_sup_redirect = sa_sup_redirect;
    meta.dst_fib.da_sup_redirect = da_sup_redirect;
    //meta.dst_fib.sa_direct_connect = sa_direct_connect;
    meta.dst_fib.ttl_decrement_bypass = ttl_decrement_bypass;
    meta.dst_fib.default_entry = default_entry;
}

action dst_fib_hit_ecmp(inout metadata meta,
//#ifdef ACI_TOR_MODE
                        bit<1> ep_bounce,
                        //bit<8> class_pri,
                        bit<16> class, bit<16> epg,
                        bit<1> policy_incomplete,
                        //bit<8> bind_notify_en,
                        //bit<8> class_notify_en,
                        //bit<8> addr_notify_en,
                        //bit<8> ivxlan_dl,
                        bit<1> policy_applied,
                        bit<1> shared_service,
                        //bit<8> sg_label,
                        bit<1> dst_local, bit<1> preserve_vrf,
                        bit<1> spine_proxy,
//#else  /*ACI_TOR_MODE*/
                        bit<16> sgt,
//#endif /*ACI_TOR_MODE*/
                        bit<1> sup_copy,
                        //bit<8> sa_sup_redirect,
                        bit<1> da_sup_redirect,
                        //bit<8> sa_direct_connect,
                        bit<1> ttl_decrement_bypass, bit<1> default_entry,
                        bit<16> ecmp_ptr)
{
    meta.l3.dst_fib_hit = TRUE;
    meta.l3.dst_ecmp_vld = TRUE;
    meta.l3.dst_ecmp_ptr = ecmp_ptr;
//#ifdef ACI_TOR_MODE
    if (meta.CFG_aci_tor_mode.enable == 1) {
        meta.dst_fib.ep_bounce = ep_bounce;
        //meta.dst_fib.class_pri = class_pri;
        //meta.dst_fib.class = class;
        meta.dst_fib.epg = epg;
        //meta.dst_fib.policy_incomplete = policy_incomplete;
        //meta.dst_fib.bind_notify_en = bind_notify_en;
        //meta.dst_fib.class_notify_en = class_notify_en;
        //meta.dst_fib.addr_notify_en = addr_notify_en;
        //meta.dst_fib.ivxlan_dl = ivxlan_dl;
        //meta.dst_fib.policy_applied = policy_applied;
        meta.dst_fib.shared_service = shared_service;
        //meta.dst_fib.sg_label = sg_label;
        meta.dst_fib.dst_local = dst_local;
        meta.dst_fib.preserve_vrf = preserve_vrf;
        meta.dst_fib.spine_proxy = spine_proxy;
        meta.pt_key.dst_class = class;
        meta.pt_key.dst_policy_applied = policy_applied;
        meta.pt_key.dst_policy_incomplete = policy_incomplete;
//#else  /*ACI_TOR_MODE*/
    } else {
        meta.dst_fib.sgt = sgt;
//#endif /*ACI_TOR_MODE*/
    }
    meta.dst_fib.sup_copy = sup_copy;
    //meta.dst_fib.sa_sup_redirect = sa_sup_redirect;
    meta.dst_fib.da_sup_redirect = da_sup_redirect;
    //meta.dst_fib.sa_direct_connect = sa_direct_connect;
    meta.dst_fib.ttl_decrement_bypass = ttl_decrement_bypass;
    meta.dst_fib.default_entry = default_entry;
}

control process_ipv4_dst_fib_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("ipv4_fib_dst_lpm") table ipv4_fib_dst_lpm {
        actions = {
            dst_fib_hit_adj(meta);
            dst_fib_hit_ecmp(meta);
            @default_only NoAction;
        }
        key = {
            meta.l3.fib_da_key_vrf   : exact;
            meta.ipv4m.fib_da_key_addr: lpm;
        }
        size = IPV4_LPM_SIZE;
        default_action = NoAction();
    }
    apply {
        // TBDP416 - see original P4_14 code for options that have
        // separate HRT and LPM tables.  Do we want that level of
        // detail here, or save it for the implmentation, outside of
        // P4 code?
        ipv4_fib_dst_lpm.apply();
    }
}

// ND unicast mode
// ND - Target IP lookup in the bridged case
// IP routing

// Link-local vs global address
control process_ipv6_fib_da_key(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if ((meta.l3.l4_type == L4TYPE_ND) &&
            ((meta.l3.nd_unicast_mode == 1) ||
             (meta.ingress.l3_fwd_mode == L3_FWD_MODE_BRIDGE)) &&
            ((meta.l3.nd_type == ND_SOL) ||
             (meta.l3.nd_type == ND_GNA)))
        {
            // Unicast mode or Target-IP lookup for sup in bridged cases
            // Target Address lookup
            meta.l3.fib_da_lookup_en = 1;
            meta.ipv6m.fib_da_key_addr = hdr.ipv6_nd.targetAddr;
            if (meta.l3.nd_ta_ll == 1) {
                meta.l3.fib_da_key_vrf = meta.ingress.src_bd;
            } else {
                meta.l3.fib_da_key_vrf = meta.src_bd.vrf;
            }
        } else if ((meta.l3.l3_type == L3TYPE_IPV6) &&
                   (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE))
        {
            meta.l3.fib_da_lookup_en = 1;
	    meta.ipv6m.fib_da_key_addr = meta.ipv6m.lkp_ipv6_da;
	    if (meta.l3.ip_da_type == IP_UNICAST_LL) { // only v6
		meta.l3.fib_da_key_vrf = meta.ingress.src_bd;
	    } else {
		meta.l3.fib_da_key_vrf = meta.src_bd.vrf;
	    }
//    } else {
//	meta.l3.fib_da_lookup_en = 0;
//	meta.l3.fib_da_key_vrf = meta.src_bd.vrf;
//	meta.ipv6m.fib_da_key_addr = meta.ipv6m.lkp_ipv6_da;
        }
    }
}

control process_ipv6_dst_fib_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("ipv6_fib_dst_lpm") table ipv6_fib_dst_lpm {
        actions = {
            dst_fib_hit_adj(meta);
            dst_fib_hit_ecmp(meta);
            @default_only NoAction;
        }
        key = {
            meta.l3.fib_da_key_vrf   : exact;
            meta.ipv6m.fib_da_key_addr: lpm;
        }
        size = IPV6_LPM_SIZE;
        default_action = NoAction();
    }
    apply {
        // TBDP416 - see original P4_14 code for options that have
        // separate HRT and LPM tables.  Do we want that level of
        // detail here, or save it for the implmentation, outside of
        // P4 code?
        ipv6_fib_dst_lpm.apply();
    }
}

control process_ipv4_mc_route_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("ipv4_mc_route_sg_hit_bits_table")
    register<bit<1>>(IPV4_MC_ROUTE_SG_HASH_TABLE_SIZE) ipv4_mc_route_sg_hit_bits_table;

    // {*,G} lookup for for Bidir or SM
    @name(".set_ipv4_mc_route_group_hit")
    action set_ipv4_mc_route_group_hit(bit<1> rpf_en, bit<1> bidir,
                                       bit<14> rpf_bd_or_group,
                                       bit<16> met0_ptr,
                                       bit<1> met0_vld, bit<1> use_met,
                                       bit<1> sup_copy,
                                       bit<1> no_dc_sup_redirect,
                                       bit<1> rpf_fail_send_to_sup,
                                       bit<1> default_entry,
                                       bit<4> mtu_idx,
//#ifdef ACI_TOR_MODE
                                       bit<3> active_ftag_idx,
                                       bit<1> force_rpf_pass,
//#endif /*ACI_TOR_MODE*/
                                       bit<16> hit_addr)
    {
        meta.multicast.mc_route_group_lookup_hit = TRUE;
        meta.multicast.mc_route_group_hit_addr = hit_addr;
        meta.multicast.group_rpf_en = rpf_en;
        meta.multicast.bidir = bidir;
        meta.multicast.group_rpf_bd_or_group = rpf_bd_or_group;
        meta.ingress.met0_vld = met0_vld;
        meta.ingress.met0_ptr = met0_ptr;
        meta.ingress.use_met = use_met;
        meta.multicast.sup_copy = sup_copy;
        meta.multicast.mtu_idx = mtu_idx;
        meta.multicast.no_dc_sup_redirect = no_dc_sup_redirect;
        meta.multicast.rpf_fail_send_to_sup = rpf_fail_send_to_sup;
        meta.multicast.default_entry = default_entry;
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.multicast.active_ftag_idx = active_ftag_idx;
            meta.multicast.force_rpf_pass = force_rpf_pass;
//#endif /*ACI_TOR_MODE*/
        }
        meta.multicast.group_rpf_bd_match = meta.ingress.src_bd ^ rpf_bd_or_group;
        meta.multicast.rpf_bd = rpf_bd_or_group;
    }

    // {S,G} for SM
    @name(".set_ipv4_mc_route_sg_hit")
    action set_ipv4_mc_route_sg_hit(bit<1> rpf_en, bit<14> rpf_bd,
                                    bit<16> met0_ptr, bit<1> met0_vld,
                                    bit<1> use_met, bit<16> hit_addr,
                                    bit<1> sup_copy, bit<1> no_dc_sup_redirect,
                                    bit<1> rpf_fail_send_to_sup,
//#ifdef ACI_TOR_MODE
                                    //bit<4> mtu_idx,
                                    bit<3> active_ftag_idx,
                                    bit<1> force_rpf_pass,
//#else  /*ACI_TOR_MODE*/
                                    bit<4> mtu_idx
//#endif /*ACI_TOR_MODE*/
                                    )
    {
        meta.multicast.mc_route_sg_lookup_hit = TRUE;
        meta.multicast.sg_rpf_en = rpf_en;
        meta.ingress.met0_vld = met0_vld;
        meta.ingress.met0_ptr = met0_ptr;
        meta.ingress.use_met = use_met;
        meta.multicast.sup_copy = sup_copy;
        meta.multicast.mtu_idx = mtu_idx;
        meta.multicast.mc_route_sg_hit_addr = hit_addr;
	//	modify_field(multicast_metadata.mc_route_sg_rpf_bd, rpf_bd );
        meta.multicast.no_dc_sup_redirect = no_dc_sup_redirect;
        meta.multicast.rpf_fail_send_to_sup = rpf_fail_send_to_sup;
        meta.multicast.sg_rpf_bd_match = meta.ingress.src_bd ^ rpf_bd;
        meta.multicast.rpf_bd = rpf_bd;
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.multicast.active_ftag_idx = active_ftag_idx;
            meta.multicast.force_rpf_pass = force_rpf_pass;
//#endif /*ACI_TOR_MODE*/
        }
        ipv4_mc_route_sg_hit_bits_table.write((bit<32>) meta.multicast.mc_route_sg_hit_addr,
                                              (bit<1>) 1);
    }
    @name("ipv4_mc_route_group_hash_table") table ipv4_mc_route_group_hash_table {
        actions = {
            set_ipv4_mc_route_group_hit;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.vrf      : exact;
            meta.ipv4m.lkp_ipv4_da: exact;
        }
        size = IPV4_MC_ROUTE_GROUP_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("ipv4_mc_route_sg_hash_table") table ipv4_mc_route_sg_hash_table {
        actions = {
            set_ipv4_mc_route_sg_hit;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.vrf      : exact;
            meta.ipv4m.lkp_ipv4_sa: exact;
            meta.ipv4m.lkp_ipv4_da: exact;
        }
        size = IPV4_MC_ROUTE_SG_OF_TCAM_SIZE;
        default_action = NoAction();
    }
    apply {
        if (meta.l3.ip_da_type == IP_MULTICAST &&
            meta.l3.l3_type == L3TYPE_IPV4)
        {
            ipv4_mc_route_group_hash_table.apply();
	    //if ((meta.multicast.mc_route_group_lookup_hit == 1)) {
            //    if (meta.multicast.bidir == TRUE) {
	    //    } else {
            ipv4_mc_route_sg_hash_table.apply();
            //    }
            //}
        }
    }
}

control process_ipv6_mc_route_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("ipv6_mc_route_sg_hit_bits_table")
    register<bit<1>>(IPV6_MC_ROUTE_SG_HASH_TABLE_SIZE) ipv6_mc_route_sg_hit_bits_table;
    @name(".set_ipv6_mc_route_group_hit")
    action set_ipv6_mc_route_group_hit(bit<1> rpf_en, bit<1> bidir,
                                       bit<14> rpf_bd_or_group,
                                       bit<16> met0_ptr, bit<1> met0_vld,
                                       bit<1> use_met, bit<1> sup_copy,
                                       bit<1> no_dc_sup_redirect,
                                       bit<1> rpf_fail_send_to_sup,
                                       bit<1> default_entry,
                                       bit<4> mtu_idx,
//#ifdef ACI_TOR_MODE
                                       bit<3> active_ftag_idx,
                                       bit<1> force_rpf_pass,
//#endif /*ACI_TOR_MODE*/
                                       bit<16> hit_addr)
    {
        meta.multicast.mc_route_group_lookup_hit = TRUE;
        meta.multicast.mc_route_group_hit_addr = hit_addr;
        meta.multicast.group_rpf_en = rpf_en;
        meta.multicast.bidir = bidir;
        meta.multicast.group_rpf_bd_or_group = rpf_bd_or_group;
        meta.ingress.met0_vld = met0_vld;
        meta.ingress.met0_ptr = met0_ptr;
        meta.ingress.use_met = use_met;
        meta.multicast.sup_copy = sup_copy;
        meta.multicast.mtu_idx = mtu_idx;
        meta.multicast.no_dc_sup_redirect = no_dc_sup_redirect;
        meta.multicast.rpf_fail_send_to_sup = rpf_fail_send_to_sup;
        meta.multicast.default_entry = default_entry;
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.multicast.active_ftag_idx = active_ftag_idx;
            meta.multicast.force_rpf_pass = force_rpf_pass;
//#endif /*ACI_TOR_MODE*/
        }
        meta.multicast.group_rpf_bd_match = meta.ingress.src_bd ^ rpf_bd_or_group;
        meta.multicast.rpf_bd = rpf_bd_or_group;
    }
    @name(".set_ipv6_mc_route_sg_hit")
    action set_ipv6_mc_route_sg_hit(bit<1> rpf_en, bit<14> rpf_bd,
                                    bit<16> met0_ptr, bit<1> met0_vld,
                                    bit<1> use_met, bit<16> hit_addr,
                                    bit<1> sup_copy, bit<1> no_dc_sup_redirect,
                                    bit<1> rpf_fail_send_to_sup,
//#ifdef ACI_TOR_MODE
                                    //bit<4> mtu_idx,
                                    bit<3> active_ftag_idx,
                                    bit<1> force_rpf_pass,
//#else  /*ACI_TOR_MODE*/
                                    bit<4> mtu_idx
//#endif /*ACI_TOR_MODE*/
                                    )
    {
        meta.multicast.mc_route_sg_lookup_hit = TRUE;
        meta.multicast.sg_rpf_en = rpf_en;
        meta.ingress.met0_vld = met0_vld;
        meta.ingress.met0_ptr = met0_ptr;
        meta.ingress.use_met = use_met;
        meta.multicast.sup_copy = sup_copy;
        meta.multicast.mtu_idx = mtu_idx;
        meta.multicast.mc_route_sg_hit_addr = hit_addr;
	//meta.multicast.mc_route_sg_rpf_bd = rpf_bd;
        meta.multicast.no_dc_sup_redirect = no_dc_sup_redirect;
        meta.multicast.rpf_fail_send_to_sup = rpf_fail_send_to_sup;
        meta.multicast.sg_rpf_bd_match = meta.ingress.src_bd ^ rpf_bd;
        meta.multicast.rpf_bd = rpf_bd;
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.multicast.active_ftag_idx = active_ftag_idx;
            meta.multicast.force_rpf_pass = force_rpf_pass;
//#endif /*ACI_TOR_MODE*/
        }
        ipv6_mc_route_sg_hit_bits_table.write((bit<32>) meta.multicast.mc_route_sg_hit_addr,
                                              (bit<1>) 1);
    }
    @name("ipv6_mc_route_group_hash_table") table ipv6_mc_route_group_hash_table {
        actions = {
            set_ipv6_mc_route_group_hit;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.vrf      : exact;
            meta.ipv6m.lkp_ipv6_da: exact;
        }
        size = IPV4_MC_ROUTE_GROUP_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("ipv6_mc_route_sg_hash_table") table ipv6_mc_route_sg_hash_table {
        actions = {
            set_ipv6_mc_route_sg_hit;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.vrf      : exact;
            meta.ipv6m.lkp_ipv6_sa: exact;
            meta.ipv6m.lkp_ipv6_da: exact;
        }
        size = IPV4_MC_ROUTE_SG_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        if (meta.l3.ip_da_type == IP_MULTICAST && meta.l3.l3_type == L3TYPE_IPV6) {
            ipv6_mc_route_group_hash_table.apply();
	    //if ((meta.multicast.mc_route_group_lookup_hit == 1)) {
	    //    if (meta.multicast.bidir == TRUE) {
	    //    } else {
            ipv6_mc_route_sg_hash_table.apply();
            //    }
            //}
        }
    }
}

control process_mc_sm_rpf_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.ingress.src_bd == meta.multicast.rpf_bd) {
            //meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
            meta.multicast.rpf_pass = TRUE;
        } else {
            //meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
            meta.multicast.rpf_pass = FALSE;
            meta.multicast.sg_rpf_pass = FALSE;
        }

        /*
        if ((meta.multicast.mc_route_sg_lookup_hit == 1) &&
            ((meta.multicast.sg_rpf_en == 0) ||
             (meta.multicast.sg_rpf_bd_match == 0)))
        {
            meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
            meta.multicast.rpf_pass = TRUE;
            meta.multicast.sg_rpf_pass = TRUE;
        } else if ((meta.multicast.mc_route_group_lookup_hit == 1) &&
                   ((meta.multicast.group_rpf_bd_match == 0) ||
                    (meta.multicast.group_rpf_en == 0)))
        {
            meta.ingress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
            meta.multicast.rpf_pass = TRUE;
            //meta.multicast.group_rpf_pass = TRUE;
            meta.multicast.sg_rpf_pass = FALSE;
        } else {
            meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
            meta.multicast.rpf_pass = FALSE;
            meta.multicast.sg_rpf_pass = FALSE;
        }
        */
    }
}

control process_non_ip_mc_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    // {*,MAC-G} lookup for IGMP v2
    @name(".set_non_ip_mc_group_hit")
    action set_non_ip_mc_group_hit(//bit<8> met0_ptr,
                                   bit<1> met0_vld,
                                   bit<1> use_met)
    {
        //meta.multicast.non_ip_group_lookup_hit = TRUE;
        meta.ingress.met0_vld = met0_vld;
        meta.ingress.use_met = use_met;
    }
    @name(".set_non_ip_mc_miss")
    action set_non_ip_mc_miss() {
        //meta.multicast.non_ip_group_lookup_hit = FALSE;
        meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
        meta.ingress.l2_fwd_mode = L2_FWD_MODE_FLOOD;
    }
    @name("non_ip_mc_group_hash_table") table non_ip_mc_group_hash_table {
        actions = {
            set_non_ip_mc_group_hit;
            set_non_ip_mc_miss;
            @default_only NoAction;
        }
        key = {
            meta.ingress.src_bd: exact;
            meta.l2.lkp_mac_da : exact;
        }
	size = NON_IP_MC_GROUP_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        non_ip_mc_group_hash_table.apply();
    }
}

// TBDP416 - There is a lot of similarity between
// process_inner_pim_sup_key and process_outer_pim_sup_key.  Can there
// easily be more code sharing between these?
control process_inner_pim_sup_key(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("inner_mcast_sup_filter_table0")
    register<bit<1>>(MCAST_SUP_FILTER_TABLE_SIZE) inner_mcast_sup_filter_table0;
    @name("inner_mcast_sup_filter_table1")
    register<bit<1>>(MCAST_SUP_FILTER_TABLE_SIZE) inner_mcast_sup_filter_table1;

    @name(".set_CFG_inner_mcast_sup_filter")
    action set_CFG_inner_mcast_sup_filter(bit<8> fixed0, bit<8> fixed1) {
        meta.inner_mcast_filter.fixed0 = fixed0;
        meta.inner_mcast_filter.fixed1 = fixed1;
    }
    @name("CFG_inner_mcast_sup_filter") table CFG_inner_mcast_sup_filter {
        actions = {
            set_CFG_inner_mcast_sup_filter;
            @default_only NoAction;
        }
        default_action = NoAction();
    }

    @name(".inner_pim_sup_action")
    action inner_pim_sup_action(bit<4> pim_bloom_filter_rcode,
                                bit<1> pim_bloom_filter_en,
                                bit<4> pim_acl_key)
    {
        meta.multicast.pim_bloom_filter_rcode = pim_bloom_filter_rcode;
        meta.multicast.pim_bloom_filter_en = pim_bloom_filter_en;
        meta.multicast.pim_acl_key = pim_acl_key;
    }
    @name("inner_pim_sup_conditions") table inner_pim_sup_conditions {
        actions = {
            inner_pim_sup_action;
            @default_only NoAction;
        }
        key = {
            meta.multicast.sup_copy                 : ternary;
            meta.multicast.mc_route_group_lookup_hit: ternary; // TODO : if it's a default entry, don't set star_g_hit
            meta.multicast.mc_route_sg_lookup_hit   : ternary;
            meta.multicast.rpf_pass                 : ternary;
            meta.multicast.sg_rpf_pass              : ternary;
            meta.src_fib.sa_direct_connect          : ternary;
            meta.multicast.rpf_fail_send_to_sup     : ternary;
            meta.multicast.no_dc_sup_redirect       : ternary;
        }
        size = 32;
        default_action = NoAction();
    }
    apply {
        if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_MC) {
            // Filter conditions
            inner_pim_sup_conditions.apply();
            // Bloom filter keys
            meta.inner_mcast_filter.rcode =
                meta.multicast.pim_bloom_filter_rcode;
            if (meta.ig_tunnel.mc_rpf_pass == 0) {
                meta.inner_mcast_filter.bd = meta.ingress.src_bd;
            }
            if (meta.ig_tunnel.mc_sg_lookup_hit == 1) {
                meta.inner_mcast_filter.hit_addr =
                    meta.multicast.mc_route_sg_hit_addr;
            }
            else if (meta.ig_tunnel.mc_group_lookup_hit == 1) { // default_entry is not used here
                meta.inner_mcast_filter.hit_addr =
                    meta.multicast.mc_route_group_hit_addr;
            }
            // Config table
            CFG_inner_mcast_sup_filter.apply();
            // Hash generation
            hash(meta.inner_mcast_filter.hash0, HashAlgorithm.crc16,
                 (bit<14>) 0,
                 { meta.inner_mcast_filter.fixed0,
                         meta.inner_mcast_filter.rcode,
                         meta.inner_mcast_filter.bd,
                         meta.inner_mcast_filter.hit_addr },
                 (bit<28>) 16384);
            // TODO : need two separate polynomials
            hash(meta.hash.hash1, HashAlgorithm.crc16,
                 (bit<14>) 0,
                 { meta.inner_mcast_filter.fixed1,
                         meta.inner_mcast_filter.rcode,
                         meta.inner_mcast_filter.bd,
                         meta.inner_mcast_filter.hit_addr },
                 (bit<28>) 16384);
            // Read Hit bits
            inner_mcast_sup_filter_table0.read(meta.inner_mcast_filter.hit0,
                                               (bit<32>) meta.inner_mcast_filter.hash0);
            inner_mcast_sup_filter_table1.read(meta.inner_mcast_filter.hit1,
                                               (bit<32>) meta.inner_mcast_filter.hash1);
            // Check if bloom filter was hit
            if (meta.inner_mcast_filter.hit0 == 1 &&
                meta.inner_mcast_filter.hit1 == 1 &&
                meta.multicast.pim_bloom_filter_en == 1)
            {
                // update hit bits
                inner_mcast_sup_filter_table0.write((bit<32>) meta.inner_mcast_filter.hash0,
                                                    (bit<1>) 1);
                inner_mcast_sup_filter_table1.write((bit<32>) meta.inner_mcast_filter.hash1,
                                                    (bit<1>) 1);
            } else {
                meta.multicast.pim_acl_key = 0;
            }
            // Zero out sup acl key field
        }
    }
}


#ifndef DISABLE_MC_BRIDGE_LOOKUPS

control process_ipv4_mc_bridge_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    /************************************************************************/
    /* IPV4 L2 Multicast lookups */
    /************************************************************************/

    // {*,G} lookup for IGMP v2
    action set_ipv4_mc_bridge_group_hit(bit<16> met0_ptr,
                                        bit<1>  met0_vld,
                                        bit<1>  use_met,
                                        bit<16> hit_addr)
    {
	meta.multicast.mc_bridge_group_lookup_hit = TRUE;
	meta.multicast.mc_bridge_group_hit_addr = hit_addr;
	meta.ingress.met0_vld = met0_vld;
	meta.ingress.met0_ptr = met0_ptr;
	meta.ingress.use_met = use_met;
    }

    table ipv4_mc_bridge_group_hash_table {
        key = {
            meta.ingress.src_bd   : exact;
            meta.ipv4m.lkp_ipv4_da : exact;
        }
        actions = {
            set_ipv4_mc_bridge_group_hit;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = IPV4_MC_BRIDGE_GROUP_HASH_TABLE_SIZE;
    }

    // TODO : add size of of_tcam
    register<bit<1>>(IPV4_MC_BRIDGE_SG_HASH_TABLE_SIZE) ipv4_mc_bridge_sg_hit_bits_table;
    
    action set_ipv4_mc_bridge_sg_hit(bit<16> met0_ptr,
                                     bit<1>  met0_vld,
                                     bit<1>  use_met,
                                     bit<16> hit_addr) {
	meta.multicast.mc_bridge_sg_lookup_hit = TRUE;
	meta.ingress.met0_vld = met0_vld;
	meta.ingress.met0_ptr = met0_ptr;
	meta.ingress.use_met = use_met;
	meta.multicast.mc_bridge_sg_hit_addr = hit_addr;
        ipv4_mc_bridge_sg_hit_bits_table.write((bit<32>) meta.multicast.mc_bridge_sg_hit_addr,
                                               1);
    }

    // {S,G} for IGMP v3

    table ipv4_mc_bridge_sg_hash_table {
        key = {
            meta.ingress.src_bd   : exact;
            meta.ipv4m.lkp_ipv4_sa : exact;
            meta.ipv4m.lkp_ipv4_da : exact;
        }
        actions = {
            set_ipv4_mc_bridge_sg_hit;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = IPV4_MC_BRIDGE_SG_HASH_TABLE_SIZE;
    }

    apply {
	if ((meta.l3.ip_da_type == IP_MULTICAST) &&
            (meta.l3.l3_type == L3TYPE_IPV4))
        {
	    if (!ipv4_mc_bridge_sg_hash_table.apply().hit) {
                ipv4_mc_bridge_group_hash_table.apply();
	    }
	}
    }
}

/*****************************************************************************/
/* IPV6 L2 Multicast lookups */
/*****************************************************************************/

control process_ipv6_mc_bridge_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // {*,G} lookup for IGMP v2
    action set_ipv6_mc_bridge_group_hit(bit<16> met0_ptr,
                                        bit<1>  met0_vld,
                                        bit<1>  use_met,
                                        bit<16> hit_addr) {
	meta.multicast.mc_bridge_group_lookup_hit = TRUE;
	meta.multicast.mc_bridge_group_hit_addr = hit_addr;
	meta.ingress.met0_vld = met0_vld;
	meta.ingress.met0_ptr = met0_ptr;
	meta.ingress.use_met = use_met;
    }

    table ipv6_mc_bridge_group_hash_table {
        key = {
            meta.ingress.src_bd : exact;
            meta.ipv6m.lkp_ipv6_da : exact;
        }
        actions = {
            set_ipv6_mc_bridge_group_hit;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = IPV6_MC_BRIDGE_GROUP_HASH_TABLE_SIZE;
    }

    // {S,G} for IGMP v3
    // TODO : add size of of_tcam
    register<bit<1>>(IPV6_MC_BRIDGE_SG_HASH_TABLE_SIZE) ipv6_mc_bridge_sg_hit_bits_table;
    
    action set_ipv6_mc_bridge_sg_hit(bit<16> met0_ptr,
                                     bit<1>  met0_vld,
                                     bit<1>  use_met,
                                     bit<16> hit_addr) {
	meta.multicast.mc_bridge_sg_lookup_hit = TRUE;
	meta.ingress.met0_vld = met0_vld;
	meta.ingress.met0_ptr = met0_ptr;
	meta.ingress.use_met = use_met;
	meta.multicast.mc_bridge_sg_hit_addr = hit_addr;
	ipv6_mc_bridge_sg_hit_bits_table.write((bit<32>) meta.multicast.mc_bridge_sg_hit_addr,
                                               1);
    }

    table ipv6_mc_bridge_sg_hash_table {
        key = {
            meta.ingress.src_bd   : exact;
            meta.ipv6m.lkp_ipv6_sa : exact;
            meta.ipv6m.lkp_ipv6_da : exact;
        }
        actions = {
            set_ipv6_mc_bridge_sg_hit;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = IPV6_MC_BRIDGE_SG_HASH_TABLE_SIZE;
    }

    apply {
	if ((meta.l3.ip_da_type == IP_MULTICAST) &&
            (meta.l3.l3_type == L3TYPE_IPV6))
        {
	    if (ipv6_mc_bridge_sg_hash_table.apply().hit) {
                ipv6_mc_bridge_group_hash_table.apply();
            }
	}
    }
}

#endif /*DISABLE_MC_BRIDGE_LOOKUPS*/


control process_mc_fib_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_bidir_rpf_pass")
    action set_bidir_rpf_pass() {
        meta.multicast.rpf_pass = TRUE;
    }
    @name("mc_bidir_rpf_hash_table")
    table mc_bidir_rpf_hash_table {
        actions = {
            set_bidir_rpf_pass;
            @default_only NoAction;
        }
        key = {
            meta.multicast.group_rpf_en         : exact;
            meta.multicast.bidir                : exact;
            meta.multicast.group_rpf_bd_or_group: exact;
            meta.ingress.src_bd                 : exact;
        }
	size = MC_RPF_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("process_ipv4_mc_route_lookup") process_ipv4_mc_route_lookup() process_ipv4_mc_route_lookup_0;
    @name("process_ipv6_mc_route_lookup") process_ipv6_mc_route_lookup() process_ipv6_mc_route_lookup_0;
    @name("process_mc_sm_rpf_check") process_mc_sm_rpf_check() process_mc_sm_rpf_check_0;
#ifndef DISABLE_MC_BRIDGE_LOOKUPS
    @name("process_ipv4_mc_bridge_lookup") process_ipv4_mc_bridge_lookup() process_ipv4_mc_bridge_lookup_0;
    @name("process_ipv6_mc_bridge_lookup") process_ipv6_mc_bridge_lookup() process_ipv6_mc_bridge_lookup_0;
#endif
    @name("process_non_ip_mc_lookup") process_non_ip_mc_lookup() process_non_ip_mc_lookup_0;
    @name("process_inner_pim_sup_key") process_inner_pim_sup_key() process_inner_pim_sup_key_0;
    apply {
        if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_MC) {
            // IP Multicast
            if (meta.l3.l3_type == L3TYPE_IPV4 ||
                meta.l3.l3_type == L3TYPE_IPV6)
            {
                // Routing
                if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) {
                    // {VRF,*,G} and {VRF,S,G} lookups
                    if (meta.l3.l3_type == L3TYPE_IPV4) {
                        process_ipv4_mc_route_lookup_0.apply(hdr, meta, standard_metadata);
                    } else if (meta.l3.l3_type == L3TYPE_IPV6) {
                        process_ipv6_mc_route_lookup_0.apply(hdr, meta, standard_metadata);
                    }
                    // RPF check
                    if (meta.multicast.bidir == TRUE) {
                        mc_bidir_rpf_hash_table.apply();
                    } else {
                        process_mc_sm_rpf_check_0.apply(hdr, meta, standard_metadata);
                    }
                }
	    
                // RPF override
//#ifdef ACI_TOR_MODE
                if (meta.CFG_aci_tor_mode.enable == 1) {
                    if ((meta.multicast.force_rpf_pass == 1) &&
                        (meta.src_bd.fib_force_rpf_pass_en == 1))
                    {
                        meta.multicast.rpf_pass = FALSE;
                    }
//#endif /*ACI_TOR_MODE*/
                }
                
                if ((meta.src_bd.is_l3_if == 1) &&
                    (meta.multicast.rpf_pass == 0))
                {
                    meta.ig_drop.mc_rpf_failure = TRUE;
                    //meta.ig_drop.inc_drop_counters = TRUE;
                }
                
#ifndef DISABLE_MC_BRIDGE_LOOKUPS
                else if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_BRIDGE) {
                    if (meta.l3.l3_type == L3TYPE_IPV4) {
                        process_ipv4_mc_bridge_lookup_0.apply(hdr, meta, standard_metadata);
                    } else if (meta.l3.l3_type == L3TYPE_IPV6) {
                        process_ipv6_mc_bridge_lookup_0.apply(hdr, meta, standard_metadata);
                    }
                }
#endif

            } else {
                // non-IP Multicast Lookup
                //if (meta.ingress.fwd_mode == FWD_MODE_NON_IP_MC) {
                process_non_ip_mc_lookup_0.apply(hdr, meta, standard_metadata);
		//}
            }
        }
        process_inner_pim_sup_key_0.apply(hdr, meta, standard_metadata);
    }
}

//#ifdef ACI_TOR_MODE

// Note : can't map sugarbowl's method of computing ftag to
// programmable h/w easily.

// TODO from jafinger - above note probably written by Ashu Agrawal.
// Why is sugarbowl's method difficult to do in programmable hw?

control process_compute_ifabric_ftag(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_ifabric_ftag")
    action set_ifabric_ftag(bit<4> ftag) {
        meta.ig_tunnel.ifabric_ftag = ftag;
    }
    @name("ifabric_ftag")
    table ifabric_ftag {
        actions = {
            set_ifabric_ftag;
            @default_only NoAction;
        }
        key = {
            meta.ig_local.ftag_addr: exact;
        }
        size = 2048;
        default_action = NoAction();
    }
    apply {
        if (meta.ig_tunnel.ftag_mode == 0) {
            // addr[7:0]=hash; addr[10:8]=active_ftag_idx
            meta.ig_local.ftag_addr =
                (bit<11>) meta.multicast.active_ftag_idx << 8;
            // TBDP416: I am not sure whether the original intent of
            // this line is to bitwise OR in 11 least significant bits
            // of hash1 into ftag_addr, or fewer bits.
            meta.ig_local.ftag_addr = (meta.ig_local.ftag_addr |
                                       (bit<11>) meta.hash.hash1);
            ifabric_ftag.apply();
        }
    }
}

//#endif /*ACI_TOR_MODE*/

control process_dst_mac_key_gen(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1 &&
            (meta.l3.arp_unicast_mode == 1) &&
            (meta.l3.l3_type == L3TYPE_RARP))
        {
            meta.dst_mac_key.addr = hdr.arp_rarp.dstHwAddr;
        } else {
            meta.dst_mac_key.addr = meta.l2.lkp_mac_da;
        }
//#endif /*ACI_TOR_MODE*/
    }
}

control process_dst_mac_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".dst_mac_miss")
    action dst_mac_miss() {
        //meta.ingress.egress_if_idx = IF_IDX_FLOOD; /*TODO*/
	meta.l2.l2_dst_hit = FALSE;
    }
    @name(".dst_mac_hit")
    action dst_mac_hit(bit<1> is_ptr, bit<13> ptr_or_idx,
                       bit<1> sup_copy, bit<1> sup_redirect
//#ifdef ACI_TOR_MODE
                       ,
                       bit<1> ep_bounce,
                       //bit<8> class_pri,
                       bit<16> class, bit<16> epg,
                       bit<1> policy_incomplete,
                       //bit<8> bind_notify_en,
                       //bit<8> class_notify_en,
                       //bit<8> addr_notify_en,
                       //bit<8> ivxlan_dl,
                       bit<1> policy_applied,
                       bit<1> shared_service, bit<1> vnid_use_bd,
                       bit<1> dst_local, bit<1> dst_vpc
//#endif /*ACI_TOR_MODE*/
                       //bit<8> secure_mac
                       ) {
        meta.l2.l2_dst_hit = TRUE;
        meta.ingress.dst_ptr_or_idx = ptr_or_idx;
        meta.ingress.dst_is_ptr = is_ptr;
        meta.dst_mac.sup_copy = sup_copy;
        meta.dst_mac.sup_redirect = sup_redirect;
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.dst_mac.policy_applied = policy_applied;
            meta.dst_mac.shared_service = shared_service;
            meta.dst_mac.ep_bounce = ep_bounce;
            meta.dst_mac.epg = epg;
            meta.dst_mac.vnid_use_bd = vnid_use_bd;
            meta.dst_mac.dst_local = dst_local;
            meta.dst_mac.dst_vpc = dst_vpc;
            meta.dst_mac.class = class;
            meta.pt_key.dst_class = class;
            meta.pt_key.dst_policy_applied = policy_applied;
            meta.pt_key.dst_policy_incomplete = policy_incomplete;
//#endif /*ACI_TOR_MODE*/
        }
    }
    @name("dst_mac_hash")
    table dst_mac_hash {
        actions = {
	    dst_mac_miss;
            dst_mac_hit;
            @default_only NoAction;
        }
        key = {
            meta.ingress.src_bd: exact;
            //meta.dst_mac_key.bd : exact;
            meta.dst_mac_key.addr       : exact;
        }
	size = MAC_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("process_dst_mac_key_gen") process_dst_mac_key_gen() process_dst_mac_key_gen_0;
    apply {
        process_dst_mac_key_gen_0.apply(hdr, meta, standard_metadata);
        if (meta.ig_tunnel.decap == 0 ||
            meta.ig_tunnel.l3_tunnel_decap == 0)
        {
            dst_mac_hash.apply();
        }
    }
}

control process_ingress_qos_key(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // ****************************
        // Key fields
        // ****************************
        
        // Pipe or uniform mode determination for tunnel termination
        if ((meta.ig_tunnel.decap == 1) &&
            (meta.src_tep.trust_cos == 0) &&
            (meta.src_tep.lkup_hit == 1))
        {
            // ~~~~ Pipe mode ~~~~
            meta.ig_qos.qos_layer = 1;
        } else {
            // ~~~~ Uniform mode for termination cases OR non-tunnel
            // forwarding mode ~~~~~
            meta.ig_qos.qos_layer = 0;
        }
        
        // DSCP/ECN
        if (meta.ig_qos.qos_layer == 1) {
            if ((hdr.inner_ipv4.isValid()) || (hdr.inner_ipv6.isValid())) {
                meta.ig_qos.acl_key_dscp_vld = TRUE;
                meta.ig_qos.acl_key_dscp = meta.ig_qos.inner_dscp;
                meta.ig_qos.acl_key_ecn = meta.ig_qos.inner_ecn;
            } else {
                meta.ig_qos.acl_key_dscp_vld = FALSE;
            }
        } else {
            //meta.ig_qos.acl_key_dscp = l3.lkp_ip_dscp;
            //meta.ig_qos.acl_key_ecn = l3.lkp_ip_ecn;
            meta.ig_qos.acl_key_dscp = meta.l3.lkp_ip_dscp;
            meta.ig_qos.acl_key_ecn = meta.l3.lkp_ip_ecn;
        }
        
        // EXP
#ifndef DISABLE_MPLS
        meta.ig_qos.acl_key_exp = meta.mplsm.topmost_non_null_label_exp; // TODO: handle null label
#endif
        
        // COS
        // By default, take it from port config
        meta.ig_qos.acl_key_cos = meta.src_if.default_cos;
        meta.ig_qos.acl_key_de = meta.src_if.default_de;
        
        // for trusted ports, take from qtag if present
        if (meta.src_if.trust_frame_cos == 1) {
            if (meta.ig_qos.qos_layer == 1) {
                if (hdr.inner_qtag0.isValid()) {
                    meta.ig_qos.acl_key_cos = hdr.inner_qtag0.pcp;
                    meta.ig_qos.acl_key_de = hdr.inner_qtag0.cfi;
                }
            } else {
                if (hdr.qtag0.isValid()) {
                    meta.ig_qos.acl_key_cos = hdr.qtag0.pcp;
                    meta.ig_qos.acl_key_de = hdr.qtag0.cfi;
                }
            }
        }
    }
}


//#ifdef ACI_TOR_MODE

// ******** Control Flow for sclass/sp_applied /sp_incomplete *********

control process_pt_key_src_class(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        /*
	if (decap && src_tep.trusted) {
	    sclass = ivxlan.sclass;
	} else if ((route || bridge_use_ip) &&
                   src_fib_hit && (fib.pri < bd.pri))
        {
	    if (dst_fib == shared_serv) {
		sclass = src_fib.ss_sclass;
	    } else {
		sclass = src_fib.sclass;
	    }
	} else if (!(route || bridge_use_ip) &&
                   src_mac_hit && (mac.pri < bd.pri))
        {
	    if (dst_mac == shared_serv) {
		sclass = src_fib.ss_sclass;
	    } else {
		sclass = src_fib.sclass;
	    }
	} else if ((fib_dst == shared_serv) || (mac_dst == shared_serv)) {
	    if (sgt_to_sclass_hit) {
		sclass = sgt.ss_sclass;
	    } else {
		sclass = bd.ss_sclass;
	    }
	} else {
	    if (sgt_to_sclass_hit) {
		sclass = sgt.sclass;
	    } else {
		sclass = bd.sclass;
	    }
	}
        */

	if ((meta.ig_tunnel.decap == 1) &&
            (meta.src_tep.trust_sclass == 1))
        {
	    // Trusted packet : take sclass from the packet
	    meta.pt_key.src_policy_applied =
                meta.src_bd.src_policy_applied | hdr.ivxlan.nonce_sp;
	    meta.pt_key.src_policy_incomplete = 0;
	    meta.pt_key.src_class = hdr.ivxlan.nonce_sclass;
	} else if ((meta.l3.src_fib_hit == 1) &&
                   (meta.src_fib.class_pri < meta.src_bd.src_class_pri))
        {
	    // FIB hit and priority is higher than BD: take sclass from FIB
	    meta.pt_key.src_policy_applied =
                meta.src_bd.src_policy_applied | meta.src_fib.policy_applied;
	    meta.pt_key.src_policy_incomplete = meta.src_fib.policy_incomplete;
	    meta.pt_key.src_class = meta.src_fib.class;
	} else if (meta.pt_key.sgt_to_sclass_hit == 1) {
	    // Packet arrived with a CMD tag: use output of
	    // sgt->sclass xlate table
            // TBDP416 - the original P4_14 code had this bitwise OR
            // with 0, which is the same as leaving out the '| 0'.
            // Why?  There is another occurrence a few lines later,
            // too.
	    meta.pt_key.src_policy_applied = meta.src_bd.src_policy_applied | 0;
	    meta.pt_key.src_policy_incomplete = meta.src_bd.src_policy_incomplete;
	    meta.pt_key.src_class = meta.pt_key.sgt_sclass;
	} else {
	    meta.pt_key.src_policy_applied = meta.src_bd.src_policy_applied | 0;
	    meta.pt_key.src_policy_incomplete = meta.src_bd.src_policy_incomplete;
	    meta.pt_key.src_class = meta.src_bd.src_class;
	}

        /*
	// Initialize src_policy_applied/incomplete
	dummy_src_policy_applied_from_bd.apply();
        
	// Trusted: take from packet
	if ((ig_tunnel.decap == 1) &&
            (src_tep.trust_sclass == 1))
        {
            dummy_src_class_from_pkt.apply();
            dummy_src_policy_applied_from_pkt.apply();
        }
	// From FIB
	else if ((ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) &&
                 (l3.src_fib_hit == 1) &&
                 (src_fib.class_pri < src_bd.src_class_pri))
        {
            // TODO : Global knob to use ip_src_class for bridged
            // traffic as well
            if (src_fib.shared_service == 1) {
                dummy_src_class_from_fib_ss.apply();
            } else {
                dummy_src_class_from_fib.apply();
            }
            dummy_src_policy_applied_from_fib.apply();
        }
        // From L2 table
        else if ((ingress.l3_fwd_mode != L3_FWD_MODE_ROUTE) &&
                 (l2.l2_src_hit == 1) &&
                 (src_mac.class_pri < src_bd.src_class_pri))
        {
            if (src_fib.shared_service == 1) {
                dummy_src_class_from_l2_ss.apply();
            } else {
                dummy_src_class_from_l2.apply();
            }
            dummy_src_policy_applied_from_l2.apply();
            // Default from BD
        } else {
            if (src_fib.shared_service == 1) {
                dummy_src_class_from_bd_ss.apply();
            } else {
                dummy_src_class_from_bd.apply();
            }
        }
        */
    }
}

// TBDP416 - consider inlining this code in the one place this control
// block is called.

control process_pt_key_class_dir(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.pt_key.src_class <= meta.pt_key.dst_class) {
            meta.pt_key.class_dir = FALSE;
            meta.pt_key.class0 = meta.pt_key.src_class;
            meta.pt_key.class1 = meta.pt_key.dst_class;
            meta.pt_key.port0 = meta.l3.lkp_l4_sport;
            meta.pt_key.port1 = meta.l3.lkp_l4_dport;
        } else {
            meta.pt_key.class_dir = FALSE;
            meta.pt_key.class0 = meta.pt_key.dst_class;
            meta.pt_key.class1 = meta.pt_key.src_class;
            meta.pt_key.port0 = meta.l3.lkp_l4_dport;
            meta.pt_key.port1 = meta.l3.lkp_l4_sport;
        }
    }
}

control process_pt_key_dst_class(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
	if ((meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) &&
            (meta.l3.dst_fib_hit == 1))
        {
	    meta.pt_key.dst_class = meta.dst_fib.class;
	} else if ((meta.ingress.l3_fwd_mode != L3_FWD_MODE_ROUTE) &&
                   (meta.l2.l2_dst_hit == 1))
        {
	    meta.pt_key.dst_class = meta.dst_mac.class;
	} else {
	    meta.pt_key.dst_class = meta.src_bd.src_class;
	}

	/*
	// Initialize src_policy_applied/incomplete
	apply(dummy_dst_policy_applied_from_bd);

	if ((ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) &&
	(l3.dst_fib_hit == 1)) {
	    apply(dummy_dst_class_from_fib);
	    apply(dummy_dst_policy_applied_from_fib);
	} else if ((ingress.l3_fwd_mode!=L3_FWD_MODE_ROUTE) &&
	(l2.l2_dst_hit == 1) ) {
	    apply(dummy_dst_class_from_l2);
	    apply(dummy_dst_policy_applied_from_l2);
	    //	} else if (l2.is_epg == 1) {
	    //	    apply(dummy_dst_class_from_epg);
	} else {
	    apply(dummy_dst_class_from_bd);
	}
	*/
    }
}

control process_policy_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    register<bit<1>>(PT_HASH_TABLE_SIZE) pt_log_status;

    @name(".read_pt_info")
    action read_pt_info(bit<2> queuing_ctrl, bit<1> mcast_flood_ctrl0,
                        bit<1> mcast_flood_ctrl1, bit<3> uplink_ctrl,
                        bit<1> deny, bit<1> log,
                        bit<1> src_policy_applied, bit<1> dst_policy_applied,
                        bit<1> service_copy, bit<2> service_oslice_vec,
                        bit<1> service_override_route, bit<1> service_redir,
                        bit<16> set_idx, bit<16> service_idx,
                        bit<1> qos_vld, bit<6> qos_map_grp,
                        bit<1> qos_map_use_dscp, bit<1> cnt_dir0,
                        bit<1> cnt_dir1, bit<1> collect_override,
                        bit<1> collect, bit<1> analytics_vld_override,
                        bit<1> analytics_vld, bit<2> mask_sel,
                        bit<2> rtt_profile, bit<1> cnt_vld,
                        bit<1> service_sample_en, bit<1> flow_sample_en,
                        bit<6> sampler_index, bit<2> service_pri,
                        bit<2> sup_pri)
    {
        // modify_field(pt_info_metadata.queuing_ctrl, queuing_ctrl);
        meta.pt_info.mcast_flood_ctrl0 = mcast_flood_ctrl0;
        meta.pt_info.mcast_flood_ctrl1 = mcast_flood_ctrl1;
        meta.pt_info.uplink_ctrl = uplink_ctrl;
        //modify_field(pt_info_metadata.deny, deny);
        meta.ig_drop.pt_deny = deny;
        meta.pt_info.log = log;
        meta.pt_info.src_policy_applied = src_policy_applied;
        meta.pt_info.dst_policy_applied = dst_policy_applied;
        meta.pt_info.service_redir = service_redir;
        // TODO maybe_wrong_cast
        meta.pt_info.service_idx = (bit<12>) service_idx;
        meta.pt_info.service_override_route = service_override_route;
        //modify_field(pt_info_metadata.service_copy ,service_copy );
        //modify_field(pt_info_metadata.service_oslice_vec ,service_oslice_vec );
        //modify_field(pt_info_metadata.set_idx ,set_idx );
        meta.ingress_sideband.srvc_oslice_vec = service_oslice_vec;
        meta.ingress_sideband.srvc_class = queuing_ctrl;
        meta.ingress_sideband.set_v = service_copy;
        meta.ingress_sideband.set_idx = set_idx;
        meta.pt_info.qos_vld = qos_vld;
        meta.pt_info.qos_map_grp = qos_map_grp;
        meta.pt_info.qos_map_use_dscp = qos_map_use_dscp;
        meta.pt_info.cnt_dir0 = cnt_dir0;
        meta.pt_info.cnt_dir1 = cnt_dir1;
        meta.pt_info.collect_override = collect_override;
        meta.pt_info.collect = collect;
        meta.pt_info.analytics_vld_override = analytics_vld_override;
        meta.pt_info.analytics_vld = analytics_vld;
        meta.pt_info.mask_sel = mask_sel;
        meta.pt_info.rtt_profile = rtt_profile;
        meta.pt_info.cnt_vld = cnt_vld;
        meta.pt_info.service_sample_en = service_sample_en;
        meta.pt_info.flow_sample_en = flow_sample_en;
        meta.pt_info.sampler_index = sampler_index;
        meta.pt_info.service_pri = service_pri;
        meta.pt_info.sup_pri = sup_pri;
        meta.pt_info.lkup_hit = TRUE;
        meta.ig_eg_header.service_redir = service_redir;
        meta.service_redir.idx = service_idx;
        meta.service_redir.pri = service_pri;
        meta.service_redir.override_route = service_override_route;
    }
    @name(".set_sclass_from_sgt")
    action set_sclass_from_sgt(bit<16> src_class) {
        meta.pt_key.sgt_sclass = src_class;
        meta.pt_key.sgt_to_sclass_hit = TRUE;
    }
    @name("pt_key_0") table pt_key_0 {
        actions = {
            read_pt_info;
            @default_only NoAction;
        }

        // TBDP416 - For sug.p4 Ashu Agarwal created new match_kind
        // values 'ternary_field' and 'mask_n_match', which are
        // given in comments below.  I have replaced them with
        // 'ternary' until I can document exactly what the new
        // ones are and implement them if needed.

        // From talking to Yogesh Bhagwat, the basic idea is that the
        // table is a hash table, but there is some extra bitwise
        // AND masking of search keys with configurable registers
        // when creating the search key, and/or before comparing
        // the search key against the one stored in the hash table
        // entries.

        key = {
            meta.pt_key.class0               : ternary;  // ternary_field
            meta.pt_key.class1               : ternary;  // ternary_field
            meta.pt_key.port0                : ternary;  // ternary_field
            meta.pt_key.port1                : ternary;  // ternary_field
            meta.l3.lkp_ip_proto             : ternary;  // ternary_field
            // Misc0
            meta.l3.l3_type_ip               : ternary; // ternary_field // replacement of L2 field
            hdr.ieth.sup_tx                    : ternary; // ternary_field
            meta.pt_key.src_policy_incomplete: ternary; // ternary_field
            meta.pt_key.dst_policy_incomplete: ternary; // ternary_field
            meta.pt_key.class_eq             : ternary; // ternary_field
            //meta.pt_key.ipv6_route         : ternary_field; // why do we need it??
            meta.pt_key.encap_transit        : ternary; // ternary_field
            meta.src_bd.sg_label             : ternary; // ternary_field // TODO: get this label from nat table when support for shared services nat is added
            // Misc1
            //meta.l3.lkp_ip_opt			: mask_n_match;
            meta.l3.ipfrag                   : ternary; // mask_n_match
            meta.pt_key.ip_frag_offset0      : ternary; // mask_n_match
            meta.pt_key.ip_frag_offset1      : ternary; // mask_n_match
            meta.l3.lkp_ip_flag_more         : ternary; // mask_n_match
            //ipv6_header                             : mask_n_match;
            meta.l3.l3_type                  : ternary; // mask_n_match
            meta.pt_key.dst_local            : ternary; // mask_n_match
            meta.pt_key.routable             : ternary; // mask_n_match
            meta.ingress.l2_fwd_mode         : ternary; // mask_n_match
            //meta.pt_key.multidest		: mask_n_match;
            meta.l3.lkp_tcp_flags            : ternary; // mask_n_match
            meta.pt_key.class_dir            : ternary; // mask_n_match
            meta.pt_key.port0                : range;
            meta.pt_key.port1                : range;
            meta.ig_qos.acl_key_dscp         : ternary; // mask_n_match
            meta.ig_qos.acl_key_ecn          : ternary; // mask_n_match
            meta.pt_key.AR                   : ternary; // mask_n_match
            meta.pt_key.ARD0                 : ternary; // mask_n_match
            meta.pt_key.ARD1                 : ternary; // mask_n_match
        }
        size = PT_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("sgt_to_sclass_xlate_hash_tbl")
    table sgt_to_sclass_xlate_hash_tbl {
        actions = {
            set_sclass_from_sgt;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.vrf: exact;
            hdr.cmd_sgt.sgt  : exact;
        }
    	size = SGT_TO_SCLASS_XLATE_HASH_TBL_SIZE;
        default_action = NoAction();
    }

    CFG_ip_frag_t CFG_ip_frag;
    action set_CFG_ip_frag_fields (bit<13> offset0, bit<13> offset1) {
        CFG_ip_frag.offset0 = offset0;
        CFG_ip_frag.offset1 = offset1;
    }
    table CFG_ip_frag_register {
        actions = {
            set_CFG_ip_frag_fields;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = 1;
    }

    @name("process_pt_key_src_class") process_pt_key_src_class() process_pt_key_src_class_0;
    @name("process_pt_key_class_dir") process_pt_key_class_dir() process_pt_key_class_dir_0;
    apply {
	// ~~~~~~~~~~~ SGT -> SCLASS translation ~~~~~~~~~~~~
        if (!sgt_to_sclass_xlate_hash_tbl.apply().hit) {
            meta.ig_drop.sgt_xlate_miss = TRUE;
        }

	// ~~~~~~~~~~ Common Key derivation ~~~~~~~~~~~~

        process_pt_key_src_class_0.apply(hdr, meta, standard_metadata);
//	process_pt_key_dst_class(); // assignments implemented earlier in the pipeline

        process_pt_key_class_dir_0.apply(hdr, meta, standard_metadata);
        if (meta.pt_key.src_class == meta.pt_key.dst_class) {
            meta.pt_key.class_eq = TRUE;
        }

//	if (valid(ipv4) || valid(ipv6)) {
//	    modify_field(pt_key.l2, FALSE);
//	} else {
//	    modify_field(pt_key.l2, TRUE);
//	}

	// PT optimization
	// AR
	meta.l3.lkp_tcp_flag_rst = (bit<1>) (meta.l3.lkp_tcp_flags >>
                                             TCP_FLAG_RST_POS);
	meta.l3.lkp_tcp_flag_ack = (bit<1>) (meta.l3.lkp_tcp_flags >>
                                             TCP_FLAG_ACK_POS);

	meta.pt_key.AR = meta.l3.lkp_tcp_flag_rst | meta.l3.lkp_tcp_flag_ack;

	//ARD0
//	if (((pt_key.AR == 1) && (pt_key.class_dir == 1)) || (pt_key.class_dir == 0)) {
	if (((meta.pt_key.AR == 1) &&
             (meta.pt_key.src_class > meta.pt_key.dst_class)) ||
            (meta.pt_key.src_class <= meta.pt_key.dst_class))
        {
	    meta.pt_key.ARD0 = TRUE;
	} else {
	    meta.pt_key.ARD0 = FALSE;
	}

	//ARD1
//	if (((pt_key.AR == 1) && (pt_key.class_dir == 0)) || (pt_key.class_dir == 1)) {
	if (((meta.pt_key.AR == 1) &&
             (meta.pt_key.src_class <= meta.pt_key.dst_class)) ||
            (meta.pt_key.src_class > meta.pt_key.dst_class))
        {
	    meta.pt_key.ARD1 = TRUE;
	} else {
	    meta.pt_key.ARD1 = FALSE;
	}

        // Identify transit cases
	if ((meta.ig_tunnel.src_encap_pkt != ENCAP_TYPE_NONE) &&
            (meta.ig_tunnel.decap == 0))
        {
	    meta.pt_key.encap_transit = TRUE;
	} else {
	    meta.pt_key.encap_transit = FALSE;
	}

	// Local vs remote destination
	if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) {
	    meta.pt_key.dst_local = meta.dst_fib.dst_local;
	} else if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_BRIDGE) {
	    meta.pt_key.dst_local = meta.dst_mac.dst_local;
	} else {
	    meta.pt_key.dst_local = 0;
	}

	// Multi-destination vs unicast
	if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) {
	    meta.pt_key.multidest = FALSE;
	} else {
	    meta.pt_key.multidest = FALSE;
	}

	// Fragment offset
        CFG_ip_frag_register.apply();
        if (meta.l3.lkp_ip_fragOffset < CFG_ip_frag.offset0) {
	    meta.pt_key.ip_frag_offset0 = TRUE;
	} else {
	    meta.pt_key.ip_frag_offset0 = FALSE;
	}
	if (meta.l3.lkp_ip_fragOffset < CFG_ip_frag.offset1) {
	    meta.pt_key.ip_frag_offset1 = TRUE;
	} else {
	    meta.pt_key.ip_frag_offset1 = FALSE;
	}

	//v6_route
	// parsing of route option is not supported

	// routable
	if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) {
	    meta.pt_key.routable = TRUE;
	} else {
	    meta.pt_key.routable = FALSE;
	}

	// Encapsulated flood packets. Perform inner lookup. If
	// destination is remote OR we are not DF, don't apply policy
	if ((meta.ig_tunnel.encap_flood == 1) &&
            (meta.src_bd.encap_flood_fwd_rslt_en == 1) &&
            (meta.l2.l2_dst_hit == 1) &&
            (meta.dst_mac.dst_local == 0) &&
            ((meta.ingress.vpc_df == 0) &&
             (meta.dst_mac.dst_vpc == 1)))
        {
	    meta.pt_key.policy_skip_remote_tep = FALSE;
	} else {
	    meta.pt_key.policy_skip_remote_tep = TRUE;
	}

	// ~~~~~~~~~~~~~~ policy table lookup ~~~~~~~~~~~~~~~
        if ((meta.pt_key.src_policy_applied == 0 ||
             meta.pt_key.dst_policy_applied == 0) &&
            meta.pt_key.policy_skip_remote_tep == 0)
        {
            if (pt_key_0.apply().hit) {
                // ~~~~~~~~~~~ permit/deny log ~~~~~~~~~~~~~~~~~~~~~~
                pt_log_status.read(meta.pt_info.log_status,
                                   (bit<32>) meta.pt_info.hit_idx);
                if ((meta.pt_info.log == 1) &&
                    (meta.pt_info.log_status == 0))
                {
                    meta.ig_acl.sup_code = PT_LOG_SUP_CODE;
                    meta.ig_acl.sup_qnum = PT_LOG_SUP_QNUM;
                    meta.ig_acl.sup_dst = PT_LOG_SUP_DST;
                    meta.ig_acl.sup_copy = TRUE;
                    meta.ig_acl.sup_pri = meta.pt_info.sup_pri;
                    pt_log_status.write((bit<32>) meta.pt_info.hit_idx, 1);
                }
                
#ifndef DISABLE_PT_STATS
                // ~~~~~~~~~~~ stats ~~~~~~~~~~~~~~~~~~~~~
                if (((meta.pt_info.cnt_dir0 == 1) &&
                     (meta.pt_key.class_dir == 0)) ||
		    ((meta.pt_info.cnt_dir1 == 1) &&
                     (meta.pt_key.class_dir == 1)))
                {
                    //count(pt_stats, meta.pt_info.hit_idx);
                }
#endif /*DISABLE_PT_STATS*/
            }
        }
    }
}

//#endif /*ACI_TOR_MODE*/

control process_service_redir_lookup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".select_service_redir_ecmp_member")
    action select_service_redir_ecmp_member(bit<8> base, bit<8> num_paths) {
        // replace ipv4_hash1 with correct hash value
        hash(meta.service_redir.mp_mbr, HashAlgorithm.crc16,
             (bit<16>) base,
             { meta.ipv4m.lkp_ipv4_sa,
                     meta.ipv4m.lkp_ipv4_da,
                     meta.l3.lkp_ip_proto,
                     meta.l3.lkp_l4_sport,
                     meta.l3.lkp_l4_dport },
             (bit<32>) num_paths);
    }
    @name("service_mp_cfg")
    table service_mp_cfg {
        actions = {
            select_service_redir_ecmp_member;
            @default_only NoAction;
        }
        key = {
            meta.service_redir.idx: exact;
        }
	size = SERVICE_MP_CFG_TABLE_SIZE;
        default_action = NoAction();
    }

    @name(".select_service_mp_info")
    action select_service_mp_info(bit<13> dst_ptr) {
	//meta.ig_tunnel.encap = TRUE;
        meta.ingress.dst_ptr_or_idx = dst_ptr;
        meta.ingress.dst_is_ptr = TRUE;
    }
    @name("service_mp_mbr")
    table service_mp_mbr {
        actions = {
            select_service_mp_info;
            @default_only NoAction;
        }
        key = {
            meta.service_redir.mp_mbr: exact;
        }
	size = SERVICE_MP_MBR_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        // Service redirection based on policy or epg/bd
        /*
	if (pt_info.service_redir==1) {
	    //TODO : sampler
	    //TODO : knob service_override_route_en
	    service_redir.vld = TRUE;
	    service_redir.idx = pt_info.service_idx;
	    service_redir.pri = pt_info.service_pri;
	    service_redir.override_route = pt_info.service_override_route;
	} else if (src_bd.service_redir==1) {
	    service_redir.vld = TRUE;
	    service_redir.idx = src_bd.service_idx;
	    service_redir.pri = src_bd.service_redir_pri;
	    service_redir.override_route = 0;
	}
        */
	if (meta.service_redir.vld == 1) {
	    meta.ingress.l2_fwd_mode = L2_FWD_MODE_UC;
//	    if (meta.service_redir.override_route == 1) {
//		meta.ingress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
//	    }
	    // Multipathing information for service destination
            service_mp_cfg.apply();
            service_mp_mbr.apply();
	}
    }
}

/*****************************************************************************/
/* After Host lookup forwarding mode decision */
/*****************************************************************************/

// TBDP416 - there is an action generate_learn_notify() in the
// original P4_14 code that might not be called from anywhere there,
// so it was not translated.  Where should it be called from, if it
// should?

control process_learn_notify(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("learn_equations") table learn_equations {
        actions = {
            @default_only NoAction;
        }
        key = {
            // BD Knobs
            meta.src_bd.mac_learn_en           : ternary;
            meta.src_bd.ip_learn_en            : ternary;
            meta.src_bd.sclass_learn_en        : ternary;
            // Port Knobs
            meta.src_if_profile.mac_learn_en   : ternary;
            meta.src_if_profile.ip_learn_en    : ternary;
            meta.src_if_profile.sclass_learn_en: ternary;
            meta.ingress.ifabric_ingress       : ternary;
            // Src TEP knobs
            meta.ig_tunnel.decap               : ternary;
            meta.src_tep.mac_learn_en          : ternary;
            meta.src_tep.ip_learn_en           : ternary;
            meta.src_tep.sclass_learn_en       : ternary;
            meta.src_tep.trust_dl              : ternary;
            // DL bit from ivxlan header
            hdr.ivxlan.isValid()                 : exact;
            hdr.ivxlan.nonce_dl                  : ternary;
            // TODO : learn enable from GIPo
            // Learn enable from the L2/IP entry
            meta.src_fib.addr_notify_en        : ternary;
            meta.src_fib.bind_notify_en        : ternary;
            meta.src_fib.class_notify_en       : ternary;
            meta.src_mac.addr_notify_en        : ternary;
            meta.src_mac.bind_notify_en        : ternary;
            meta.src_mac.class_notify_en       : ternary;
            meta.bypass_info.learn_bypass      : ternary;

            // L2 miss/move
            meta.l2.l2_src_hit                 : ternary;
            meta.l2.l2_src_move                : ternary;
            // IP miss
            meta.l3.src_fib_hit                : ternary;
            // Forwarding mode
            meta.ingress.l3_fwd_mode           : ternary;
            meta.l3.src_ecmp_vld               : ternary;
            // packet type
            meta.l3.l3_type                    : ternary;
            // Miss/Move events
            meta.l3.ip_mac_binding_failure     : ternary;
            meta.l3.ip_sclass_binding_failure  : ternary;
            meta.l2.mac_sclass_binding_failure : ternary;
        }
        size = 64;
        default_action = NoAction();
    }
    apply {
        // Notify vector fields
        if (meta.ig_tunnel.decap == 1) {
            meta.notify_vec.src_is_ptr = TRUE;
            // TODO maybe_wrong_cast
            meta.notify_vec.src_ptr_or_idx = (bit<14>) meta.src_tep.src_ptr;
        } else {
            meta.notify_vec.src_is_ptr = FALSE;
            // TODO maybe_wrong_cast
            meta.notify_vec.src_ptr_or_idx = (bit<14>) meta.ingress.src_if_idx;
        }
        
        //meta.notify_vec.src_ip_type = meta.l3.l3_type;
        if ((meta.l3.l3_type == L3TYPE_IPV4) ||
            (meta.l3.l3_type == L3TYPE_ARP))
        {
            // TODO maybe_wrong_cast
            meta.notify_vec.src_ip_addr = (bit<128>) meta.ipv4m.lkp_ipv4_sa;
        } else {
            meta.notify_vec.src_ip_addr = meta.ipv6m.lkp_ipv6_sa;
        }
        
        // ~~~~~~ mac-interface binding ~~~~~~
        if (meta.l2.l2_src_hit == 1) {
            if ((meta.src_mac.is_ptr != meta.notify_vec.src_is_ptr) ||
                (meta.src_mac.ptr_or_idx != meta.notify_vec.src_ptr_or_idx))
            {
                meta.l2.l2_src_move = TRUE;
            } else {
                meta.l2.l2_src_move = FALSE;
            }
        } else {
            meta.l2.l2_src_move = FALSE;
        }
        
        // ~~~~~~ ip-mac binding ~~~~~~
        // total operand size is 132 bits hence breaking the operation
        // into two parts
        if (meta.src_adj.mac != meta.l2.lkp_mac_sa) {
            meta.ig_local.src_mac_mismatch = TRUE;
        } else {
            meta.ig_local.src_mac_mismatch = FALSE;
        }
        
        if ((meta.l3.src_fib_hit == 1) &&
            (meta.l3.src_ecmp_vld == 0) &&
            (meta.l2.l2_src_hit == 1) &&
            (meta.src_fib.default_entry == 0) &&
            ((meta.src_adj.bd != meta.ingress.src_bd) ||
             (meta.ig_local.src_mac_mismatch == 1)))
            // (src_adj.mac != l2.lkp_mac_sa))) {
        {
            meta.l3.ip_mac_binding_failure = TRUE;
        } else {
            meta.l3.ip_mac_binding_failure = FALSE;
        }
        
        // ~~~~~~ ip-sclass binding ~~~~~~
        if ((meta.l3.src_fib_hit == 1) &&
            (meta.src_fib.default_entry == 0) &&
            (meta.src_fib.class != meta.pt_key.src_class))
        {
            meta.l3.ip_sclass_binding_failure = TRUE;
        } else {
            meta.l3.ip_sclass_binding_failure = FALSE;
        }
        
        
        // ~~~~~~ mac-sclass binding ~~~~~~
        if ((meta.l2.l2_src_hit == 1) &&
            (meta.src_mac.class != meta.pt_key.src_class)) {
            meta.l2.mac_sclass_binding_failure = TRUE;
        } else {
            meta.l2.mac_sclass_binding_failure = FALSE;
        }
        learn_equations.apply();
    }
}

control process_dst_bd(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_dst_bd_state")
    action set_dst_bd_state(bit<16> flood_met_ptr, bit<16> omf_met_ptr,
                            bit<8> acl_label, bit<4> mtu_idx)
    {
        meta.ig_dst_bd.flood_met_ptr = flood_met_ptr;
        meta.ig_dst_bd.omf_met_ptr = omf_met_ptr;
        meta.ig_dst_bd.acl_label = acl_label;
        meta.ig_dst_bd.mtu_idx = mtu_idx;
	/* TODO
	src_bd.uuc_flood_offset = uuc_flood_offset;
	src_bd.umc_flood_offset = umc_flood_offset;
	src_bd.bc_flood_offset = bc_flood_offset;
	src_bd.ipv4_omf_offset = ipv4_omf_offset;
	src_bd.ipv6_omf_offset = ipv6_omf_offset;
	*/
	// set post-route flood Destination pointer 
	//meta.egress.smac_idx = smac_idx;
    }
    @name("dst_bd_state") table dst_bd_state {
        actions = {
            set_dst_bd_state;
            @default_only NoAction;
        }
        key = {
            meta.ingress.dst_bd: exact;
        }
        size = DST_BD_STATE_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
	//if ((meta.l3.dst_fib_hit == 1) &&
        //    (meta.ingress.l3_fwd_mode == L3_FWD_MODE_MPLS) ||
        //    (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE))
        //{
	//if ((meta.l3.dst_fib_hit == 1) &&
        //    (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE))
        //{
	if (meta.l3.dst_fib_hit == 1) {
	    // TODO : assumption here is that l3_mode is set to route
	    // for arp/nd unicast
	    if (meta.dst_fib.preserve_vrf == 1) {
		meta.ingress.dst_bd = meta.src_bd.vrf;
//#ifdef ACI_TOR_MODE
                if (meta.CFG_aci_tor_mode.enable == 1) {
                    meta.ingress.dst_epg = meta.src_bd.vrf;
                }
//#endif /*ACI_TOR_MODE*/
	    } else {
		meta.ingress.dst_bd = meta.dst_adj.bd;
//#ifdef ACI_TOR_MODE
                if (meta.CFG_aci_tor_mode.enable == 1) {
                    // TODO maybe_wrong_cast
                    meta.ingress.dst_epg = (bit<14>) meta.dst_fib.epg;
                }
//#endif /*ACI_TOR_MODE*/
	    }
	} else if (meta.l2.l2_dst_hit == 1) {
//#ifdef ACI_TOR_MODE
            if (meta.CFG_aci_tor_mode.enable == 1) {
                // TODO maybe_wrong_cast
                meta.ingress.dst_epg = (bit<14>) meta.dst_mac.epg;
            }
//#endif /*ACI_TOR_MODE*/
	    meta.ingress.dst_bd = meta.ingress.src_bd;
	} else {
	    meta.ingress.dst_bd = meta.ingress.src_bd;
//#ifdef ACI_TOR_MODE
            if (meta.CFG_aci_tor_mode.enable == 1) {
                meta.ingress.dst_epg = meta.ingress.src_epg;
            }
//#endif /*ACI_TOR_MODE*/
	}
        dst_bd_state.apply();
    }
}


/*****************************************************************************/
/* After Host loolkup forwarding mode decision */
/*****************************************************************************/

// erspan_term
// encap_flood - not df - lookup bypassed.
// encap_flood - ifabric ingress - forwarding using inner only
// encap_flood - post inner lookup - remote or not df
// encap_flood - post inner lookup - local - terminate outer and use inner only
// encap_flood - miss - flood on outer only
//             - miss - flood on both outer and inner

// bridge - hit/miss
//        - miss - if spine-proxy is enabled - send to spine proxy
// route - hit/miss
//       - post_route_flood
//       - NLB
// fcf - hit/miss
// mpls - hit/miss
//      - hit post-route-flood
//      - hit _ frr event
// arp unicast - ip hit/miss 
// rarp unicast - mac hit/miss
// spine proxy hit on egress - glean
// proxy_up

// Multicast
// igmp-mld - omf
// multicast - hit or miss
// miss - omf or flood

control process_post_lookup_forwarding_mode(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_post_lookup_fwd_mode_uc_flood")
    action set_post_lookup_fwd_mode_uc_flood() {
        meta.ingress.l2_fwd_mode = L2_FWD_MODE_FLOOD;
        meta.ingress.met0_vld = TRUE;
        meta.ingress.met0_ptr = meta.ig_dst_bd.flood_met_ptr;
    }
    @name(".set_post_lookup_fwd_mode_mc_flood")
    action set_post_lookup_fwd_mode_mc_flood() {
        // Unknown multicast flood
        meta.ingress.l2_fwd_mode = L2_FWD_MODE_FLOOD;
//#ifdef DISABLE_UNEQUAL_WIDTH_OPS
        meta.ingress.met0_vld = TRUE;
        meta.ingress.met0_ptr = meta.ig_dst_bd.flood_met_ptr;
//#else 
//        meta.ingress.flood_dst_ptr = meta.ig_dst_bd.flood_dst_ptr + meta.ig_dst_bd.l2mc_offset;
//#endif
    }
    @name(".set_post_lookup_fwd_mode_mc_omf")
    action set_post_lookup_fwd_mode_mc_omf() {
        // Unknown multicast flood
        meta.ingress.l2_fwd_mode = L2_FWD_MODE_FLOOD;
//#ifdef DISABLE_UNEQUAL_WIDTH_OPS
        meta.ingress.met0_vld = TRUE;
        meta.ingress.met0_ptr = meta.ig_dst_bd.omf_met_ptr;
//#else 
//        meta.ingress.flood_dst_ptr = meta.ig_dst_bd.flood_dst_ptr + meta.ig_dst_bd.l2mc_offset;
//#endif
    }
    @name(".set_post_lookup_bridge_miss_drop")
    action set_post_lookup_bridge_miss_drop() {
        meta.ig_drop.bridge_miss = TRUE;
        //meta.ig_drop.inc_drop_counters = TRUE;
    }
    @name(".set_post_lookup_route_miss_drop")
    action set_post_lookup_route_miss_drop() {
        meta.ig_drop.route_miss = TRUE;
        //meta.ig_drop.inc_drop_counters = TRUE;
    }
#ifndef DISABLE_MPLS
    action set_post_lookup_mpls_miss_drop() {
        meta.ig_drop.mpls_miss = TRUE;
    }
#endif /*DISABLE_MPLS*/
#ifndef DISABLE_FCF
    action set_post_lookup_fcf_miss_drop() {
        meta.ig_drop.fcf_miss = TRUE;
    }
#endif /*DISABLE_FCF*/
    @name(".set_post_lookup_spine_proxy_fwd")
    action set_post_lookup_spine_proxy_fwd() {
        meta.ingress.dst_is_ptr = TRUE;
        // TODO maybe_wrong_cast
        meta.ingress.dst_ptr_or_idx =
            (bit<13>) meta.ig_local.spine_proxy_dst_ptr;
    }
    @name(".set_post_lookup_fwd_inner_only")
    action set_post_lookup_fwd_inner_only() {
        meta.ingress.met1_vld = TRUE;
    }
    @name(".set_post_lookup_fwd_outer_only")
    action set_post_lookup_fwd_outer_only() {
        meta.ingress.l2_fwd_mode = L2_FWD_MODE_FLOOD;
        meta.ingress.met0_vld = FALSE;
    }
    @name(".set_post_lookup_egress_tor_glean")
    action set_post_lookup_egress_tor_glean() {
        meta.l3.egress_tor_glean = TRUE;
    }
    @name("post_lookup_fwd_mode") table post_lookup_fwd_mode {
    actions = {
            set_post_lookup_fwd_mode_uc_flood;
            set_post_lookup_fwd_mode_mc_flood;
            set_post_lookup_fwd_mode_mc_omf;
            set_post_lookup_bridge_miss_drop;
            set_post_lookup_route_miss_drop;
#ifndef DISABLE_FCF
            set_post_lookup_fcf_miss_drop;
#endif /*DISABLE_FCF*/
#ifndef DISABLE_MPLS
            set_post_lookup_mpls_miss_drop;
#endif /*DISABLE_MPLS*/
            set_post_lookup_spine_proxy_fwd;
            set_post_lookup_fwd_inner_only;
            set_post_lookup_fwd_outer_only;
            set_post_lookup_egress_tor_glean;
            @default_only NoAction;
        }
        key = {
            meta.ingress.l2_fwd_mode                  : ternary;
            meta.ingress.l3_fwd_mode                  : ternary;
            meta.ingress.ifabric_ingress              : ternary;
            //meta.ingress.ifabric_egress           : ternary;
            
            // BD knobs
            meta.src_bd.unknown_uc_flood              : ternary;
            meta.src_bd.unknown_uc_proxy              : ternary;
            meta.src_bd.arp_unicast_flood_on_miss     : ternary;
            meta.src_bd.encap_flood_outer_only_on_miss: ternary;
            meta.src_bd.unknown_mc_flood              : ternary;

            // hit/miss
            meta.l2.l2_dst_hit                        : ternary;
            meta.l3.dst_fib_hit                       : ternary;
            meta.l2.l2_da_type                        : ternary;
            meta.multicast.mc_route_group_lookup_hit  : ternary;
            meta.multicast.default_entry              : ternary;
            meta.multicast.rpf_pass                   : ternary;

            // Flood-to-routers or flood-to-bd
            meta.src_bd.v4_omf                        : ternary;
            meta.src_bd.v6_omf                        : ternary;

            // lookup for multicast-outside-unicast-inside
            meta.ig_tunnel.encap_flood_fwd_lkup       : ternary;
            meta.dst_mac.dst_local                    : ternary;
            meta.dst_mac.dst_vpc                      : ternary;
            meta.ingress.vpc_df                       : ternary;

            // Glean spine-proxy on egress tor
            meta.dst_fib.spine_proxy                  : ternary;

            // Spine proxy for L2
            meta.dst_mac.spine_proxy                  : ternary;

            // Service redirection
            meta.service_redir.vld                    : ternary;
            meta.service_redir.override_route         : ternary;

            // erspan_term
            meta.ig_tunnel.erspan_term                : ternary;
        }
        size = FWD_MODE_TABLE_SIZE;
        default_action = NoAction();
    }

//#ifdef ACI_TOR_MODE
    /************************************************************************/
    /* Spine-proxy destination pointer */
    /************************************************************************/
    @name(".set_spine_proxy_dst_ptr")
    action set_spine_proxy_dst_ptr(bit<14> dst_ptr) {
        //meta.ingress.dst_is_ptr = TRUE;
        //meta.ingress.dst_ptr_or_idx = dst_ptr;
        meta.ig_local.spine_proxy_dst_ptr = dst_ptr;
    }
    @name("spine_proxy") table spine_proxy {
        actions = {
            set_spine_proxy_dst_ptr;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.spine_proxy_idx: exact;
        }
        size = SPINE_PROXY_DST_TABLE_SIZE;
        default_action = NoAction();
    }
//#endif /*ACI_TOR_MODE*/

    apply {
#ifdef USE_TABLE_FOR_FWD_MODE

//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            // Spine-proxy
            spine_proxy.apply();
            // TODO : handle ivleaf case
//#endif /*ACI_TOR_MODE*/
        }

        post_lookup_fwd_mode.apply();

#else /*USE_TABLE_FOR_FWD_MODE*/
    
        if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) {
            if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_BRIDGE) {
                if (meta.l2.l2_dst_hit == 0) {
                    if (meta.src_bd.unknown_uc_flood == 1) {
                        // Unknown unicast flood
                        meta.ingress.l2_fwd_mode = L2_FWD_MODE_FLOOD;
                        meta.ingress.flood_dst_ptr = meta.src_bd.flood_dst_ptr;
//#ifdef ACI_TOR_MODE
                    } else if (meta.CFG_aci_tor_mode.enable == 1 &&
                               (meta.src_bd.unknown_uc_proxy == 1) &&
                               (meta.ingress.ifabric_ingress == 1))
                    {
                        // Spine-proxy
                        apply(spine_proxy);
                        // TODO : handle ivleaf case
//#endif /*ACI_TOR_MODE*/
                    } else {
                        // Drop unknown unicast
                        meta.ig_drop.bridge_miss = TRUE;
                        //meta.ig_drop.inc_drop_counters = TRUE;
                    }
                } else {
                    // already taken care of in dst_mac_hit action
                }
#ifndef DISABLE_FCF
            } else if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_FCF) {
                if (meta.l3.dst_fib_hit == 1) {
                } else {
                    meta.ig_drop.fcf_miss = TRUE;
                    //meta.ig_drop.inc_drop_counters = TRUE;
                }
#endif /*DISABLE_FCF*/
#ifndef DISABLE_MPLS
            } else if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_MPLS) {
                if (meta.l3.dst_fib_hit == 1) {
                } else {
                    meta.ig_drop.mpls_miss = TRUE;
                    //meta.ig_drop.inc_drop_counters = TRUE;
                }
#endif /*DISABLE_MPLS*/
            } else if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) {
                if (meta.l3.dst_fib_hit == 1) {
                } else {
                    meta.ig_drop.route_miss = TRUE;
                    //meta.ig_drop.inc_drop_counters = TRUE;
                }
            } else {
            }
        } else if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_FLOOD) {
            if (meta.l2.l2_da_type == L2_MULTICAST) {
                // Unknonw multicast flood 
#ifndef DISABLE_UNEQUAL_WIDTH_OPS
                meta.ingress.flood_dst_ptr = (meta.src_bd.flood_dst_ptr +
                                              meta.src_bd.l2mc_offset);
#endif
            } else if (meta.l2.l2_da_type == L2_BROADCAST) {
                // Broadcast
#ifndef DISABLE_UNEQUAL_WIDTH_OPS
                meta.ingress.flood_dst_ptr = (meta.src_bd.flood_dst_ptr +
                                              meta.src_bd.bc_offset);
#endif
            } else {
                // Unknown unicast flood
                meta.ingress.flood_dst_ptr = meta.src_bd.flood_dst_ptr;
            }
        } else if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_BC) {
            // Broadcast
#ifndef DISABLE_UNEQUAL_WIDTH_OPS
            meta.ingress.flood_dst_ptr = (meta.src_bd.flood_dst_ptr +
                                          meta.src_bd.bc_offset);
#endif
        } else {
            // Multicast
            if ((meta.multicast.mc_route_group_lookup_hit == 0) ||
                (meta.multicast.default_entry == 1))
            {
                // Unknown multicast flood
                meta.ingress.l2_fwd_mode = L2_FWD_MODE_FLOOD;
#ifndef DISABLE_UNEQUAL_WIDTH_OPS
                meta.ingress.flood_dst_ptr = (meta.src_bd.flood_dst_ptr +
                                              meta.src_bd.l2mc_offset);
#endif
            } else {
            }
        }

#endif /*USE_TABLE_FOR_FWD_MODE*/

        // Detect EP bounce
        if (((meta.dst_fib.ep_bounce == 1) ||
             (meta.dst_mac.ep_bounce == 1)) &&
            (meta.ingress.ifabric_ingress == 0))
        {
            meta.ingress.ep_bounce = TRUE;
        }
        
        // Check eligibility of vpc_bounce
        // Assuming there is no VL->VL traffic in ACI.
        if ((meta.ig_tunnel.decap == 0) ||
            (meta.src_tep.is_vpc_peer == 0))
        {
            meta.ingress.vpc_bounce_en = TRUE;
        }
    }
}

control process_storm_control(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("storm_control_meter")
    meter(STORM_CONTROL_METER_TABLE_SIZE, MeterType.bytes) storm_control_meter;
    @name(".set_storm_control_meter")
    action set_storm_control_meter(bit<8> meter_idx) {
        storm_control_meter.execute_meter((bit<32>)meter_idx,
                                          meta.ingress.storm_control_drop);
    }
    @name("storm_control")
    table storm_control {
        actions = {
            set_storm_control_meter;
            @default_only NoAction;
        }
        key = {
            meta.ingress.src_if_idx: exact;
            meta.l2.l2_da_type     : ternary;
        }
        size = STORM_CONTROL_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        storm_control.apply();
    }
}


// TBDP416 - In the original code, several of the tables in the
// control block below have "dummy_" at the beginning of their name.
// However, unlike most other places where that naming convention was
// used, these have counters associated with them, so either they need
// to have non-0 sizes and not be dummy, or the statistics should be
// collected in a different way in this code.

control process_port_security(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_non_secure_mac_drop")
    action set_non_secure_mac_drop() {
        meta.ig_drop.non_secure_mac = TRUE;
	//meta.ig_drop.inc_drop_counters = TRUE;
    }
    @name(".set_secure_mac_move_drop")
    action set_secure_mac_move_drop() {
        meta.ig_drop.secure_mac_move = TRUE;
	//meta.ig_drop.inc_drop_counters = TRUE;
    }
    @name(".set_smac_miss_drop")
    action set_smac_miss_drop() {
        meta.ig_drop.smac_miss = TRUE;
	//meta.ig_drop.inc_drop_counters = TRUE;
    }
    @name("dummy_non_secure_mac_drop")
    table dummy_non_secure_mac_drop {
        actions = {
            set_non_secure_mac_drop;
            @default_only NoAction;
        }
        default_action = NoAction();
        @name("non_secure_mac_drop_counts")
        counters = direct_counter(CounterType.packets);
    }
    @name("dummy_secure_mac_move_drop")
    table dummy_secure_mac_move_drop {
        actions = {
            set_secure_mac_move_drop;
            @default_only NoAction;
        }
        default_action = NoAction();
        @name("secure_mac_move_drop_counts")
        counters = direct_counter(CounterType.packets);
    }
    @name("dummy_smac_miss_drop")
    table dummy_smac_miss_drop {
        actions = {
            set_smac_miss_drop;
            @default_only NoAction;
        }
        default_action = NoAction();
        @name("smac_miss_drop_counts")
        counters = direct_counter(CounterType.packets);
    }
    apply {
        if (meta.src_if.drop_on_smac_miss == 1 && meta.l2.l2_src_hit == 0) {
            dummy_smac_miss_drop.apply();
        }
        if (meta.l2.l2_src_move == 1 && meta.l2.src_secure_mac == 1) {
            dummy_secure_mac_move_drop.apply();
        }
        if (meta.src_if.drop_non_secure_mac == 1 &&
            meta.l2.l2_src_hit == 1 &&
            meta.l2.src_secure_mac == 1)
        {
            dummy_non_secure_mac_drop.apply();
        }
    }
}

#ifndef DISABLE_L2_BIND_CHECK
/*****************************************************************************/
/* L2 Bind Check                                                             */
/*****************************************************************************/

control process_l2_bind_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_l2_bind_failure")
    action set_l2_bind_failure() {
        meta.ig_drop.l2_bind_failure = TRUE;
        //meta.ig_drop.inc_drop_counters = TRUE;
    }
    @name("dummy_l2_bind_failure")
    table dummy_l2_bind_failure {
        actions = {
            set_l2_bind_failure;
            @default_only NoAction;
        }
        default_action = NoAction();
        @name("l2_bind_failure_counts")
        counters = direct_counter(CounterType.packets);
    }
    apply {
        if (meta.src_if.l2_bind_check_en == 1 &&
            meta.src_bd.l2_bind_check_en == 1 &&
            meta.l2.l2_src_move == 1 &&
            meta.l2.l2_src_hit == 1)
        {
            dummy_l2_bind_failure.apply();
        }
    }
}
#endif /*DISABLE_L2_BIND_CHECK*/

#ifndef DISABLE_L3_BIND_CHECK
/*****************************************************************************/
/* IP Sourceguard                                                            */
/* TODO: add arp/rarp/nd knobs and cases */
/*****************************************************************************/

control process_l3_bind_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (
            //(meta.bypass_info.l3_bind_bypass == 1) ||
            (meta.src_if.l3_bind_check_en == 0) ||
            (meta.src_bd.l3_bind_check_en == 0) ||
            ((meta.l3.l3_type != L3TYPE_IPV4) &&
             (meta.l3.l3_type != L3TYPE_IPV6)))
        {
            meta.ig_drop.l3_binding_failure = FALSE;
            //meta.ig_drop.inc_drop_counters = TRUE;
        } else if (meta.l3.ip_mac_binding_failure == 1) {
            meta.ig_drop.l3_binding_failure = TRUE;
            //meta.ig_drop.inc_drop_counters = TRUE;
        }
    }
}

//TODO
#endif /*DISABLE_L3_BIND_CHECK*/

#ifndef DISABLE_URPF_CHECK
/*****************************************************************************/
/* uRPF check                                                                */
/*****************************************************************************/

control process_urpf_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    //action urpf_miss() {
    //    meta.l3.urpf_fail = TRUE;
    //}
    action urpf_pass() {
        meta.l3.urpf_pass = TRUE;
    }
    //action urpf_fail() {
    //    meta.l3.urpf_fail = TRUE;
    //}
    table urpf_hash_table {
        /* First  program overflow entries  - urpf_pass */
        /* Then Program these static entries in order of priority */
        // {disable      , *, *, *, *} -> urpf_pass
        // {loose_default, 1, *, *, *} -> urpf_pass 
        // {loose,         1, 0, *, *} -> urpf_pass
        /* Last entry is a catchall -> urpf_fail */
        key = {
            //TODO meta.l3.rpf_type            : ternary;
            // meta.l3.fib_sa_hit           : ternary;
            // meta.l3.fib_sa_default_entry : ternary;
	    meta.l3.urpf_group  : exact;
	    meta.ingress.src_bd : exact;
        }
        actions = {
            //urpf_miss;
            urpf_pass;
            //urpf_fail;
            NoAction;
        }
        default_action = NoAction();
        size = URPF_HASH_TABLE_SIZE;
    }
    apply {
        if (meta.l3.src_ecmp_vld == 1) {
            // TODO maybe_wrong_cast
            meta.l3.urpf_group = (bit<14>) meta.l3.src_ecmp_ptr;
        } else {
            // TODO maybe_wrong_cast
            meta.l3.urpf_group = (bit<14>) meta.l3.src_adj_ptr;
        }
        
        if (meta.bypass_info.rpf_bypass == 1) {
            meta.l3.urpf_pass = 1;
        } else if ((meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) &&
                   (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE))
        {
            if (meta.l3.urpf_type == uRPF_MODE_DISABLE) {
                meta.l3.urpf_pass = 1;
            } else if (meta.l3.src_fib_hit == 1) {
                if (!urpf_hash_table.apply().hit) {
                    if (meta.l3.urpf_type == uRPF_MODE_LOOSE) {
                        meta.l3.urpf_pass = 1;
                    } else if ((meta.l3.urpf_type == uRPF_MODE_LOOSE_ALLOW_DEFAULT) &&
                               (meta.src_fib.default_entry == 0))
                    {
                        meta.l3.urpf_pass = 1;
                    } else {
                        meta.l3.urpf_pass = 0;
                        meta.ig_drop.uc_rpf_failure = 1;
                        //meta.ig_drop.inc_drop_counters = TRUE;
                    }
                }
            }
        }
    }
}

/*
switch (bd_state_table.rpf_type)
{
    DISABLE      : check = pass;                                                
    LOOSE_DEFAULT: check = fib_sa lookup hit;                                   
    LOOSE        : check = fib_sa lookup hit && !fib_sa_result.default_entry;   
    STRICT       : check = fib_sa lookup hit && rpf lookup hit;                 
}
}
*/

#endif /*DISABLE_URPF_CHECK*/


control process_ipv6_ll_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // V6 link local unicast cross-bd check
        // Unicast routing + Src/Dst link-local + bd crossing
        if ((meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) &&
            (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) &&
            (meta.l3.dst_fib_hit == 1) &&
            ((meta.l3.ip_da_type == IP_UNICAST_LL) ||
             (meta.l3.ip_sa_type == IP_UNICAST_LL)) &&
            (meta.src_bd.enforce_v6_link_local_uc == 1) &&
            (meta.ingress.src_bd != meta.ingress.dst_bd))
        {
            meta.ig_drop.ipv6_uc_link_local_cross_bd = 1;
            //meta.ig_drop.inc_drop_counters = TRUE;
        }
        
        // Multicast routing + source link-local + destination global
        if ((meta.ingress.l2_fwd_mode == L2_FWD_MODE_MC) &&
            (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) &&
            (meta.l3.dst_fib_hit == 1) &&
            (meta.l3.ip_da_type == IP_MULTICAST) &&
            (meta.l3.ip_sa_type == IP_UNICAST_LL) &&
            (meta.src_bd.enforce_v6_link_local_mc == 1))
        {
            if (meta.src_bd.is_l3_if == 1) {
                meta.ig_drop.ipv6_mc_sa_local_da_global_svi = 1;
                //meta.ig_drop.inc_drop_counters = TRUE;
            } else {
                meta.ig_drop.ipv6_mc_sa_local_da_global_l3if = 1;
                //meta.ig_drop.inc_drop_counters = TRUE;
                meta.multicast.rpf_pass = 0;
            }
        }
    }
}


/*****************************************************************************/
/* IP/MPLS Self-forwarding check */
/*****************************************************************************/

control process_l3_self_fwd_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // IP or MPLS packet and self-forwarding check is enabled
        if (((meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) &&
             (((meta.l3.l3_type == L3TYPE_IPV4) &&
               (meta.src_bd.v4_ignore_self_fwd_check == 0)) ||
              ((meta.l3.l3_type == L3TYPE_IPV6) &&
               (meta.src_bd.v6_ignore_self_fwd_check == 0))))
#ifndef DISABLE_MPLS
            ||
            ((meta.ingress.l3_fwd_mode == L3_FWD_MODE_MPLS) &&
             (meta.src_bd.mpls_ignore_self_fwd_check == 0))
#endif /*DISABLE_MPLS*/
            )
        {
            if (((meta.src_bd.use_primary_l3_self == 1) &&
                 (meta.src_bd.primary_bd != meta.dst_adj.bd)) ||
                ((meta.src_bd.use_primary_l3_self == 0) &&
                 (meta.ingress.src_bd != meta.dst_adj.bd)))
            {
                meta.ig_drop.self_fwd_failure = TRUE;
                //ig_drop.inc_drop_counters = TRUE;
            }
        }
    }
}


// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Prevent ARP/ND unicast packets from crossing BD
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

control process_arp_nd_crossing_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (((((meta.l3.arp_type == ARP_REQ) ||
               (meta.l3.arp_type == ARP_RES)) &&
              (meta.l3.arp_unicast_mode == 1)) ||
             (meta.l3.nd_unicast_mode == 1)) &&
            (meta.src_bd.arp_nd_bd_crossing_dis == 1) &&
            (meta.ingress.src_bd != meta.dst_adj.bd))
        {
            meta.ig_drop.arp_nd_ucast_cross_bd = TRUE;
            //meta.ig_drop.inc_drop_counters = TRUE;
        }
    }
}

control process_uc_sh_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
	if ((meta.ingress.dst_is_ptr == 1) &&
            (meta.ig_tunnel.decap == 1) &&
            (meta.ig_tunnel.encap == 1) &&
            (meta.src_tep.src_sh_group == meta.ig_tunnel.dst_sh_group) &&
            (meta.src_tep.src_sh_group != 0) &&
            (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) &&
            (!(((meta.ingress.l3_fwd_mode == L3_FWD_MODE_BRIDGE) &&
                (meta.dst_mac.ep_bounce == 1)) ||
               ((meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) &&
                (meta.dst_fib.ep_bounce == 1)))))
        {
	    meta.ig_drop.split_horizon_check = TRUE;
	    //meta.ig_drop.inc_drop_counters = TRUE;
	}
    }
}

control process_dst_pc(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".select_l2_pc_member")
    action select_l2_pc_member(bit<8> base, bit<8> num_paths) {
        hash(meta.ingress.dst_port_idx, HashAlgorithm.identity,
             (bit<8>) base, { meta.hash.hash2 }, (bit<16>)num_paths);
    }
    @name(".bounce_to_vpc_peer")
    action bounce_to_vpc_peer(bit<8> base, bit<8> num_paths) {
        hash(meta.ingress.dst_port_idx, HashAlgorithm.identity,
             (bit<8>) base, { meta.hash.hash2 }, (bit<16>)num_paths);
        meta.ingress.dst_if_idx = CFG_VPC_BOUNCE_DST_IF_IDX;
        meta.ig_tunnel.encap = CFG_VPC_BOUNCE_ENCAP_VLD;
        meta.ig_tunnel.encap_idx = CFG_VPC_BOUNCE_ENCAP_IDX;
        meta.ig_tunnel.encap_l2_idx = CFG_VPC_BOUNCE_ENCAP_L2_IDX;
        meta.ingress.outer_dst_bd = CFG_VPC_BOUNCE_OUTER_DST_BD;
        meta.ingress.vpc_bounce = TRUE;
    }
    @name("dst_pc_cfg")
    table dst_pc_cfg {
        // action_profile: pc_action_profile;
        actions = {
            select_l2_pc_member;
            bounce_to_vpc_peer;
            @default_only NoAction;
        }
        key = {
#ifdef MERGE_2LAYER_VPC_RESOLUTION
            meta.ingress.dst_if_idx   : exact;
#else
            meta.ingress.dst_vpc_idx  : exact;
#endif
            meta.ingress.vpc_bounce_en: exact;
        }
        size = PC_CFG_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        dst_pc_cfg.apply();
    }
}

control process_dst_port(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".ig_set_dst_port_state")
    action ig_set_dst_port_state(bit<13> ovector_idx, bit<8> dst_chip,
                                 bit<8> dst_port, bit<1> vnic_if,
                                 bit<1> is_local, bit<1> is_vpc,
                                 bit<6> acl_label)
    {
        //meta.ingress.ovector_idx = ovector_idx;
        meta.ingress_sideband.ovector_idx = ovector_idx;
        meta.ig_eg_header.ieth_dst_chip = dst_chip;
        meta.ig_eg_header.ieth_dst_port = dst_port;
        //meta.ingress.dst_chip = dst_chip;
        //meta.ingress.dst_port = dst_port;
        meta.ig_dst_port.vnic_if = vnic_if;
        meta.ig_dst_port.is_local = is_local;
        meta.ig_dst_port.is_vpc = is_vpc;
        meta.ig_dst_port.acl_label = acl_label;
    }
    @name("dst_pc_mbr")
    table dst_pc_mbr {
        actions = {
            ig_set_dst_port_state;
            @default_only NoAction;
        }
        key = {
            meta.ingress.dst_port_idx: exact;
        }
        size = PC_MBR_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        dst_pc_mbr.apply();
    }
}


//#ifdef ACI_TOR_MODE

//****************************************************************************
// Drop for double exception cases in ACI
//****************************************************************************

control process_double_exception_drop(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if ((meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) &&
            hdr.ivxlan.isValid() &&
            (hdr.ivxlan.nonce_e == 1) &&
            ((meta.ingress.ep_bounce == 1) ||
             (meta.ingress.vpc_bounce == 1) ||
             (meta.dst_mac.spine_proxy == 1) ||
             (meta.dst_fib.spine_proxy == 1))) {
            meta.ig_drop.double_exception = TRUE;
            //meta.ig_drop.inc_drop_counters = TRUE;
        }
    }
}

//#endif /*ACI_TOR_MODE*/

control process_ingress_fstat0_log(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("ingress_fstat0_permit_log_stats")
    register<bit<1>>(INGRESS_FSTAT0_ACTION_TABLE_SIZE) ingress_fstat0_permit_log_stats;
    apply {
        if (meta.ig_acl.fstat0_hit == 1) {
            ingress_fstat0_permit_log_stats.read(meta.ig_acl.permit_log_ready,
                                                 (bit<32>) meta.ig_acl.fstat0_hit_idx);
        }
        if (meta.ig_acl.fstat0_hit == 1 && meta.ig_acl.permit_log_ready == 1) {
            meta.ig_acl.sup_copy = TRUE;
            ingress_fstat0_permit_log_stats.write((bit<32>) meta.ig_acl.fstat0_hit_idx, 
                                                  1);
        }
    }
}

control process_ingress_fstat0(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".ingress_fstat0_permit")
    action ingress_fstat0_permit(bit<12> hit_idx) {
        meta.ig_acl.fstat0_hit = 1;
        meta.ig_acl.fstat0_hit_idx = hit_idx;
    }
    /*
    action ingress_fstat0_permit_reflect(hit_idx, ref_acl_expiry_timer) {
	meta.ig_acl.fstat0_hit = 1;
	meta.ig_acl.fstat0_hit_idx = hit_idx;
	meta.ig_acl.ref_acl_reflect = ref_acl_reflect;
	meta.ig_acl.ref_acl_expiry_timer = ref_acl_expiry_timer;
    }  
    */
    @name(".ingress_fstat0_permit_log")
    action ingress_fstat0_permit_log(bit<12> hit_idx, bit<6> sup_code,
                                     bit<2> sup_dst, bit<8> sup_qnum)
    {
        meta.ig_acl.fstat0_hit = 1;
        meta.ig_acl.fstat0_hit_idx = hit_idx;
        meta.ig_acl.sup_code = sup_code;
        meta.ig_acl.sup_qnum = sup_qnum;
        meta.ig_acl.sup_dst = sup_dst;
        meta.ig_acl.sup_copy = TRUE;
    }
    @name("ingress_ipv4_fstat0")
    table ingress_ipv4_fstat0 {
        actions = {
            ingress_fstat0_permit;
            ingress_fstat0_permit_log;
            //ingress_fstat0_permit_reflect;
            //ingress_fstat0_deny_evaluate;
            //ingress_qos_hit;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            CMN_ACL_KEY

            meta.ig_dst_bd.acl_label     : ternary;

            IPV4_FLOW_KEY
            //meta.ig_acl.ipv4_spare : ternary;
        }
        size = INGRESS_IPV4_FSTAT0_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("ingress_ipv6_fstat0")
    table ingress_ipv6_fstat0 {
        actions = {
            ingress_fstat0_permit;
            ingress_fstat0_permit_log;
            //ingress_fstat0_permit_reflect;
            //ingress_fstat0_deny_evaluate;
            //ingress_qos_hit;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            CMN_ACL_KEY

            meta.ig_dst_bd.acl_label     : ternary;

            IPV6_FLOW_KEY
            //meta.ig_acl.ipv6_spare : ternary;
        }
        size = INGRESS_IPV6_FSTAT0_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("ingress_mac_fstat0")
    table ingress_mac_fstat0 {
        actions = {
            ingress_fstat0_permit;
            ingress_fstat0_permit_log;
            //ingress_fstat0_permit_reflect;
            //ingress_fstat0_deny_evaluate;
            //ingress_qos_hit;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            CMN_ACL_KEY

            meta.ig_dst_bd.acl_label     : ternary;

            MAC_FLOW_KEY
            //meta.ig_acl.mac_spare : ternary;
        }
        size = INGRESS_MAC_FSTAT0_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("process_ingress_fstat0_log") process_ingress_fstat0_log() process_ingress_fstat0_log_0;
    apply {
        if (meta.bypass_info.acl_bypass == 0) {
            if (meta.l3.l3_type == L3TYPE_IPV4) {
                ingress_ipv4_fstat0.apply();
            } else if (meta.l3.l3_type == L3TYPE_IPV6) {
                ingress_ipv6_fstat0.apply();
            } else {
                ingress_mac_fstat0.apply();
            }
            process_ingress_fstat0_log_0.apply(hdr, meta, standard_metadata);
            //process_ingress_fstat0_stats();
            //count(ingress_fstat0_stats, ig_acl_metadata.fstat0_hit_idx);
        }
    }
}

control process_ingress_qos(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("qos_meter") meter(QOS_METER_TABLE_SIZE, MeterType.bytes) qos_meter;
    @name(".ingress_qos_mark")
    action ingress_qos_mark(bit<1> qos_vld, bit<11> qos_map_idx) {
        meta.ig_acl.qos_map_idx = qos_map_idx;
        meta.ig_acl.qos_vld = qos_vld;
    }
    @name(".ingress_qos_drop_meter")
    action ingress_qos_drop_meter(bit<1> qos_vld, bit<11> qos_map_idx,
                                  bit<8> policer_select)
    {
        meta.ig_acl.qos_vld = qos_vld;
        meta.ig_acl.qos_map_idx = qos_map_idx;
        qos_meter.execute_meter((bit<32>) policer_select,
                                meta.ig_drop.qos_policer_drop);
        // TODO : increment drop stats 
    }
    @name(".ingress_qos_mark_meter")
    action ingress_qos_mark_meter(bit<1> qos_vld, bit<11> qos_map_idx,
                                  bit<11> mark_qos_map_idx,
                                  bit<8> policer_select)
    {
        meta.ig_acl.qos_vld = qos_vld;
        meta.ig_acl.qos_map_idx = qos_map_idx;
        meta.ig_acl.mark_qos_map_idx = mark_qos_map_idx;
        qos_meter.execute_meter((bit<32>) policer_select,
                                meta.ig_acl.qos_policer_mark);
        // TODO : increment drop stats 
    }
    @name("ingress_ipv4_qos")
    table ingress_ipv4_qos {
        actions = {
            ingress_qos_mark;
            ingress_qos_drop_meter;
            ingress_qos_mark_meter;
            @default_only NoAction;
        }
        key = {
	    // Common Key Fields
	    CMN_ACL_KEY

            //meta.ig_dst_port.acl_label    : ternary; // commented out to reduce pipeline dependency
            meta.ig_dst_bd.acl_label     : ternary;
//////	    // Result from previous acls
//////	    meta.ig_acl.sup_copy         : ternary;
//////	    meta.ig_acl.sup_redirect     : ternary;
//////	    meta.ig_acl.redirect         : ternary;
//////	    meta.ig_drop.acl_deny        : ternary;
            meta.ig_qos.qos_layer        : ternary;
            meta.ig_qos.acl_key_cos      : ternary;
            meta.ig_qos.acl_key_de       : ternary;
            meta.ig_qos.acl_key_dscp     : ternary;
            meta.ig_qos.acl_key_ecn      : ternary;
            meta.ig_qos.acl_key_dscp_vld : ternary;
//	    meta.ig_qos.qos_map_grp      : ternary;
//	    meta.ig_qos.qos_use_dscp     : ternary;
//	    meta.ig_qos.qos_use_tc       : ternary;

            IPV4_FLOW_KEY
        }
        size = INGRESS_IPV4_QOS_TABLE_SIZE;
        default_action = NoAction();
        @name("ingress_ipv4_qos_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    @name("ingress_ipv6_qos")
    table ingress_ipv6_qos {
        actions = {
            ingress_qos_mark;
            ingress_qos_drop_meter;
            ingress_qos_mark_meter;
            @default_only NoAction;
        }
        key = {
	    // Common Key Fields
	    CMN_ACL_KEY

            //meta.ig_dst_port.acl_label    : ternary; // commented out to reduce pipeline dependency
            meta.ig_dst_bd.acl_label     : ternary;
//////	    // Result from previous acls
//////	    meta.ig_acl.sup_copy         : ternary;
//////	    meta.ig_acl.sup_redirect     : ternary;
//////	    meta.ig_acl.redirect         : ternary;
//////	    meta.ig_drop.acl_deny        : ternary;

            meta.ig_qos.qos_layer        : ternary;
            meta.ig_qos.acl_key_cos      : ternary;
            meta.ig_qos.acl_key_de       : ternary;
            meta.ig_qos.acl_key_dscp     : ternary;
            meta.ig_qos.acl_key_ecn      : ternary;
            meta.ig_qos.acl_key_dscp_vld : ternary;

            IPV6_FLOW_KEY
        }
	size = INGRESS_IPV6_QOS_TABLE_SIZE;
        default_action = NoAction();
        @name("ingress_ipv6_qos_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    @name("ingress_mac_qos") table ingress_mac_qos {
        actions = {
            ingress_qos_mark;
            ingress_qos_drop_meter;
            ingress_qos_mark_meter;
            @default_only NoAction;
        }
        key = {
	    // Common Key Fields
	    CMN_ACL_KEY

            //meta.ig_dst_port.acl_label    : ternary; // commented out to reduce pipeline dependency
            meta.ig_dst_bd.acl_label     : ternary;
//////	    // Result from previous acls
//////	    meta.ig_acl.sup_copy         : ternary;
//////	    meta.ig_acl.sup_redirect     : ternary;
//////	    meta.ig_acl.redirect         : ternary;
//////	    meta.ig_drop.acl_deny        : ternary;

            meta.ig_qos.qos_layer        : ternary;
            meta.ig_qos.acl_key_cos      : ternary;
            meta.ig_qos.acl_key_de       : ternary;
            meta.ig_qos.acl_key_dscp     : ternary;
            meta.ig_qos.acl_key_ecn      : ternary;
            meta.ig_qos.acl_key_dscp_vld : ternary;
//	    meta.ig_qos.qos_map_grp      : ternary;
//	    meta.ig_qos.qos_use_dscp     : ternary;
//	    meta.ig_qos.qos_use_tc       : ternary;

            MAC_FLOW_KEY
        }
        size = INGRESS_MAC_QOS_TABLE_SIZE;
        default_action = NoAction();
        @name("ingress_mac_qos_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // ****************************
    // QoS Map Index Calculation
    // ****************************

    // TODO :
    // if (ig_qos_metadata.qos_use_tc == 1) {
    //     qos_map_idx = (qos_map_grp * 16) + tc;
    // } else if (ig_qos_metadata.qos_use_dscp == 1) {
    //     if (ig_qos_metadata.acl_key_dscp_vld == 1) {
    //         qos_map_idx = (qos_map_grp * 16) + dscp;
    //     } else {
    //         qos_map_idx = (qos_map_grp * 16) + 64 + (de * 8) + cos;
    //     }
    // } else {
    //     qos_map_idx = (qos_map_grp * 16) + cos;
    // }

    @name(".set_qos_map_idx")
    action set_qos_map_idx(bit<11> idx) {
        meta.ig_qos.qos_map_idx = idx;
        meta.ig_eg_header.qos_map_idx = idx;
    }
    @name("qos_idx_calc")
    table qos_idx_calc {
        actions = {
            set_qos_map_idx;
            @default_only NoAction;
        }
        key = {
            meta.ig_qos.qos_use_tc      : exact;
            meta.ig_qos.qos_use_dscp    : exact;
            meta.ig_qos.qos_map_grp     : exact;
            meta.ig_qos.acl_key_dscp_vld: exact;
            meta.ig_qos.acl_key_dscp    : exact;
            meta.ig_qos.acl_key_cos     : exact;
//#ifndef ACI_TOR_MODE
	    meta.ig_qos.acl_key_exp_vld : exact;
	    meta.ig_qos.acl_key_exp     : exact;
//#endif /*ACI_TOR_MODE*/
        }
        size = QOS_IDX_CALC_TABLE_SIZE;
        default_action = NoAction();
    }

    @name(".set_ingress_qos_info")
    action set_ingress_qos_info(bit<4> iclass, bit<4> oclass, bit<1> cpu,
                                bit<4> tclass, bit<1> spantransit)
    {
        meta.ingress_sideband.iclass = iclass;
        //meta.ig_qos.iclass = iclass;
        meta.ingress_sideband.oclass = oclass;
        //meta.ig_qos.oclass = oclass;
        meta.ig_qos.tclass = tclass;
        meta.ig_qos.cpu = cpu;
        meta.ig_qos.spantransit = spantransit;
    }
    @name("qos_info")
    table qos_info {
        actions = {
            set_ingress_qos_info;
            @default_only NoAction;
        }
        key = {
            //dirmap
            meta.ig_qos.qos_map_idx: exact;
        }
        size = INGRESS_QOS_INFO_TABLE_SIZE;
        default_action = NoAction();
    }

    apply {

        // ****************************
        // TCAM Lookup
        // ****************************
        if (meta.l3.l3_type == L3TYPE_IPV4) {
            ingress_ipv4_qos.apply();
        } else if (meta.l3.l3_type == L3TYPE_IPV6) {
            ingress_ipv6_qos.apply();
        } else {
            ingress_mac_qos.apply();
        }

        // ****************************
        // QoS Resoution
        // ****************************
        
        // AC > PT > IETH > BD > VIF
        
        if (meta.pt_info.qos_vld == 1) {
            // TODO maybe_wrong_cast
            meta.ig_qos.qos_map_grp = (bit<8>) meta.pt_info.qos_map_grp;
            meta.ig_qos.qos_use_dscp = meta.pt_info.qos_map_use_dscp;
            meta.ig_qos.qos_use_tc = FALSE;
        } else if (hdr.ieth.isValid()) {
            meta.ig_qos.qos_map_grp = CFG_IETH_QOS_MAP_GRP;
            meta.ig_qos.qos_use_dscp = CFG_IETH_QOS_MAP_USE_DSCP;
            meta.ig_qos.qos_use_tc = CFG_IETH_QOS_MAP_USE_TC;
            //meta.ig_qos.qos_map_grp  = meta.CFG_ieth_qos_map.grp;
            //meta.ig_qos.qos_use_dscp = meta.CFG_ieth_qos_map.use_dscp;
            //meta.ig_qos.qos_use_tc   = meta.CFG_ieth_qos_map.use_tc;
        } else if (meta.src_bd.qos_vld == 1) {
            // TODO maybe_wrong_cast
            meta.ig_qos.qos_map_grp = (bit<8>) meta.src_bd.qos_map_grp;
            meta.ig_qos.qos_use_dscp = meta.src_bd.qos_map_use_dscp;
            meta.ig_qos.qos_use_tc = meta.src_bd.qos_map_use_tc;
        } else {
            // TODO maybe_wrong_cast
            meta.ig_qos.qos_map_grp = (bit<8>) meta.src_if_profile.qos_map_grp;
            meta.ig_qos.qos_use_dscp = meta.src_if_profile.qos_map_use_dscp;
            meta.ig_qos.qos_use_tc = meta.src_if_profile.qos_map_use_tc;
        }
        
        qos_idx_calc.apply();

        if (meta.ig_acl.qos_vld == 1) {
            if (meta.ig_acl.qos_policer_mark == 1) {
                meta.ig_qos.qos_map_idx = meta.ig_acl.mark_qos_map_idx;
                meta.ig_eg_header.qos_map_idx = meta.ig_acl.mark_qos_map_idx;
            } else {
                meta.ig_qos.qos_map_idx = meta.ig_acl.qos_map_idx;
                meta.ig_eg_header.qos_map_idx = meta.ig_acl.qos_map_idx;
            }
        }
        qos_info.apply();
    }
}

control process_ingress_sup(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
#ifdef DISABLE_COPP_TCAM
    @name("copp_meter")
    meter(COPP_METER_TABLE_SIZE, MeterType.packets) copp_meter;
#endif

    @name(".ingress_punt_to_sup")
    action ingress_punt_to_sup(
#ifdef DISABLE_COPP_TCAM
                               bit<6> sup_qnum, bit<8> policer_select,
                               bit<8> oclass, bit<4> drop_mask_select,
#endif
                               bit<12> hit_idx, bit<8> sup_code,
                               bit<2> sup_dst)
    {
        meta.ig_acl.sup_hit = 1;
        meta.ig_acl.sup_hit_idx = hit_idx;
        //meta.ig_acl.sup_code = sup_code;
        meta.ig_acl.sup_dst = sup_dst;
        meta.ig_eg_header.sup_code = sup_code;
#ifdef DISABLE_COPP_TCAM
        //meta.ig_acl.sup_qnum = sup_qnum;
        meta.ig_eg_header.sup_qnum = sup_qnum;
        copp_meter.execute_meter((bit<32>)policer_select, meta.ingress.copp_drop);
        meta.ig_acl.drop_mask_select = drop_mask_select;
        //meta.ig_qos.oclass = oclass;
#endif
    }

    @name(".ingress_copy_to_sup")
    action ingress_copy_to_sup(
#ifdef DISABLE_COPP_TCAM
                               bit<6> sup_qnum, bit<8> policer_select,
                               bit<8> oclass, bit<4> drop_mask_select,
#endif
                               bit<12> hit_idx, bit<8> sup_code,
                               bit<2> sup_dst)
    {
        meta.ig_acl.sup_hit = 1;
        meta.ig_acl.sup_hit_idx = hit_idx;
        //meta.ig_acl_metadata.sup_code = sup_code;
        meta.ig_acl.sup_dst = sup_dst;
        meta.ig_eg_header.sup_code = sup_code;
#ifdef DISABLE_COPP_TCAM
        //meta.ig_acl_metadata.sup_qnum = sup_qnum;
        meta.ig_eg_header.sup_qnum = sup_qnum;
        copp_meter.execute_meter((bit<32>)policer_select, meta.ingress.copp_drop);
        meta.ig_acl.drop_mask_select = drop_mask_select;
        //meta.ig_qos_metadata.oclass = oclass;
#endif
    }

    @name("ingress_ipv4_sup")
    table ingress_ipv4_sup {
        actions = {
            ingress_punt_to_sup;
            ingress_copy_to_sup;
            // TBDP416 The original P4_14 code has a list of 4 more
            // actions when not using an action profile.  Same for
            // ingress_ipv6_sup and ingress_mac_sup tables, too.  Why
            // the difference in possible actions?  Could be just an
            // oversight, and action profile should have the same
            // longer list.
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            CMN_ACL_KEY

            //meta.ig_dst_port.acl_label[7:0]             : ternary;
            meta.ig_dst_bd.acl_label[3:0]               : ternary;

//#ifndef ACI_TOR_MODE
            // Result from previous acls
            meta.ig_acl.sup_copy     : ternary;
            meta.ig_acl.sup_redirect : ternary;
            meta.ig_acl.redirect     : ternary;
//#endif /*ACI_TOR_MODE*/

            // from FIB/L2
            meta.src_fib.sa_sup_redirect                : ternary;
            meta.dst_fib.da_sup_redirect                : ternary;
            meta.dst_fib.sup_copy                       : ternary;
            meta.l3.egress_tor_glean                    : ternary;

            // NAT
            meta.l3.src_nat_sup_redirect                : ternary;
            meta.l3.src_nat_sup_copy                    : ternary;
            meta.l3.dst_nat_sup_redirect                : ternary;
            meta.l3.dst_nat_sup_copy                    : ternary;
            meta.l3.twice_nat_sup_redirect              : ternary;
            meta.l3.twice_nat_sup_copy                  : ternary;

            // IGMP/MLD
            meta.src_bd.igmp_snp_en                     : ternary;
            meta.src_bd.mld_snp_en                      : ternary;

            // PIM
            meta.ig_tunnel.pim_acl_key                  : ternary;
            meta.multicast.pim_acl_key                  : ternary;

            // Flags
            meta.src_tep.lkup_hit                       : ternary;
            meta.ig_drop.missing_vntag                  : ternary;
            meta.ig_drop.illegal_vntag                  : ternary;
            meta.ig_drop.src_if_miss                    : ternary;
            meta.ig_drop.src_vlan_mbr                   : ternary;
            meta.ig_drop.src_tep_miss                   : ternary;
            meta.ig_drop.iic_check_failure              : ternary;
            meta.ig_drop.outer_ttl_expired              : ternary;
            meta.ig_drop.vlan_xlate_miss                : ternary;
            meta.ig_drop.ttl_expired                    : ternary;
            meta.ig_drop.routing_disabled               : ternary;
            meta.ig_drop.sgt_xlate_miss                 : ternary;
            meta.ig_drop.src_nat_drop                   : ternary;
            meta.ig_drop.dst_nat_drop                   : ternary;
            meta.ig_drop.twice_nat_drop                 : ternary;
            meta.ig_drop.smac_miss                      : ternary;
            meta.ig_drop.route_miss                     : ternary;
            meta.ig_drop.bridge_miss                    : ternary;
            meta.ig_drop.mtu_check_failure              : ternary;
            meta.ig_drop.uc_rpf_failure                 : ternary;
            meta.ig_drop.mc_rpf_failure                 : ternary;
            meta.ig_drop.l3_binding_failure             : ternary;
            meta.ig_drop.ipv6_uc_link_local_cross_bd    : ternary;
            meta.ig_drop.ipv6_mc_sa_local_da_global_svi : ternary;
            meta.ig_drop.ipv6_mc_sa_local_da_global_l3if: ternary;
            meta.ig_drop.self_fwd_failure               : ternary;
            meta.ig_drop.split_horizon_check            : ternary;
            meta.ig_drop.arp_nd_ucast_cross_bd          : ternary;
            meta.ig_drop.secure_mac_move                : ternary;
            meta.ig_drop.non_secure_mac                 : ternary;
            meta.ig_drop.l2_bind_failure                : ternary;
            meta.ig_drop.pt_deny                        : ternary;
            meta.ig_drop.qos_policer_drop               : ternary;

            IPV4_FLOW_KEY

            //meta.l2.lkp_mac_sa : ternary;
            //meta.l2.lkp_mac_da : ternary;
        }
        size = INGRESS_IPV4_SUP_TABLE_SIZE;
        default_action = NoAction();

        // TBDP416 - there is some stuff in the original P4_14 code
        // about #ifndef __TARGET_BMV2 use an action profile,
        // otherwise do not.  I am not sure why that is there.
        @name("ingress_sup_action_profile")
        implementation = action_profile(256);

        @name("ingress_ipv4_sup_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    @name("ingress_ipv6_sup")
    table ingress_ipv6_sup {
        actions = {
            ingress_punt_to_sup;
            ingress_copy_to_sup;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            CMN_ACL_KEY

            //meta.ig_dst_port.acl_label[7:0]             : ternary;
            meta.ig_dst_bd.acl_label[3:0]               : ternary;

//#ifndef ACI_TOR_MODE
            // Result from previous acls
            meta.ig_acl.sup_copy     : ternary;
            meta.ig_acl.sup_redirect : ternary;
            meta.ig_acl.redirect     : ternary;
//#endif /*ACI_TOR_MODE*/

            // from FIB/L2
            meta.src_fib.sa_sup_redirect                : ternary;
            meta.dst_fib.da_sup_redirect                : ternary;
            meta.dst_fib.sup_copy                       : ternary;
            meta.l3.egress_tor_glean                    : ternary;

            // NAT
            meta.l3.src_nat_sup_redirect                : ternary;
            meta.l3.src_nat_sup_copy                    : ternary;
            meta.l3.dst_nat_sup_redirect                : ternary;
            meta.l3.dst_nat_sup_copy                    : ternary;
            meta.l3.twice_nat_sup_redirect              : ternary;
            meta.l3.twice_nat_sup_copy                  : ternary;

            // IGMP/MLD
            meta.src_bd.igmp_snp_en                     : ternary;
            meta.src_bd.mld_snp_en                      : ternary;

            // PIM
            meta.ig_tunnel.pim_acl_key                  : ternary;
            meta.multicast.pim_acl_key                  : ternary;

            // Flags
            meta.src_tep.lkup_hit                       : ternary;
            meta.ig_drop.missing_vntag                  : ternary;
            meta.ig_drop.illegal_vntag                  : ternary;
            meta.ig_drop.src_if_miss                    : ternary;
            meta.ig_drop.src_vlan_mbr                   : ternary;
            meta.ig_drop.src_tep_miss                   : ternary;
            meta.ig_drop.iic_check_failure              : ternary;
            meta.ig_drop.outer_ttl_expired              : ternary;
            meta.ig_drop.vlan_xlate_miss                : ternary;
            meta.ig_drop.ttl_expired                    : ternary;
            meta.ig_drop.routing_disabled               : ternary;
            meta.ig_drop.sgt_xlate_miss                 : ternary;
            meta.ig_drop.src_nat_drop                   : ternary;
            meta.ig_drop.dst_nat_drop                   : ternary;
            meta.ig_drop.twice_nat_drop                 : ternary;
            meta.ig_drop.smac_miss                      : ternary;
            meta.ig_drop.route_miss                     : ternary;
            meta.ig_drop.bridge_miss                    : ternary;
            meta.ig_drop.mtu_check_failure              : ternary;
            meta.ig_drop.uc_rpf_failure                 : ternary;
            meta.ig_drop.mc_rpf_failure                 : ternary;
            meta.ig_drop.l3_binding_failure             : ternary;
            meta.ig_drop.ipv6_uc_link_local_cross_bd    : ternary;
            meta.ig_drop.ipv6_mc_sa_local_da_global_svi : ternary;
            meta.ig_drop.ipv6_mc_sa_local_da_global_l3if: ternary;
            meta.ig_drop.self_fwd_failure               : ternary;
            meta.ig_drop.split_horizon_check            : ternary;
            meta.ig_drop.arp_nd_ucast_cross_bd          : ternary;
            meta.ig_drop.secure_mac_move                : ternary;
            meta.ig_drop.non_secure_mac                 : ternary;
            meta.ig_drop.l2_bind_failure                : ternary;
            meta.ig_drop.pt_deny                        : ternary;
            meta.ig_drop.qos_policer_drop               : ternary;

            IPV6_FLOW_KEY
            //meta.l2.lkp_mac_sa : ternary;
            //meta.l2.lkp_mac_da : ternary;
        }
        size = INGRESS_IPV6_SUP_TABLE_SIZE;
        default_action = NoAction();
        @name("ingress_sup_action_profile")
        implementation = action_profile(256);
        @name("ingress_ipv6_sup_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    @name("ingress_mac_sup")
    table ingress_mac_sup {
        actions = {
            ingress_punt_to_sup;
            ingress_copy_to_sup;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            CMN_ACL_KEY

            //meta.ig_dst_port.acl_label[7:0]             : ternary;
            meta.ig_dst_bd.acl_label[3:0]               : ternary;

//#ifndef ACI_TOR_MODE
            // Result from previous acls
            meta.ig_acl.sup_copy     : ternary;
            meta.ig_acl.sup_redirect : ternary;
            meta.ig_acl.redirect     : ternary;
//#endif /*ACI_TOR_MODE*/
            
            // from FIB/L2
            meta.src_fib.sa_sup_redirect                : ternary;
            meta.dst_fib.da_sup_redirect                : ternary;
            meta.dst_fib.sup_copy                       : ternary;
            meta.l3.egress_tor_glean                    : ternary;

            // NAT
            meta.l3.src_nat_sup_redirect                : ternary;
            meta.l3.src_nat_sup_copy                    : ternary;
            meta.l3.dst_nat_sup_redirect                : ternary;
            meta.l3.dst_nat_sup_copy                    : ternary;
            meta.l3.twice_nat_sup_redirect              : ternary;
            meta.l3.twice_nat_sup_copy                  : ternary;

            // IGMP/MLD
            meta.src_bd.igmp_snp_en                     : ternary;
            meta.src_bd.mld_snp_en                      : ternary;

            // PIM
            meta.ig_tunnel.pim_acl_key                  : ternary;
            meta.multicast.pim_acl_key                  : ternary;

            // Flags
            meta.src_tep.lkup_hit                       : ternary;
            meta.ig_drop.missing_vntag                  : ternary;
            meta.ig_drop.illegal_vntag                  : ternary;
            meta.ig_drop.src_if_miss                    : ternary;
            meta.ig_drop.src_vlan_mbr                   : ternary;
            meta.ig_drop.src_tep_miss                   : ternary;
            meta.ig_drop.iic_check_failure              : ternary;
            meta.ig_drop.outer_ttl_expired              : ternary;
            meta.ig_drop.vlan_xlate_miss                : ternary;
            meta.ig_drop.ttl_expired                    : ternary;
            meta.ig_drop.routing_disabled               : ternary;
            meta.ig_drop.sgt_xlate_miss                 : ternary;
            meta.ig_drop.src_nat_drop                   : ternary;
            meta.ig_drop.dst_nat_drop                   : ternary;
            meta.ig_drop.twice_nat_drop                 : ternary;
            meta.ig_drop.smac_miss                      : ternary;
            meta.ig_drop.route_miss                     : ternary;
            meta.ig_drop.bridge_miss                    : ternary;
            meta.ig_drop.mtu_check_failure              : ternary;
            meta.ig_drop.uc_rpf_failure                 : ternary;
            meta.ig_drop.mc_rpf_failure                 : ternary;
            meta.ig_drop.l3_binding_failure             : ternary;
            meta.ig_drop.ipv6_uc_link_local_cross_bd    : ternary;
            meta.ig_drop.ipv6_mc_sa_local_da_global_svi : ternary;
            meta.ig_drop.ipv6_mc_sa_local_da_global_l3if: ternary;
            meta.ig_drop.self_fwd_failure               : ternary;
            meta.ig_drop.split_horizon_check            : ternary;
            meta.ig_drop.arp_nd_ucast_cross_bd          : ternary;
            meta.ig_drop.secure_mac_move                : ternary;
            meta.ig_drop.non_secure_mac                 : ternary;
            meta.ig_drop.l2_bind_failure                : ternary;
            meta.ig_drop.pt_deny                        : ternary;
            meta.ig_drop.qos_policer_drop               : ternary;

            MAC_FLOW_KEY
        }
        size = INGRESS_MAC_SUP_TABLE_SIZE;
        default_action = NoAction();
        @name("ingress_sup_action_profile")
        implementation = action_profile(256);
        @name("ingress_mac_sup_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    apply {
        if (meta.l3.l3_type == L3TYPE_IPV4) {
            ingress_ipv4_sup.apply();
        } else if (meta.l3.l3_type == L3TYPE_IPV4) {
            ingress_ipv6_sup.apply();
        } else {
            ingress_mac_sup.apply();
        }
	// apply copp result
#ifdef DISABLE_COPP_TCAM
        /*
        if ((meta.ingress.copp_drop == 1) &&
            (meta.ig_acl.sup_redirect == 1))
        {
            meta.ingress.drop_flag = TRUE;
	    meta.ingress_sideband.opcode_drop = 1;
	    meta.ingress_sideband.opcode_lcpu = 0;
	}
	if ((meta.ingress.copp_drop == 1) &&
            (meta.ig_acl.sup_copy == 1))
        {
	    meta.ig_acl.sup_copy = 0;
	    meta.ingress_sideband.opcode_lcpu = 0;
	}
        */
	if (meta.ingress.copp_drop == 1) {
	    meta.ingress_sideband.opcode_lcpu = 0;
	}
	if ((meta.ingress.copp_drop == 1) &&
            (meta.ig_acl.sup_redirect == 1))
        {
	    meta.ingress_sideband.opcode_drop = 1;
	}
#endif /*DISABLE_COPP_TCAM*/
    }
}

control process_rx_span_filter(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".ingress_rx_span_hit")
    action ingress_rx_span_hit(bit<6> span_idx) {
        meta.ingress_sideband.span_idx = span_idx;
        meta.ingress_sideband.span_vld = TRUE;
    }
    @name("ingress_ipv4_rx_span")
    table ingress_ipv4_rx_span {
        actions = {
            ingress_rx_span_hit;
            @default_only NoAction;
        }
        key = {
	    // Common Key Fields
	    CMN_ACL_KEY

            //meta.ig_dst_port.acl_label    : ternary;
            meta.ingress.dst_port_idx    : ternary;
            meta.ig_dst_bd.acl_label     : ternary;

            IPV4_FLOW_KEY
        }
	size = INGRESS_IPV4_RX_SPAN_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("ingress_ipv6_rx_span")
    table ingress_ipv6_rx_span {
        actions = {
            ingress_rx_span_hit;
            @default_only NoAction;
        }
        key = {
	    // Common Key Fields
	    CMN_ACL_KEY

            //meta.ig_dst_port.acl_label    : ternary;
            meta.ingress.dst_port_idx    : ternary;
            meta.ig_dst_bd.acl_label     : ternary;

            IPV6_FLOW_KEY
        }
        size = INGRESS_IPV6_RX_SPAN_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("ingress_mac_rx_span")
    table ingress_mac_rx_span {
        actions = {
            ingress_rx_span_hit;
            @default_only NoAction;
        }
        key = {
	    // Common Key Fields
	    CMN_ACL_KEY

            //meta.ig_dst_port.acl_label    : ternary;
            meta.ingress.dst_port_idx    : ternary;
            meta.ig_dst_bd.acl_label     : ternary;

            MAC_FLOW_KEY
        }
	size = INGRESS_MAC_RX_SPAN_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        if (meta.l3.l3_type == L3TYPE_IPV4) {
            ingress_ipv4_rx_span.apply();
        }
        else if (meta.l3.l3_type == L3TYPE_IPV6) {
            ingress_ipv6_rx_span.apply();
        } else {
            ingress_mac_rx_span.apply();
        }
    }
}


// ==================================================================
// Sideband to datapath
// ==================================================================

control process_ig_sideband_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
//    apply(CFG_cpu_oport_0_register);
        meta.ingress_sideband.mark = meta.ig_local.mark;
        // meta.ingress_sideband.segrate , _metadata.); //
        // meta.ingress_sideband.gbw_color , _metadata.);
        // meta.ingress_sideband.gbw_tagged , _metadata.);
        //////// sb_info
        // meta.ingress_sideband.oslice_vec , _metadata.);
        // meta.ingress_sideband.srvc_oslice_vec ,pt_info.service_oslice_vec);
        // meta.ingress_sideband.is_tcp , _metadata.); // TODO
        // meta.ingress_sideband.srvc_class , pt_info.queuing_ctrl);
        // meta.ingress_sideband.cpu_oclass , _metadata.); // assigned in sup block
        // meta.ingress_sideband.set_v , pt_info.service_copy);
        // meta.ingress_sideband.set_idx , pt_info.set_idx);
        // meta.ingress_sideband.sod_cap , _metadata.);
        // meta.ingress_sideband.sod_en , _metadata.);
        meta.ingress_sideband.bd = meta.ingress.dst_bd;
        // meta.ingress_sideband.src_is_l3_if , _metadata.);
        
        meta.ingress_sideband.vpc_df = meta.ingress.vpc_df;
        meta.ingress_sideband.is_my_tep = meta.ig_tunnel.decap;
        meta.ingress_sideband.src_sh_group = meta.ig_tunnel.src_sh_group;
        // TODO maybe_wrong_cast
        meta.ingress_sideband.ftag = (bit<5>) meta.ig_tunnel.ifabric_ftag;
        meta.ingress_sideband.rpf_fail = meta.multicast.rpf_pass;
        // meta.ingress_sideband.post_route_flood , _metadata.);
        // meta.ingress_sideband.pkt_hash , ipv4_hash1);
        // meta.ingress_sideband.alt_if_profile , _metadata.);
        meta.ingress_sideband.met0_vld = meta.ingress.met0_vld;
        meta.ingress_sideband.met0_ptr = meta.ingress.met0_ptr;
        // meta.ingress_sideband.bd_enabled_on_mct , _metadata.);
        // meta.ingress_sideband.ip_clen , _metadata.);
        
        if ((meta.ig_tunnel.ftag_mode == 1) ||
            (meta.ingress.ifabric_ingress == 1))
        {
            meta.ingress_sideband.ifabric_ftag_mode = TRUE;
        } else {
            meta.ingress_sideband.ifabric_ftag_mode = FALSE;
        }

        // meta.ingress_sideband.ifabric_alpine_mode , _metadata.);
        // meta.ingress_sideband.outer_mc_use_met , _metadata.);
        meta.ingress_sideband.ifabric_ingress_mode = meta.ingress.ifabric_ingress;
        // meta.ingress_sideband.ifabric_egress_mode = meta.ingress.ifabric_egress;
        // meta.ingress_sideband.bd_fabric_copy_en , _metadata.);
        meta.ingress_sideband.src_if_num = meta.src_port.src_if_num;
        // meta.ingress_sideband.span_vld = meta.ingress.span_vld); // set in sug_ig_span.p4
        meta.ingress_sideband.is_epg = meta.l2.src_is_epg;
        // meta.ingress_sideband.flood_to_epg , _metadata.); // assigned in sup.p4
        // meta.ingress_sideband.tx_span_en , _metadata.);
        // meta.ingress_sideband.is_ipv6 , _metadata.);
        // meta.ingress_sideband.lcpu_v , _metadata.);
        //////// sb_info
        
        // meta.ingress_sideband.stats_index7 , _metadata.);
        // meta.ingress_sideband.stats_mode7 , _metadata.);
        // meta.ingress_sideband.stats_atomic7 , _metadata.);
        // meta.ingress_sideband.stats_vld7 , _metadata.);
        // meta.ingress_sideband.stats_index6 , _metadata.);
        // meta.ingress_sideband.stats_mode6 , _metadata.);
        // meta.ingress_sideband.stats_atomic6 , _metadata.);
        // meta.ingress_sideband.stats_vld6 , _metadata.);
        // meta.ingress_sideband.stats_index5 , _metadata.);
        // meta.ingress_sideband.stats_mode5 , _metadata.);
        // meta.ingress_sideband.stats_atomic5 , _metadata.);
        // meta.ingress_sideband.stats_vld5 , _metadata.);
        // meta.ingress_sideband.stats_index4 , _metadata.);
        // meta.ingress_sideband.stats_mode4 , _metadata.);
        // meta.ingress_sideband.stats_atomic4 , _metadata.);
        // meta.ingress_sideband.stats_vld4 , _metadata.);
        // meta.ingress_sideband.stats_index3 , _metadata.);
        // meta.ingress_sideband.stats_mode3 , _metadata.);
        // meta.ingress_sideband.stats_atomic3 , _metadata.);
        // meta.ingress_sideband.stats_vld3 , _metadata.);
        // meta.ingress_sideband.stats_index2 , _metadata.);
        // meta.ingress_sideband.stats_mode2 , _metadata.);
        // meta.ingress_sideband.stats_atomic2 , _metadata.);
        // meta.ingress_sideband.stats_vld2 , _metadata.);
        // meta.ingress_sideband.stats_index1 , _metadata.);
        // meta.ingress_sideband.stats_mode1 , _metadata.);
        // meta.ingress_sideband.stats_atomic1 , _metadata.);
        // meta.ingress_sideband.stats_vld1 , _metadata.);
        // meta.ingress_sideband.stats_index0 , _metadata.);
        // meta.ingress_sideband.stats_mode0 , _metadata.);
        // meta.ingress_sideband.stats_atomic0 , _metadata.);
        // meta.ingress_sideband.stats_vld0 , _metadata.);
        
        // meta.ingress_sideband.storefwd , _metadata.); // assigned later
        // meta.ingress_sideband.nodrop , _metadata.); // used for etrap, from LBX
        
        if (meta.l3.lkp_ip_ecn != 0) {
            meta.ingress_sideband.ecncapable = TRUE;
        }
        
        if (meta.ingress.drop_flag == 1) {
            // Drop
            ///// meta.ingress_sideband.opcode_drop = 1;
            // meta.ingress_sideband.ovector_idx = 0x1FF;
        }
        if (meta.ig_acl.sup_redirect == 1) {
            // LCPU/RCPU Redirect
            // meta.ingress_sideband.opcode_ucmc = DP_OPCODE_UCMC_DROP;
            // if (meta.ig_acl.sup_dst == 0x1) {
            //     // RCPU
            //     meta.ingress_sideband.opcode_rcpu = 1;
            //     meta.ingress_sideband.ovector_idx = CFG_cpu_oport_0.cpu_oport;
            // } else if (meta.ig_acl.sup_dst == 0x3) {
            // LCPU
            //////     meta.ingress_sideband.opcode_lcpu = 1;
            //     meta.ingress_sideband.ovector_idx = 0x1FF;
            // }
        }
        
        if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) {
            // Unicast
            meta.ingress_sideband.opcode_uc = 1;
            // meta.ingress_sideband.ovector_idx = meta.ingress.ovector_idx;
            // } else if (meta.ingress.use_met == 1) {
        } else {
            // L2/L3 MC
            meta.ingress_sideband.opcode_l3mc = 1;
            meta.ingress_sideband.met0_vld = 1;
            meta.ingress_sideband.met0_ptr = meta.ingress.met0_ptr;
            if (meta.ingress.met1_vld == 1) {
                meta.ingress_sideband.met1_vld = 1;
                meta.ingress_sideband.met1_ptr = meta.ingress.met1_ptr;
            }
 //    } else {
 // meta.ingress_sideband.opcode_l2mc = 1;
 // meta.ingress_sideband.ovector_idx[12:0] = meta.ingress.met0_ptr;
    }

        // QoS info
        // meta.ig_eg_header.qos_map_idx = meta.ig_qos.qos_map_idx; // assigned in qos
        // meta.ingress_sideband.iclass = meta.ig_qos.iclass; // assigned in qos
        // meta.ingress_sideband.oclass = meta.ig_qos.oclass; // assigned in qos and sup blocks
        // Assuming here that SUP redirect acl also overwrote qos_map_idx
        
        // Assuming that datapath can change oclass to OCLASS_SPAN for span_only cases
        //if ((meta.ig_qos.spantransit == 1) ||
        //    (meta.ieth.span == 1) ||
        //    (meta.ig_tunnel.erspan_term == 1) ||
        //    ((meta.ingress_sideband.opcode_ucmc == DP_OPCODE_UCMC_DROP) &&
        //     (meta.ingress_sideband.opcode_lcpu == 0) &&
        //     (meta.ingress_sideband.opcode_rcpu == 0)))
        //{
        //    meta.ingress_sideband.oclass = OCLASS_SPAN;
        //}


        // meta.ingress_sideband.oclass , _metadata.);
        // meta.ingress_sideband.iclass , _metadata.);
        // meta.ingress_sideband.span_idx , _metadata.);
        // meta.ingress_sideband.span_idx, ingress.span_idx); // assigned in sug_ig_span
        // meta.ingress_sideband.cpu_oport , _metadata.);
        // meta.ingress_sideband.pktid , _metadata.);
        // meta.ingress_sideband.tdmid , _metadata.);
        // meta.ingress_sideband.srcid , _metadata.);
    }
}

control process_ieth_hdr_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
#ifdef EXTRA_DEBUG
    table debug_process_ieth_hdr_rewrite {
        key = {
            meta.ingress.l2_fwd_mode : exact;
            meta.ingress.l3_fwd_mode : exact;
            meta.ingress.src_if_idx : exact;
            meta.ingress.dst_if_idx : exact;
            meta.src_port.src_chip : exact;
            meta.src_port.src_port : exact;
            meta.ig_tunnel.encap : exact;
            meta.ingress.outer_dst_bd : exact;
            meta.ingress.dst_bd : exact;
            meta.ingress.outer_src_bd : exact;
            meta.ig_local.mark : exact;
            meta.ig_tunnel.decap : exact;
            meta.ig_tunnel.encap : exact;
            meta.ig_qos.acl_key_cos : exact;
            meta.ig_qos.acl_key_de : exact;
            meta.ig_qos.tclass : exact;
            meta.ingress.vpc_df : exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction;
    }
#endif /*EXTRA_DEBUG*/
    apply {
#ifdef EXTRA_DEBUG
        debug_process_ieth_hdr_rewrite.apply();
#endif /*EXTRA_DEBUG*/
        // ==================================================================
        // Fields for ieth header. Final header is formed in egress pipeline
        // ==================================================================

//    if (bypass_info.keep_ieth == 1) {
//    } else {
//	modify_field(ig_eg_header.ieth_sof               , 0xFB);
//	modify_field(ig_eg_header.ieth_hdr_type          , 0x0);
//	modify_field(ig_eg_header.ieth_ext_hdr           , 0x0);
	meta.ig_eg_header.ieth_l2_fwd_mode = meta.ingress.l2_fwd_mode;
	meta.ig_eg_header.ieth_l3_fwd_mode = meta.ingress.l3_fwd_mode;
        // TODO maybe_wrong_cast
	meta.ig_eg_header.ieth_src_idx = (bit<14>) meta.ingress.src_if_idx;
        // TODO maybe_wrong_cast
	meta.ig_eg_header.ieth_dst_idx = (bit<14>) meta.ingress.dst_if_idx;
	meta.ig_eg_header.ieth_src_chip = meta.src_port.src_chip;
        // TODO maybe_wrong_cast
	meta.ig_eg_header.ieth_src_port = (bit<16>) meta.src_port.src_port;
//	modify_field(ig_eg_header.ieth_dst_chip	   , ingress.dst_chip);
//	modify_field(ig_eg_header.ieth_dst_port	   , ingress.dst_port);
	if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) {
	    // Unicast : Outer BD carries BD of outgoing header
	    if (meta.ig_tunnel.encap == 1) {
                // TODO maybe_wrong_cast
		meta.ig_eg_header.ieth_outer_bd =
                    (bit<9>) meta.ingress.outer_dst_bd;
	    } else {
                // TODO maybe_wrong_cast
		meta.ig_eg_header.ieth_outer_bd = (bit<9>) meta.ingress.dst_bd;
	    }
	} else {
	    // Multicast : outer BD carries BD of incoming header
            // TODO maybe_wrong_cast
	    meta.ig_eg_header.ieth_outer_bd =
                (bit<9>) meta.ingress.outer_src_bd;
	}
	// Decap : inner BD else outer BD
	meta.ig_eg_header.ieth_bd = meta.ingress.dst_bd;

	// Mark Bit
	meta.ig_eg_header.ieth_mark = meta.ig_local.mark;
	////    modify_field(ig_eg_header.ieth_dont_lrn	   , _metadata.); // NOT PRESENT
	// modify_field(ig_eg_header.ieth_span 	   , _metadata.);
	// modify_field(ig_eg_header.ieth_alt_if_profile  , _metadata.);
	// modify_field(ig_eg_header.ieth_ip_ttl_bypass   , _metadata.);
	meta.ig_eg_header.ieth_src_is_tunnel = meta.ig_tunnel.decap;
	meta.ig_eg_header.ieth_dst_is_tunnel = meta.ig_tunnel.encap;// duplicate of ig_eg_header.tunnel_encap/decap
//	if (ig_tunnel.l3_tunnel_decap == 0) {
//	    modify_field(ig_eg_header.ieth_l2_tunnel 	 , 1); // overloaded for nsh
//	}
	meta.ig_eg_header.ieth_sup_tx = 0;
//	modify_field(ig_eg_header.ieth_sup_code    , ig_acl.sup_code); // not needed
        // TODO maybe_wrong_cast
        meta.ig_eg_header.ieth_cos = (bit<4>) meta.ig_qos.acl_key_cos;
        // TODO maybe_wrong_cast
        meta.ig_eg_header.ieth_de = (bit<4>) meta.ig_qos.acl_key_de;

	meta.ig_eg_header.ieth_tclass = meta.ig_qos.tclass;
	meta.ig_eg_header.ieth_vpc_df = meta.ingress.vpc_df;
	// modify_field(ig_eg_header.ieth_pkt_hash        , _metadata.); // TODO
//    }
    }
}

control process_ig_eg_hdr_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // ==================================================================
        // Internal Header between Ingress and Egress pipelines
        // ==================================================================
        meta.ig_eg_header.tstmp = meta.dp_ig_header.ingress_global_tstamp;
        meta.ig_eg_header.ingress_port = meta.dp_ig_header.ingress_port;
        meta.ig_eg_header.cap_1588 = meta.ig_acl.tstmp_1588_out;
        meta.ig_eg_header.erspan_term = meta.ig_tunnel.erspan_term;
        meta.ig_eg_header.erspan_term = meta.ig_tunnel.erspan_term_decap;
        meta.ig_eg_header.qinq_customer_port = meta.src_if.qinq_customer_port;

        //  IP/non-IP packet to determine cutthrough/store-n-fwd
        if (((meta.ig_tunnel.src_encap_pkt != 0) &&
             (hdr.inner_ipv4.isValid() ||
              hdr.inner_ipv6.isValid())) ||
            ((meta.ig_tunnel.src_encap_pkt == 0) &&
             (hdr.ipv4.isValid() ||
              hdr.ipv6.isValid())))
        {
            meta.ig_eg_header.len_type = 1;
            meta.ingress_sideband.storefwd = 1;
        }
        
        // meta.ig_eg_header.pkt_type = ig_tunnel.src_encap_pkt; // TODO : let egress determine it
        meta.ig_eg_header.l2_fwd_mode = meta.ingress.l2_fwd_mode;
        meta.ig_eg_header.l3_fwd_mode = meta.ingress.l3_fwd_mode;
        meta.ig_eg_header.tunnel_encap = meta.ig_tunnel.encap;
        meta.ig_eg_header.tunnel_decap = meta.ig_tunnel.decap;
        meta.ig_eg_header.ieth_fwd = meta.bypass_info.fwd_lookup_bypass;
        
        // Destination is epg or bd
        if (meta.ig_acl.flood_to_epg == 1) {
            meta.ig_eg_header.vnid_use_bd = FALSE;
        } else if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) {
            meta.ig_eg_header.vnid_use_bd = meta.dst_mac.vnid_use_bd;
        } else {
            meta.ig_eg_header.vnid_use_bd = TRUE;
        }
        
        // meta.ig_eg_header.vnid_use_bd = _metadata.;
        meta.ig_eg_header.aa_multihomed = meta.src_if.vpc;
        meta.ig_eg_header.encap_vld = meta.ig_tunnel.encap;
        // TODO maybe_wrong_cast
        meta.ig_eg_header.encap_idx = (bit<14>) meta.ig_tunnel.encap_idx;
        // meta.ig_eg_header.encap_pcid = _metadata.;
        meta.ig_eg_header.encap_l2_idx = meta.ig_tunnel.encap_l2_idx;
        // meta.ig_eg_header.adj_vld = _metadata.;
        meta.ig_eg_header.dmac = meta.dst_adj.mac;
        meta.ig_eg_header.nat_idx = meta.l3.nat_ptr;
        // meta.ig_eg_header.ol_ecn         = _metadata.);
        // meta.ig_eg_header.ol_udp_sp      = _metadata.);
        
        if ((meta.src_port.ivxlan_dl == 1) ||
            //(meta.src_if.ivxlan_dl == 1) ||
            (meta.src_fib.ivxlan_dl == 1) ||
            (meta.src_mac.ivxlan_dl == 1) ||
            (meta.src_tep.ivxlan_dl == 1) ||
            (meta.src_bd.ivxlan_dl == 1) ||
            (hdr.ivxlan.isValid() &&
             (hdr.ivxlan.nonce_dl == 1) &&
             (meta.src_tep.trust_dl == 1)))
        {
            meta.ig_eg_header.ol_dl = TRUE;
        } else {
            meta.ig_eg_header.ol_dl = FALSE;
        }
        
        //// modify_field(ig_eg_header.ol_e              , _metadata.);
        meta.ig_eg_header.ol_sp = meta.pt_info.src_policy_applied;
        meta.ig_eg_header.ol_dp = meta.pt_info.dst_policy_applied;
        //// modify_field(ig_eg_header.ol_lb             , _metadata.);
        //// modify_field(ig_eg_header.ol_vpath          , _metadata.);
        //// modify_field(ig_eg_header.ol_dre            , _metadata.);
        //// modify_field(ig_eg_header.ol_fb_vpath       , _metadata.);
        //// modify_field(ig_eg_header.ol_fb_metric      , _metadata.);
        
        // modify_field(ig_eg_header.lat_index           , _metadata.);
        // modify_field(ig_eg_header.lat_update          , _metadata.);
        // modify_field(ig_eg_header.ttl_cio             , _metadata.);
        // modify_field(ig_eg_header.ttl_coi             , _metadata.);
        // modify_field(ig_eg_header.ecn_cio             , _metadata.);
        // modify_field(ig_eg_header.ecn_coi             , _metadata.);
        // modify_field(ig_eg_header.sup_code            , ig_acl.sup_code);
        // modify_field(ig_eg_header.sup_qnum            , ig_acl.sup_qnum);
        meta.ig_eg_header.src_class = meta.pt_key.src_class;
        meta.ig_eg_header.dst_class = meta.pt_key.dst_class;
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.ig_eg_header.src_epg_or_bd = meta.ingress.src_epg;
            meta.ig_eg_header.dst_epg_or_bd = meta.ingress.dst_epg;
//#else  /*ACI_TOR_MODE*/
        } else {
            meta.ig_eg_header.src_epg_or_bd = meta.ingress.src_bd;
            meta.ig_eg_header.dst_epg_or_bd = meta.ingress.dst_bd;
        }
//#endif /*ACI_TOR_MODE*/
        // modify_field(ig_eg_header.pif_block_type      , _metadata.); // Not used in Egress
        
        if ((meta.ingress.ep_bounce == 1) ||
            (meta.ingress.vpc_bounce == 1))
        {
            meta.ig_eg_header.bounce = TRUE;
        }
        //    modify_field(ig_eg_header.cap_access          , _metadata.);
        //    modify_field(ig_eg_header.lat_index_msb       , _metadata.);
        
        if (meta.l2.l2_da_type == L2_UNICAST) {
            if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_FLOOD) {
                // Unknown unicast flood
                meta.ig_eg_header.block_epg_crossing =
                    meta.pt_info.mcast_flood_ctrl0;
            } else {
                // Known unicast
                meta.ig_eg_header.block_epg_crossing = 0;
            }
        } else {
            // Unknown or known multicast OR broadcast
            meta.ig_eg_header.block_epg_crossing =
                meta.pt_info.mcast_flood_ctrl1;
        }
        
        // modify_field(ig_eg_header.nat_port            , _metadata.);
        // modify_field(ig_eg_header.nat_type            , _metadata.);
        // modify_field(ig_eg_header., _metadata.);
    }
}

control process_ingress_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("process_ig_sideband_rewrite") process_ig_sideband_rewrite() process_ig_sideband_rewrite_0;
    @name("process_ieth_hdr_rewrite") process_ieth_hdr_rewrite() process_ieth_hdr_rewrite_0;
    @name("process_ig_eg_hdr_rewrite") process_ig_eg_hdr_rewrite() process_ig_eg_hdr_rewrite_0;
    apply {
        process_ig_sideband_rewrite_0.apply(hdr, meta, standard_metadata);
        process_ieth_hdr_rewrite_0.apply(hdr, meta, standard_metadata);
        process_ig_eg_hdr_rewrite_0.apply(hdr, meta, standard_metadata);
    }
}

control process_ig_stats_update(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_CFG_mark_fields")
    action set_CFG_mark_fields(bit<1> override, bit<1> val) {
        meta.CFG_mark.override = override;
        meta.CFG_mark.val = val;
    }
    @name("CFG_mark_register")
    table CFG_mark_register {
        actions = {
            set_CFG_mark_fields;
            @default_only NoAction;
        }
        size = 1;
        default_action = NoAction();
    }
    apply {
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Mark Bit
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        CFG_mark_register.apply();
        if (hdr.ieth.isValid()) {
            meta.ig_local.mark = hdr.ieth.mark;
        } else if (meta.CFG_mark.override == 1) {
            meta.ig_local.mark = meta.CFG_mark.val;
        } else if (meta.src_tep.rw_mark == 1) {
            meta.ig_local.mark = meta.CFG_mark.val;
        } else if ((meta.src_tep.keep_mark == 1) ||
                   (meta.ingress.ifabric_ingress == 0) ||
                   ((meta.ig_tunnel.src_encap_pkt == 1) &&
                    (meta.ig_tunnel.decap == 0)))
        {
            meta.ig_local.mark = hdr.ivxlan.lsb_m;
        } else {
            meta.ig_local.mark = meta.CFG_mark.val;
        }
        
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // OR all the drop conditions
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if (
            (meta.ig_drop.missing_vntag == 1) ||
            (meta.ig_drop.illegal_vntag == 1) ||
            (meta.ig_drop.src_if_miss == 1) ||
            (meta.ig_drop.src_vlan_mbr == 1) ||
            (meta.ig_drop.src_tep_miss == 1) ||
            (meta.ig_drop.iic_check_failure == 1) ||
            (meta.ig_drop.outer_ttl_expired == 1) ||
            (meta.ig_drop.vlan_xlate_miss == 1) ||
            (meta.ig_drop.ttl_expired == 1) ||
            (meta.ig_drop.routing_disabled == 1) ||
            (meta.ig_drop.sgt_xlate_miss == 1) ||
            (meta.ig_drop.src_nat_drop == 1) ||
            (meta.ig_drop.dst_nat_drop == 1) ||
            (meta.ig_drop.twice_nat_drop == 1) ||
            (meta.ig_drop.smac_miss == 1) ||
            (meta.ig_drop.route_miss == 1) ||
            (meta.ig_drop.bridge_miss == 1) ||
            (meta.ig_drop.mtu_check_failure == 1) ||
            (meta.ig_drop.uc_rpf_failure == 1) ||
            (meta.ig_drop.mc_rpf_failure == 1) ||
            (meta.ig_drop.l3_binding_failure == 1) ||
            (meta.ig_drop.ipv6_uc_link_local_cross_bd == 1) ||
            (meta.ig_drop.ipv6_mc_sa_local_da_global_svi == 1) ||
            (meta.ig_drop.ipv6_mc_sa_local_da_global_l3if == 1) ||
            (meta.ig_drop.self_fwd_failure == 1) ||
            (meta.ig_drop.split_horizon_check == 1) ||
            (meta.ig_drop.arp_nd_ucast_cross_bd == 1) ||
            (meta.ig_drop.double_exception == 1) ||
            (meta.ig_drop.secure_mac_move == 1) ||
            (meta.ig_drop.non_secure_mac == 1) ||
            (meta.ig_drop.l2_bind_failure == 1) ||
            (meta.ig_drop.pt_deny == 1) ||
            (meta.ig_drop.qos_policer_drop == 1) ||
            false)
        {
            meta.ig_drop.inc_drop_counters = TRUE;
        }
        
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //   Ingress UMF
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        // -- per-port, byte_n_packets, non-atomic
        // set_umf/drop/cos - 64 ports x 4 (umf) x 2 (drop) x 8 (cos) x 2 (FC) = 8K
        
#ifndef DISABLE_SRC_PORT_UMF_STATS
        // ~~~~~~~~~~ Port Stats ~~~~~~~~~~~~~
        // TODO maybe_wrong_cast
        meta.ig_local.src_port_stats_idx =
            (bit<11>) meta.dp_ig_header.ingress_port;
        
        // UC/MC/BC/Flood
        meta.ig_local.src_port_stats_idx = (meta.ig_local.src_port_stats_idx <<
                                            meta.ingress.l2_fwd_mode);
        
        // cos.
        meta.ig_local.src_port_stats_idx = (meta.ig_local.src_port_stats_idx <<
                                            hdr.qtag0.pcp);
        
        // Total
        if (hdr.fcoe.isValid()) {
            //count(src_port_fc_total_stats, meta.ig_local.src_port_stats_idx);
        } else {
            //count(src_port_eth_total_stats, meta.ig_local.src_port_stats_idx);
        }
        
        // Dropped
        if (meta.ig_drop.inc_drop_counters == 1) {
            if (hdr.fcoe.isValid()) {
                //count(src_port_fc_drop_stats, meta.ig_local.src_port_stats_idx);
            } else {
                //count(src_port_eth_drop_stats, meta.ig_local.src_port_stats_idx);
            }
        }
#endif /*DISABLE_SRC_PORT_UMF_STATS*/

        
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Port-Class
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        // -- per-port - 64 x 10 (in_class) x 2 (drop) x 2 (FC) = 2K
        // pkt_class set in_class/drop
        
#ifndef DISABLE_SRC_PORT_CLASS_STATS
        // ~~~~~~~~~~ Port Stats ~~~~~~~~~~~~~
        // TODO maybe_wrong_cast
        meta.ig_local.src_port_class_stats_idx =
            (bit<11>) meta.dp_ig_header.ingress_port;
        
        // Eth/FC
        if (hdr.fcoe.isValid()) {
            meta.ig_local.src_port_class_stats_idx =
                meta.ig_local.src_port_class_stats_idx << 1;
        }
        
        // iclass.
        meta.ig_local.src_port_class_stats_idx =
            meta.ig_local.src_port_class_stats_idx << meta.ig_qos.iclass;
        
        // Total
        //count(src_port_class_total_stats, meta.ig_local.src_port_class_stats_idx);
        // Dropped
        if (meta.ig_drop.inc_drop_counters == 1) {
            //count(src_port_class_drop_stats, meta.ig_local.src_port_class_stats_idx);
        }
#endif /*DISABLE_SRC_PORT_UMF_STATS*/
        
#ifndef DISABLE_SRC_TEP_STATS
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // TEP RX
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // per src-tep, packets and bytes, atomic
        // mask - mytep, outer_uc, ivxlan_e=0, not_span
        // pkt-class - set drop, fabric_if
        // 256 teps x 2 (mark) x 8 (fabric_if) x 2 (drop)  = 8K
        
        // TEP ID
        // TODO maybe_wrong_cast
        meta.ig_local.src_tep_stats_idx[7:0] = (bit<8>) meta.src_tep.src_ptr;
        
        // Fabric port
        meta.ig_local.src_tep_stats_idx = (meta.ig_local.src_tep_stats_idx <<
                                           meta.src_port.fabric_if_stats_idx);
        
        if ((meta.ig_tunnel.decap == 1) &&
            (meta.ig_tunnel.mc_tunnel_decap == 0) &&
            hdr.ivxlan.isValid() &&
            (hdr.ivxlan.nonce_e == 0)) { // TODO : add span transit here. we dont want to count span copies
            if (meta.ig_drop.inc_drop_counters == 1) {
                if (meta.ig_local.mark == 0) {
                    //count(src_tep_mark0_drop_stats, meta.ig_local.src_tep_stats_idx);
                } else {
                    //count(src_tep_mark1_drop_stats, meta.ig_local.src_tep_stats_idx);
                }
            } else {
                if (meta.ig_local.mark == 0) {
                    //count(src_tep_mark0_total_stats, meta.ig_local.src_tep_stats_idx);
                } else {
                    //count(src_tep_mark1_total_stats, meta.ig_local.src_tep_stats_idx);
                }
            }
        }
#endif /*DISABLE_SRC_TEP_STATS*/

        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // EPG_IN
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // pkt_class - drop
        // 4K EPG x 2 (drop) = 8K
        
#ifndef DISABLE_SRC_BD_STATS
        
        // Total
        //count(src_bd_stats, meta.src_bd.bd_stats_idx);
        
        // Dropped
        if (meta.ig_drop.inc_drop_counters == 1) {
            //count(src_bd_drop_stats, meta.src_bd.bd_stats_idx);
        }
#endif /*DISABLE_SRC_BD_STATS*/
        
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Flow RX and TX
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        // fstat0
        // 1K counters
        // packet_n_bytes, atomic
        // pkt-class drop
        // 1K x 2 (mark) x 2 (drop) = 4K
        
        if (meta.ig_acl.fstat0_hit == 1) {
            if (meta.ig_drop.inc_drop_counters == 1) {
                if (meta.ig_local.mark == 0) {
                    //count(src_tep_mark0_drop_stats, meta.ig_acl.fstat0_hit_idx);
                } else {
                    //count(src_tep_mark1_drop_stats, meta.ig_acl.fstat0_hit_idx);
                }
            } else {
	        if (meta.ig_local.mark == 0) {
		    //count(src_tep_mark0_total_stats, meta.ig_acl.fstat0_hit_idx);
	        } else {
		    //count(src_tep_mark1_total_stats, meta.ig_acl.fstat0_hit_idx);
	        }
	    }
        }
    }
}


/*****************************************************************************/
/* ARP/ND Unicast Mode Decision */
/*****************************************************************************/

control process_arp_nd_unicast_mode(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if ((meta.l3.l3_type == L3TYPE_ARP) &&
            (meta.src_bd.arp_unicast_mode == 1) &&
            (((meta.l3.arp_type == ARP_REQ) &&
              (meta.l3.arp_type != GARP) &&
              (meta.src_bd.arp_req_unicast_mode_dis == 0)) ||
             ((meta.l3.arp_type == ARP_RES) &&
              (meta.l3.arp_type != GARP) &&
              (meta.src_bd.arp_res_unicast_mode_dis == 0)) ||
             ((meta.l3.arp_type == GARP) &&
              (meta.src_bd.garp_unicast_mode_dis == 0))))
        {
            meta.l3.arp_unicast_mode = 1;
        } else {
            meta.l3.arp_unicast_mode = 0;
        }
        
        if ((meta.l3.l3_type == L3TYPE_RARP) &&
            (meta.src_bd.rarp_unicast_mode == 1) &&
            (((meta.l3.arp_type == RARP_REQ) &&
              (meta.src_bd.rarp_req_unicast_mode_dis == 0)) ||
             ((meta.l3.arp_type == RARP_RES) &&
              (meta.src_bd.rarp_res_unicast_mode_dis == 0))))
        {
            meta.l3.rarp_unicast_mode = 1;
        } else {
            meta.l3.rarp_unicast_mode = 0;
        }
        
        if ((meta.l3.l4_type == L4TYPE_ND) &&
            (meta.src_bd.nd_unicast_mode == 1) &&
            (((meta.l3.nd_type == ND_SOL) &&
              (meta.l3.nd_type != ND_GNA) &&
              (meta.src_bd.uc_nd_sol_unicast_mode_dis == 0) &&
              (meta.l3.ip_da_type != IP_MULTICAST)) ||
             ((meta.l3.nd_type == ND_ADV) &&
              (meta.l3.nd_type != ND_GNA) &&
              (meta.src_bd.mc_nd_adv_unicast_mode_dis == 0) &&
              (meta.l3.ip_da_type == IP_MULTICAST))))
        {
            meta.l3.nd_unicast_mode = 1;
        } else {
            meta.l3.nd_unicast_mode = 0;
        }
    }
}

control process_ttl_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (((meta.l3.l3_type == L3TYPE_IPV4 ||
              meta.l3.l3_type == L3TYPE_IPV6) &&
             (meta.l3.lkp_ip_ttl == 1 || meta.l3.lkp_ip_ttl == 0))
#ifndef DISABLE_MPLS
            || ((hdr.mpls[0].isValid() && ((meta.mplsm.outermost_ttl == 1) ||
                                           (meta.mplsm.outermost_ttl == 0))))
#endif /*DISABLE_MPLS*/
            )
        {
            /* TODO: add logic to check ttl for packets with
             * null/entropy labels */
            meta.l3.ttl_expired = TRUE;
        }
    }
}

#ifndef DISABLE_COPP_TCAM

control process_ingress_copp(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    @name("copp_meter") meter(COPP_METER_TABLE_SIZE, MeterType.bytes) copp_meter;
    action ingress_copp_meter(bit<8> sup_qnum,
                              bit<8> policer_select,
                              bit<4> oclass)
    {
	meta.ig_acl.sup_qnum = sup_qnum;
        copp_meter.execute_meter((bit<32>) policer_select,
                                 meta.ingress.copp_drop);
	meta.ingress_sideband.oclass = oclass;
        //meta.ig_qos.oclass = oclass;
    }

    table ingress_mac_copp {
        key = {
            // Common Key Fields
            CMN_ACL_KEY
                
            meta.ig_dst_port.acl_label    : ternary;
            meta.ig_dst_bd.acl_label         : ternary;
            
#ifndef IG_COPP_COPT
            meta.ig_acl.sup_copy     : ternary;
            meta.ig_acl.sup_code     : ternary;
            meta.ig_acl.sup_dst      : ternary;
            meta.ig_acl.sup_redirect : ternary;
#endif /*IG_COPP_OPT*/
            
            MAC_FLOW_KEY
        }
        actions = {
            ingress_copp_meter;
            @default_only NoAction;
        }
        default_action = NoAction();
        size = INGRESS_MAC_COPP_TABLE_SIZE;
    }
    table ingress_ipv4_copp {
        key = {
            // Common Key Fields
            CMN_ACL_KEY
                
            meta.ig_dst_port.acl_label    : ternary;
            meta.ig_dst_bd.acl_label         : ternary;

#ifndef IG_COPP_COPT
            meta.ig_acl.sup_copy     : ternary;
            meta.ig_acl.sup_code     : ternary;
            meta.ig_acl.sup_dst      : ternary;
            meta.ig_acl.sup_redirect : ternary;
#endif /*IG_COPP_OPT*/
            
            IPV4_FLOW_KEY
        }
        actions = {
            ingress_copp_meter;
            @default_only NoAction;
        }
        default_action = NoAction();
        size = INGRESS_IPV4_COPP_TABLE_SIZE;
    }
    table ingress_ipv6_copp {
        key = {
            // Common Key Fields
            CMN_ACL_KEY
            
            meta.ig_dst_port.acl_label    : ternary;
            meta.ig_dst_bd.acl_label         : ternary;
            
#ifndef IG_COPP_COPT
            meta.ig_acl.sup_copy     : ternary;
            meta.ig_acl.sup_code     : ternary;
            meta.ig_acl.sup_dst      : ternary;
            meta.ig_acl.sup_redirect : ternary;
#endif /*IG_COPP_OPT*/
            
            IPV6_FLOW_KEY
        }
        actions = {
            ingress_copp_meter;
            @default_only NoAction;
        }
        default_action = NoAction();
        size = INGRESS_IPV6_COPP_TABLE_SIZE;
    }

    apply {
	if (meta.l3.l3_type == L3TYPE_IPV4) {
	    ingress_ipv4_copp.apply();
	}  else if (meta.l3.l3_type == L3TYPE_IPV6) {
	    ingress_ipv6_copp.apply();
	} else {
	    ingress_mac_copp.apply();
	}
	if (meta.ingress.copp_drop == 1) {
	    if (meta.ig_acl.sup_redirect == 1) {
                meta.ingress.drop_flag = 1;
                meta.ingress_sideband.opcode_drop = 1;
	    } else if (meta.ig_acl.sup_copy == 1) {
                meta.ig_acl.sup_copy = 0;
	    }
	}
    }
}
//  END HAND TRANSLATION //////////////////////////////////////////////////

#endif /*DISABLE_COPP_TCAM*/

//#ifdef ACI_TOR_MODE
#ifndef DISABLE_SERVICE_BYPASS

control process_service_bypass_info(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action set_CFG_BdServiceBypassInfo_fields(
                //bit<1> arp_nd_unicast_bypass,
                //bit<1> src_if_pruning_bypass,
                bit<1> rpf_bypass,
                //bit<1> drop_vec_bypass,
                //bit<1> outer_cbl_bypass,
                //bit<1> ieth_regen_flood_mc_idx,
                bit<1> keep_ieth,
                //bit<1> keep_ieth_src,
                //bit<1> use_ieth_l3mc_info,
                //bit<1> use_ieth_l2mc_info,
                //bit<1> use_ieth_dport,
                //bit<1> use_ieth_dchip,
                //bit<1> drop_bypass_code,
                //bit<1> outer_mc_bypass,
                //bit<1> my_tep_bypass,
                //bit<1> vif_bypass,
                bit<1> outer_vlan_xlate_bypass,
                //bit<1> ovector_bypass,
                bit<1> is_rmac_bypass,
                bit<1> eg_mtu_check_bypass,
                //bit<1> fp_da_bypass,
                //bit<1> fp_sa_bypass,
                bit<1> pt_bypass,
                //bit<1> drop_count_bypass,
                bit<1> fwd_lookup_bypass,
                bit<1> acl_bypass,
                //bit<1> vlan_mbr_bypass,
                //bit<1> ttl_bypass,
                //bit<1> force_bridge,
                //bit<1> cdce_sa_gen_bypass,
                bit<1> learn_bypass,
                //bit<1> cos_map_bypass,
                //bit<1> vlan_xlate_bypass,
                //bit<1> fcf_adjacency_bypass,
                bit<1> sup_rx_bypass
                //bit<1> sgt_bypass
                )
    {
//	meta.CFG_BdServiceBypassInfo.arp_nd_unicast_bypass = arp_nd_unicast_bypass;
//	meta.CFG_BdServiceBypassInfo.src_if_pruning_bypass = src_if_pruning_bypass;
        meta.CFG_BdServiceBypassInfo.rpf_bypass = rpf_bypass;
//	meta.CFG_BdServiceBypassInfo.drop_vec_bypass = drop_vec_bypass;
//	meta.CFG_BdServiceBypassInfo.outer_cbl_bypass = outer_cbl_bypass;
//	meta.CFG_BdServiceBypassInfo.ieth_regen_flood_mc_idx = ieth_regen_flood_mc_idx;
	meta.CFG_BdServiceBypassInfo.keep_ieth = keep_ieth;
//	meta.CFG_BdServiceBypassInfo.keep_ieth_src = keep_ieth_src;
//	meta.CFG_BdServiceBypassInfo.use_ieth_l3mc_info = use_ieth_l3mc_info;
//	meta.CFG_BdServiceBypassInfo.use_ieth_l2mc_info = use_ieth_l2mc_info;
//	meta.CFG_BdServiceBypassInfo.use_ieth_dport = use_ieth_dport;
//	meta.CFG_BdServiceBypassInfo.use_ieth_dchip = use_ieth_dchip;
//	meta.CFG_BdServiceBypassInfo.drop_bypass_code = drop_bypass_code;
//	meta.CFG_BdServiceBypassInfo.outer_mc_bypass = outer_mc_bypass;
//	meta.CFG_BdServiceBypassInfo.my_tep_bypass = my_tep_bypass;
//	meta.CFG_BdServiceBypassInfo.vif_bypass = vif_bypass;
	meta.CFG_BdServiceBypassInfo.outer_vlan_xlate_bypass = outer_vlan_xlate_bypass;
//	meta.CFG_BdServiceBypassInfo.ovector_bypass = ovector_bypass;
	meta.CFG_BdServiceBypassInfo.is_rmac_bypass = is_rmac_bypass;
	meta.CFG_BdServiceBypassInfo.eg_mtu_check_bypass = eg_mtu_check_bypass;
//	meta.CFG_BdServiceBypassInfo.fp_da_bypass = fp_da_bypass;
//	meta.CFG_BdServiceBypassInfo.fp_sa_bypass = fp_sa_bypass;
	meta.CFG_BdServiceBypassInfo.pt_bypass = pt_bypass;
//	meta.CFG_BdServiceBypassInfo.drop_count_bypass = drop_count_bypass;
	meta.CFG_BdServiceBypassInfo.fwd_lookup_bypass = fwd_lookup_bypass;
	meta.CFG_BdServiceBypassInfo.acl_bypass = acl_bypass;
//	meta.CFG_BdServiceBypassInfo.vlan_mbr_bypass = vlan_mbr_bypass;
//	meta.CFG_BdServiceBypassInfo.ttl_bypass = ttl_bypass;
//	meta.CFG_BdServiceBypassInfo.force_bridge = force_bridge;
//	meta.CFG_BdServiceBypassInfo.cdce_sa_gen_bypass = cdce_sa_gen_bypass;
	meta.CFG_BdServiceBypassInfo.learn_bypass = learn_bypass;
//	meta.CFG_BdServiceBypassInfo.cos_map_bypass = cos_map_bypass;
//	meta.CFG_BdServiceBypassInfo.vlan_xlate_bypass = vlan_xlate_bypass;
//	meta.CFG_BdServiceBypassInfo.fcf_adjacency_bypass = fcf_adjacency_bypass;
	meta.CFG_BdServiceBypassInfo.sup_rx_bypass = sup_rx_bypass;
//	meta.CFG_BdServiceBypassInfo.sgt_bypass = sgt_bypass;
    }

    table CFG_BdServiceBypassInfo_register {
        actions = {
            set_CFG_BdServiceBypassInfo_fields;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = 1;
    }

    apply {
        CFG_BdServiceBypassInfo_register.apply();
        if (meta.src_bd.service_redir == 1) {
	    meta.bypass_info.outer_vlan_xlate_bypass = meta.CFG_BdServiceBypassInfo.outer_vlan_xlate_bypass;
	    meta.bypass_info.rpf_bypass = meta.CFG_BdServiceBypassInfo.rpf_bypass;
	    meta.bypass_info.is_rmac_bypass = meta.CFG_BdServiceBypassInfo.is_rmac_bypass;
	    meta.bypass_info.pt_bypass = meta.CFG_BdServiceBypassInfo.pt_bypass;
	    meta.bypass_info.fwd_lookup_bypass = meta.CFG_BdServiceBypassInfo.fwd_lookup_bypass;
	    meta.bypass_info.acl_bypass = meta.CFG_BdServiceBypassInfo.acl_bypass;
	    meta.bypass_info.learn_bypass = meta.CFG_BdServiceBypassInfo.learn_bypass;
	    meta.bypass_info.sup_rx_bypass = meta.CFG_BdServiceBypassInfo.sup_rx_bypass;
	    meta.bypass_info.eg_mtu_check_bypass = meta.CFG_BdServiceBypassInfo.eg_mtu_check_bypass;
        }
    }
}

#endif /*DISABLE_SERVICE_BYPASS*/
//#endif /*ACI_TOR_MODE*/


#ifndef DISABLE_IG_MTU_CHECK
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// MTU Check
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

control process_mtu_check (inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action set_mtu_info(bit<16> mtu_val) {
        meta.ig_local.mtu_val = mtu_val;
    }
    
    table ip_mtu_table {
        key = {
	    meta.ig_local.mtu_idx : exact;
        }
        actions = {
            set_mtu_info;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = MTU_TABLE_SIZE;
    }

    apply {
        if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) {
            // TODO maybe_wrong_cast
            meta.ig_local.mtu_idx = (bit<7>) meta.ig_dst_bd.mtu_idx;
        } else {
            // TODO maybe_wrong_cast
            meta.ig_local.mtu_idx = (bit<7>) meta.multicast.mtu_idx;
            meta.ig_local.mtu_idx = meta.ig_local.mtu_idx | 0x10;
        }
        
        // TODO: double check this shift amount to see if it is
        // correct.  I am going to insert a cast that avoids compiler
        // warnings on the width of the operands.
        meta.ig_local.mtu_idx_msb = ((bit<7>) meta.l3.l3_type) << 5;
        meta.ig_local.mtu_idx =
            meta.ig_local.mtu_idx | meta.ig_local.mtu_idx_msb;
        
        ip_mtu_table.apply();
        
        if ((meta.bypass_info.eg_mtu_check_bypass == 0) &&
            (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) &&
            //((meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) ||
            // (meta.ingress.l3_fwd_mode == L3_FWD_MODE_MPLS)) &&
            (meta.ig_local.mtu_val < meta.l3.lkp_ip_len))
        {
            meta.ig_drop.mtu_check_failure = TRUE;
            //meta.ig_drop.inc_drop_counters = TRUE;
        }
    }
}
#endif /*DISABLE_IG_MTU_CHECK*/


#ifndef MERGE_2LAYER_VPC_RESOLUTION
/*****************************************************************************/
/* 2-layer VPC resolution                                                    */
/*****************************************************************************/

control process_dst_vpc (inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action select_vpc_member(bit<13> base) {
        // Since the '2' arg means to do modulo 2, and the hash
        // algorithm is 'identity', this looks like it is equivalent
        // to the following commented-out assignment:
        //meta.ingress.dst_vpc_idx = base + (bit<13>) meta.hash.hash2[0:0];
        hash(meta.ingress.dst_vpc_idx, HashAlgorithm.identity,
             base, { meta.hash.hash2 }, (bit<32>) 2);
    }
    table dst_vpc_mbr {
        key = {
    	    meta.ingress.dst_if_idx : exact;
        }
        // action_profile: vpc_action_profile;
        actions = {
    	    select_vpc_member;
            @default_only NoAction;
        }
        default_action = NoAction;
        size = VPC_MP_TABLE_SIZE;
    }
    apply {
        dst_vpc_mbr.apply();
    }
}

#endif


control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action read_CFG_ig_aci_tor_mode(bit<1> enable) {
        meta.CFG_aci_tor_mode.enable = enable;
    }
    table CFG_ig_aci_tor_mode {
        key = { }
        actions = { read_CFG_ig_aci_tor_mode; }
        default_action = read_CFG_ig_aci_tor_mode(0);
    }
    @name(".set_dst_l2_rw_adjacency")
    action set_dst_l2_rw_adjacency(bit<14> bd, bit<48> mac,
                                   bit<1> is_ptr, bit<13> ptr_or_idx)
    {
        meta.ingress.dst_ptr_or_idx = ptr_or_idx;
        meta.ingress.dst_is_ptr = is_ptr;
        meta.ig_tunnel.encap = FALSE;
        meta.dst_adj.mac = mac;
        meta.dst_adj.bd = bd;
        //meta.dst_adj.adj_type = ADJ_TYPE_L2_RW;
    }
    @name(".set_dst_post_route_flood_adjacency")
    action set_dst_post_route_flood_adjacency(bit<14> bd, bit<48> mac,
                                              bit<16> flood_met_ptr)
    {
        meta.ingress.l2_fwd_mode = L2_FWD_MODE_FLOOD;
        meta.ingress.met0_vld = TRUE;
        meta.ingress.met0_ptr = flood_met_ptr;
        meta.ig_tunnel.encap = FALSE;
        meta.dst_adj.mac = mac;
        meta.dst_adj.bd = bd;
        //meta.dst_adj.adj_type = ADJ_TYPE_L2_RW;
    }
    @name(".set_dst_ip_tunnel_encap_adjacency")
    action set_dst_ip_tunnel_encap_adjacency(bit<14> bd, bit<48> mac,
                                             bit<1> is_ptr,
                                             bit<13> ptr_or_idx)
    {
        meta.ingress.dst_ptr_or_idx = ptr_or_idx;
        meta.ingress.dst_is_ptr = is_ptr;
        meta.ig_tunnel.encap = TRUE;
        meta.dst_adj.mac = mac;
        meta.dst_adj.bd = bd;
        //meta.dst_adj.adj_type = ADJ_TYPE_IP_TUNNEL_ENCAP;
    }
    @name(".set_dst_mac_label")
    action set_dst_mac_label(bit<12> label) {
        meta.ig_acl.dst_mac_label = label;
    }
    @name(".inner_rmac_hit")
    action inner_rmac_hit() {
        meta.l3.rmac_hit = TRUE;
    }
    @name(".inner_rmac_miss")
    action inner_rmac_miss() {
        meta.l3.rmac_hit = FALSE;
    }
    @name(".set_src_l2_rw_adjacency")
    action set_src_l2_rw_adjacency(bit<14> bd, bit<48> mac
                                   //bit<8> is_ptr,
                                   //bit<8> ptr_or_idx
                                   )
    {
        //meta.src_adj.ptr_or_idx = ptr_or_idx;
        //meta.src_adj.is_ptr = is_ptr;
        meta.ig_tunnel.encap = FALSE;
        meta.src_adj.mac = mac;
        meta.src_adj.bd = bd;
        //meta.src_adj.adj_type = ADJ_TYPE_L2_RW;
    }
    @name(".set_src_post_route_flood_adjacency")
    action set_src_post_route_flood_adjacency(bit<14> bd, bit<48> mac
                                              //bit<8> flood_met_ptr
                                              )
    {
        //meta.src_adj_metadata.ptr_or_idx = ptr_or_idx;
        //meta.src_adj_metadata.is_ptr = is_ptr;
        meta.ig_tunnel.encap = FALSE;
        meta.src_adj.mac = mac;
        meta.src_adj.bd = bd;
        //meta.src_adj_metadata.adj_type = ADJ_TYPE_L2_RW;
    }
    @name(".set_src_ip_tunnel_encap_adjacency")
    action set_src_ip_tunnel_encap_adjacency(bit<14> bd, bit<48> mac,
                                             bit<1> is_ptr, bit<14> ptr_or_idx)
    {
        meta.src_adj.ptr_or_idx = ptr_or_idx;
        meta.src_adj.is_ptr = is_ptr;
        meta.ig_tunnel.encap = 1;
        meta.src_adj.mac = mac;
        meta.src_adj.bd = bd;
        //meta.src_adj.adj_type = ADJ_TYPE_IP_TUNNEL_ENCAP;
    }
    @name(".set_src_mac_label")
    action set_src_mac_label(bit<12> label) {
        meta.ig_acl.src_mac_label = label;
    }
    @name(".select_tunnel_ecmp_member")
    action select_tunnel_ecmp_member(bit<8> base, bit<8> num_paths) {
        // TODO : use appropriate hash
        hash(meta.ig_tunnel.encap_ecmp_mbr, HashAlgorithm.crc16,
             (bit<16>) base,
             { meta.ipv4m.lkp_ipv4_sa,
                     meta.ipv4m.lkp_ipv4_da,
                     meta.l3.lkp_ip_proto,
                     meta.l3.lkp_l4_sport,
                     meta.l3.lkp_l4_dport },
             (bit<32>) num_paths);
    }
    @name(".set_tunnel_ecmp_mbr_info")
    action set_tunnel_ecmp_mbr_info(bit<13> if_idx, bit<13> encap_l2_ptr,
                                    bit<14> outer_bd)
    {
        meta.ingress.dst_if_idx = if_idx;
        meta.ig_tunnel.encap_l2_idx = encap_l2_ptr;
        meta.ingress.outer_dst_bd = outer_bd;
    }
#ifndef DISABLE_MPLS
    action set_mpls_adjacency(bit<1> lbl0_vld,
                              bit<20> lbl0,
                              bit<13> encap_idx,
                              bit<1> frr_en,
                              bit<14> dst_bd)
    {
        meta.ig_tunnel.encap = TRUE;
        meta.ig_tunnel.encap_idx = encap_idx;
        meta.dst_adj.bd = dst_bd;
        //meta.dst_adj.type = ADJ_TYPE_MPLS;
        meta.mplsm.fib_lbl0_vld = lbl0_vld;
        meta.mplsm.fib_lbl0 = lbl0;
        meta.mplsm.frr_en = frr_en;
    }
#endif /*DISABLE_MPLS*/
    @name("dst_adjacency")
    table dst_adjacency {
        actions = {
            set_dst_l2_rw_adjacency;
            set_dst_post_route_flood_adjacency;
            set_dst_ip_tunnel_encap_adjacency;
#ifndef DISABLE_MPLS
            set_mpls_adjacency;
#endif /*DISABLE_MPLS*/
            @default_only NoAction;
        }
        key = {
            meta.l3.dst_adj_ptr: exact;
        }
        size = ADJACENCY_TABLE_SiZE;
        default_action = NoAction();
    }
    @name("dst_mac_compression")
    table dst_mac_compression {
        actions = {
            set_dst_mac_label;
            @default_only NoAction;
        }
        key = {
            meta.l2.lkp_mac_da: exact;
        }
        size = INGRESS_DST_MAC_COMPRESSION_HASH_TABLE_SIZE;
        // overflow tcam:
        //size = INGRESS_DST_MAC_COMPRESSION_OF_TCAM_SIZE;
        default_action = NoAction();
    }
    @name("inner_rmac")
    table inner_rmac {
        actions = {
            inner_rmac_hit;
            inner_rmac_miss;
            @default_only NoAction;
        }
        key = {
            meta.src_bd.rmac_index: exact;
            hdr.inner_ipv4.isValid(): exact;
            hdr.inner_ipv6.isValid(): exact;
            meta.l2.lkp_mac_da    : ternary;
            //meta.ig_tunnel.l3_tunnel_decap : ternary;
        }
        size = INNER_ROUTER_MAC_TABLE_SIZE;
        default_action = NoAction();
    }
    @name(".select_l3_dst_ecmp_member")
    action select_l3_dst_ecmp_member(bit<8> base, bit<8> num_paths) {
        // TODO : use appropriate hash for v4/v6
        // TBD - This method of ECMP requires that all dst_adj_ptr
        // values be consecutive for the same group of ECMP paths.  Is
        // that a reasonable design?  Perhaps we should add an 'ECMP
        // path' table level of indirection here so that dst_adj_ptr
        // values do not have to be consecutive, but can be anywhere.

        // TBD: Is this the way Sugarbowl really does it?  If so,
        // doesn't this make standalone NXOS FIB software much more
        // slow/difficult for handling changes in the number of paths
        // in an ECMP group?
        hash(meta.l3.dst_adj_ptr, HashAlgorithm.crc16,
             (bit<10>) base,
             { meta.ipv4m.lkp_ipv4_sa,
                     meta.ipv4m.lkp_ipv4_da,
                     meta.l3.lkp_ip_proto,
                     meta.l3.lkp_l4_sport,
                     meta.l3.lkp_l4_dport,
                     meta.ingress.flowlet_id },
             (bit<20>) num_paths);
    }
    @name("l3_dst_ecmp_group")
    table l3_dst_ecmp_group {
        //From P4_14 original:
        //action_profile: l3_ecmp_action_profile;
        actions = {
            select_l3_dst_ecmp_member;
            @default_only NoAction;
        }
        key = {
            meta.l3.dst_ecmp_ptr: exact;
        }
        size = L3_ECMP_GROUP_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("src_adjacency")
    table src_adjacency {
        actions = {
            set_src_l2_rw_adjacency;
            set_src_post_route_flood_adjacency;
            set_src_ip_tunnel_encap_adjacency;
#ifndef DISABLE_MPLS
#endif /*DISABLE_MPLS*/
            @default_only NoAction;
        }
        key = {
            meta.l3.src_adj_ptr: exact;
        }
        size = ADJACENCY_TABLE_SiZE;
        default_action = NoAction();
    }
    @name("src_mac_compression")
    table src_mac_compression {
        actions = {
            set_src_mac_label;
            @default_only NoAction;
        }
        key = {
            meta.l2.lkp_mac_sa: exact;
        }
        size = INGRESS_SRC_MAC_COMPRESSION_HASH_TABLE_SIZE;
        // overflow tcam:
        //size = INGRESS_SRC_MAC_COMPRESSION_OF_TCAM_SIZE;
        default_action = NoAction();
    }
    @name(".set_tunnel_dst_results")
    action set_tunnel_dst_results(bit<4> encap_type, bit<13> tep_idx,
                                  bit<2> encap_l3_type, bit<13> encap_ecmp_ptr,
                                  bit<1> l3_tunnel, bit<4> sh_group,
                                  bit<1> adj_vld, bit<14> adj_idx)
    {
        meta.ig_tunnel.dst_encap_type = encap_type;
        meta.ig_tunnel.encap_idx = tep_idx;
        meta.ig_tunnel.dst_encap_l3_type = encap_l3_type;
        meta.ig_tunnel.encap_ecmp_ptr = encap_ecmp_ptr;
        meta.ig_tunnel.l3_tunnel_encap = l3_tunnel;
        meta.ig_tunnel.dst_sh_group = sh_group;
        meta.ingress.rw_adj_vld = adj_vld;
        meta.ingress.rw_adj_idx = adj_idx;
    }
    @name("tunnel_dst_info")
    table tunnel_dst_info {
        actions = {
            set_tunnel_dst_results;
            @default_only NoAction;
        }
        key = {
            meta.ingress.dst_ptr_or_idx: exact;
            //meta.ig_tunnel.encap_idx : exact;
        }
        size = TUNNEL_REWRITE_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("tunnel_ecmp_group")
    table tunnel_ecmp_group {
        // From P4_14 original:
        //action_profile: tunnel_ecmp_action_profile;
        actions = {
            select_tunnel_ecmp_member;
            @default_only NoAction;
        }
        key = {
            meta.ig_tunnel.encap_ecmp_ptr: exact;
        }
        size = TUNNEL_ECMP_GROUP_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("tunnel_ecmp_mbr")
    table tunnel_ecmp_mbr {
        actions = {
            set_tunnel_ecmp_mbr_info;
            @default_only NoAction;
        }
        key = {
            meta.ig_tunnel.encap_ecmp_mbr: exact;
        }
        size = TUNNEL_ECMP_MEMBER_TABLE_SIZE;
        default_action = NoAction();
    }

    @name("process_decode_outer_headers") process_decode_outer_headers() process_decode_outer_headers_0;
    @name("process_decode_inner_headers") process_decode_inner_headers() process_decode_inner_headers_0;
    @name("process_initial_bypass_code") process_initial_bypass_code() process_initial_bypass_code_0;
    @name("process_src_port_mapping") process_src_port_mapping() process_src_port_mapping_0;
    @name("process_vntag_sanity_check") process_vntag_sanity_check() process_vntag_sanity_check_0;
    @name("process_src_if_mapping") process_src_if_mapping() process_src_if_mapping_0;
    @name("process_outer_src_bd_derivation") process_outer_src_bd_derivation() process_outer_src_bd_derivation_0;
    @name("process_outer_src_bd_stats") process_outer_src_bd_stats() process_outer_src_bd_stats_0;
    @name("process_src_vlan_mbr_check") process_src_vlan_mbr_check() process_src_vlan_mbr_check_0;
    @name("process_rmac_check") process_rmac_check() process_rmac_check_0;
    @name("process_pre_tunnel_decap_fwd_mode") process_pre_tunnel_decap_fwd_mode() process_pre_tunnel_decap_fwd_mode_0;
    @name("process_ig_tunnel_decap_decision") process_ig_tunnel_decap_decision() process_ig_tunnel_decap_decision_0;
    @name("process_src_bd_derivation") process_src_bd_derivation() process_src_bd_derivation_0;
//#ifdef ACI_TOR_MODE
#ifndef DISABLE_SERVICE_BYPASS
    @name("process_service_bypass_info") process_service_bypass_info() process_service_bypass_info_0;
#endif /*DISABLE_SERVICE_BYPASS*/
//#endif /*ACI_TOR_MODE*/
    @name("process_post_tunnel_decap_fwd_mode") process_post_tunnel_decap_fwd_mode() process_post_tunnel_decap_fwd_mode_0;
    @name("process_hashes") process_hashes() process_hashes_0;
    @name("process_vpc_df") process_vpc_df() process_vpc_df_0;
    @name("process_nat_lookup") process_nat_lookup() process_nat_lookup_0;
    @name("process_ipv4_fib_sa_key") process_ipv4_fib_sa_key() process_ipv4_fib_sa_key_0;
    @name("process_ipv4_src_fib_lookup") process_ipv4_src_fib_lookup() process_ipv4_src_fib_lookup_0;
    @name("process_ipv6_fib_sa_key") process_ipv6_fib_sa_key() process_ipv6_fib_sa_key_0;
    @name("process_ipv6_src_fib_lookup") process_ipv6_src_fib_lookup() process_ipv6_src_fib_lookup_0;
    @name("process_src_mac_lookup") process_src_mac_lookup() process_src_mac_lookup_0;
    @name("process_ipv4_fib_da_key") process_ipv4_fib_da_key() process_ipv4_fib_da_key_0;
    @name("process_ipv4_dst_fib_lookup") process_ipv4_dst_fib_lookup() process_ipv4_dst_fib_lookup_0;
    @name("process_ipv6_fib_da_key") process_ipv6_fib_da_key() process_ipv6_fib_da_key_0;
    @name("process_ipv6_dst_fib_lookup") process_ipv6_dst_fib_lookup() process_ipv6_dst_fib_lookup_0;
    @name("process_mc_fib_lookup") process_mc_fib_lookup() process_mc_fib_lookup_0;
//#ifdef ACI_TOR_MODE
    @name("process_compute_ifabric_ftag") process_compute_ifabric_ftag() process_compute_ifabric_ftag_0;
//#endif /*ACI_TOR_MODE*/
    @name("process_dst_mac_lookup") process_dst_mac_lookup() process_dst_mac_lookup_0;
    @name("process_ingress_qos_key") process_ingress_qos_key() process_ingress_qos_key_0;
//#ifdef ACI_TOR_MODE
    @name("process_policy_lookup") process_policy_lookup() process_policy_lookup_0;
    @name("process_service_redir_lookup") process_service_redir_lookup() process_service_redir_lookup_0;
//#endif /*ACI_TOR_MODE*/
    @name("process_learn_notify") process_learn_notify() process_learn_notify_0;
    @name("process_dst_bd") process_dst_bd() process_dst_bd_0;
    @name("process_post_lookup_forwarding_mode") process_post_lookup_forwarding_mode() process_post_lookup_forwarding_mode_0;
    @name("process_storm_control") process_storm_control() process_storm_control_0;
    @name("process_port_security") process_port_security() process_port_security_0;
    @name("process_l2_bind_check") process_l2_bind_check() process_l2_bind_check_0;
    @name("process_l3_bind_check") process_l3_bind_check() process_l3_bind_check_0;
    @name("process_urpf_check") process_urpf_check() process_urpf_check_0;
    @name("process_ipv6_ll_check") process_ipv6_ll_check() process_ipv6_ll_check_0;
#ifndef DISABLE_IG_MTU_CHECK
    @name("process_mtu_check") process_mtu_check() process_mtu_check_0;
#endif /*DISABLE_IG_MTU_CHECK*/
    @name("process_l3_self_fwd_check") process_l3_self_fwd_check() process_l3_self_fwd_check_0;
    @name("process_arp_nd_crossing_check") process_arp_nd_crossing_check() process_arp_nd_crossing_check_0;
    @name("process_uc_sh_check") process_uc_sh_check() process_uc_sh_check_0;
#ifndef MERGE_2LAYER_VPC_RESOLUTION
    @name("process_dst_vpc") process_dst_vpc() process_dst_vpc_0;
#endif
    @name("process_dst_pc") process_dst_pc() process_dst_pc_0;
    @name("process_dst_port") process_dst_port() process_dst_port_0;
//#ifdef ACI_TOR_MODE
    @name("process_double_exception_drop") process_double_exception_drop() process_double_exception_drop_0;
//#endif /*ACI_TOR_MODE*/
    @name("process_ingress_fstat0") process_ingress_fstat0() process_ingress_fstat0_0;
    @name("process_ingress_qos") process_ingress_qos() process_ingress_qos_0;
    @name("process_ingress_sup") process_ingress_sup() process_ingress_sup_0;
#ifndef DISABLE_COPP_TCAM
    @name("process_ingress_copp") process_ingress_copp() process_ingress_copp_0;
#endif
    @name("process_rx_span_filter") process_rx_span_filter() process_rx_span_filter_0;
    @name("process_ingress_rewrite") process_ingress_rewrite() process_ingress_rewrite_0;
    @name("process_ig_stats_update") process_ig_stats_update() process_ig_stats_update_0;
    apply {
        CFG_ig_aci_tor_mode.apply();
        // Decode packet headers
        process_decode_outer_headers_0.apply(hdr, meta, standard_metadata);
        process_decode_inner_headers_0.apply(hdr, meta, standard_metadata);
        // Initial Bypass Info
#ifndef DISABLE_SUP_TX
        process_initial_bypass_code_0.apply(hdr, meta, standard_metadata);
#endif /*DISABLE_SUP_TX*/
        // Local Port -> Global Port Group
        process_src_port_mapping_0.apply(hdr, meta, standard_metadata);
        // Sanity Checks
#ifndef P4_DISABLE_FEX
        process_vntag_sanity_check_0.apply(hdr, meta, standard_metadata);
        // Source Interface Derivation. {src_port_grp, svif} -> src_if
        process_src_if_mapping_0.apply(hdr, meta, standard_metadata);
#endif /*P4_DISABLE_FEX*/
        // Outer BD Derivation. {src_idx, vlan} -> Outer BD
        process_outer_src_bd_derivation_0.apply(hdr, meta, standard_metadata);
        process_outer_src_bd_stats_0.apply(hdr, meta, standard_metadata);

        // VLAN Membership
#ifndef DISABLE_VLAN_MBR_TBL
        if (meta.src_if.vlan_mbr_chk_en == 1) {
            process_src_vlan_mbr_check_0.apply(hdr, meta, standard_metadata);
        }
#endif
	// IDS checks
	//ingress_sanity_check.apply();

	// Initial Forwarding mode determination
        if ((meta.l3.l3_type == L3TYPE_IPV4 ||
             meta.l3.l3_type == L3TYPE_IPV6) &&
            meta.l3.ip_da_type == IP_UNICAST)
        {
            process_rmac_check_0.apply(hdr, meta, standard_metadata);
            //process_ttl_check();
        }
        process_pre_tunnel_decap_fwd_mode_0.apply(hdr, meta, standard_metadata);

        //-------------------------------------------------------------------
        // Tunnel Termination
        //-------------------------------------------------------------------

        //if (meta.bypass_info.my_tep_bypass == 0) {
        //   -- Tunnel Source
        //   -- Tunnel Destination
        //   -- Multicast Outer {*,G}
        //   -- Multicast Outer {S,G}
        //   -- VNID Translation
        //   -- Tunnel Termination
        //   -- VNID BD State
        //   -- Inner Router MAC Check
        //   -- Forwarding mode update
        process_ig_tunnel_decap_decision_0.apply(hdr, meta, standard_metadata);
        //}

        // BD Derivation.
        process_src_bd_derivation_0.apply(hdr, meta, standard_metadata);
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
#ifndef DISABLE_SERVICE_BYPASS
            process_service_bypass_info_0.apply(hdr, meta, standard_metadata);
#endif /*DISABLE_SERVICE_BYPASS*/
        }
//#endif /*ACI_TOR_MODE*/
        /* ~~~~~~ check if inner packet needs to be routed ~~~~~~ */
        inner_rmac.apply();
        // Post-tunnel decap forwarding mode update
        //process_arp_nd_unicast_mode();
        process_post_tunnel_decap_fwd_mode_0.apply(hdr, meta, standard_metadata);
        // Calculate Hash
        process_hashes_0.apply(hdr, meta, standard_metadata);
        // VPC DF
        process_vpc_df_0.apply(hdr, meta, standard_metadata);
        if (meta.bypass_info.fwd_lookup_bypass == 0) {
            // NAT
#ifndef DISABLE_NAT
            process_nat_lookup_0.apply(hdr, meta, standard_metadata);
#endif
            // Source IP lookup
            if (meta.l3.l3_type == L3TYPE_IPV4 ||
                meta.l3.l3_type == L3TYPE_ARP ||
                meta.l3.l3_type == L3TYPE_RARP)
            {
                process_ipv4_fib_sa_key_0.apply(hdr, meta, standard_metadata);
                if (meta.l3.fib_sa_lookup_en == 1) {
                    process_ipv4_src_fib_lookup_0.apply(hdr, meta, standard_metadata);
                }
            } else if (meta.l3.l3_type == L3TYPE_IPV6) {
                process_ipv6_fib_sa_key_0.apply(hdr, meta, standard_metadata);
                if (meta.l3.fib_sa_lookup_en == 1) {
                    process_ipv6_src_fib_lookup_0.apply(hdr, meta, standard_metadata);
                }
            }
            if (meta.l3.src_ecmp_vld == 0) {
                // ECMP resolution is not done for source
                src_adjacency.apply();
            }
            // Source MAC
            process_src_mac_lookup_0.apply(hdr, meta, standard_metadata);
            // Unicast FIB/LFIB lookup
            if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) {
                if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_ROUTE) {
                    if (meta.l3.l3_type == L3TYPE_IPV4) {
                        process_ipv4_fib_da_key_0.apply(hdr, meta, standard_metadata);
                        process_ipv4_dst_fib_lookup_0.apply(hdr, meta, standard_metadata);
                    } else if (meta.l3.l3_type == L3TYPE_IPV6) {
                        process_ipv6_fib_da_key_0.apply(hdr, meta, standard_metadata);
                        process_ipv6_dst_fib_lookup_0.apply(hdr, meta, standard_metadata);
                    }
                }
            }
            // Multicast Lookup
            process_mc_fib_lookup_0.apply(hdr, meta, standard_metadata);
//#ifdef ACI_TOR_MODE
            if (meta.CFG_aci_tor_mode.enable == 1) {
                process_compute_ifabric_ftag_0.apply(hdr, meta, standard_metadata);
            }
//#endif /*ACI_TOR_MODE*/

            // Resolve Adjacency + DMAC Lookup
            // // ACL vs normal forwarding
            // if (meta.ig_acl.redirect == 1) {
            //     acl_redirect.apply();
            // }
            if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) {
                if (meta.ingress.l3_fwd_mode == L3_FWD_MODE_BRIDGE) {
                    process_dst_mac_lookup_0.apply(hdr, meta, standard_metadata);
                } else {
                    if (meta.l3.dst_ecmp_vld == 1) {
                        l3_dst_ecmp_group.apply();
                    }
                    dst_adjacency.apply();
                }
            }

            // ACI Policy
            process_ingress_qos_key_0.apply(hdr, meta, standard_metadata);
//#ifdef ACI_TOR_MODE
            if (meta.CFG_aci_tor_mode.enable == 1) {
                if (meta.bypass_info.pt_bypass == 0) {
                    process_policy_lookup_0.apply(hdr, meta, standard_metadata);
                    process_service_redir_lookup_0.apply(hdr, meta, standard_metadata);
                }
            }
//#endif /*ACI_TOR_MODE*/
            // Source MAC/IP/Sclass learn notification
            process_learn_notify_0.apply(hdr, meta, standard_metadata);
            // Destination BD State
            // if ((meta.ingress.fwd_mode_uc == 1) && (meta.ingress.fwd_mode_route == 1)) {
            process_dst_bd_0.apply(hdr, meta, standard_metadata);
            // }

            // Intermediate Forwarding mode resolution
            process_post_lookup_forwarding_mode_0.apply(hdr, meta, standard_metadata);

            // Security
#ifndef DISABLE_STORM_CONTROL
            process_storm_control_0.apply(hdr, meta, standard_metadata);
#endif
#ifndef DISABLE_PORT_SECURITY
            process_port_security_0.apply(hdr, meta, standard_metadata);
#endif
#ifndef DISABLE_L2_BIND_CHECK
            process_l2_bind_check_0.apply(hdr, meta, standard_metadata);
#endif
#ifndef DISABLE_L3_BIND_CHECK
            process_l3_bind_check_0.apply(hdr, meta, standard_metadata);
#endif

            // DHCP Snooping
            // Dynamic ARP inspection
            // IPSG

#ifndef DISABLE_URPF_CHECK
            process_urpf_check_0.apply(hdr, meta, standard_metadata);
#endif
            process_ipv6_ll_check_0.apply(hdr, meta, standard_metadata);
#ifndef DISABLE_IG_MTU_CHECK
            process_mtu_check_0.apply(hdr, meta, standard_metadata);
#endif /*DISABLE_IG_MTU_CHECK*/
#ifndef DISABLE_L3_SELF_FWD_CHECK
            process_l3_self_fwd_check_0.apply(hdr, meta, standard_metadata);
#endif /*DISABLE_L3_SELF_FWD_CHECK*/
            process_arp_nd_crossing_check_0.apply(hdr, meta, standard_metadata);

            // Tunnel Destination/ECMP
            if (meta.ingress.dst_is_ptr == 1) {
                tunnel_dst_info.apply();
                tunnel_ecmp_group.apply();
                tunnel_ecmp_mbr.apply();
                process_uc_sh_check_0.apply(hdr, meta, standard_metadata);
            } else {
                // jafinger - I checked this change with Ashu Agarwal,
                // and he says this is one way to do it that should be
                // correct.  Assigning a value to
                // meta.ingress.dst_if_idx earlier, at the same time
                // meta.ingress.dst_ptr_or_idx is assigned a value,
                // would also be correct, and depending upon the
                // compiler and target might lead to a more efficient
                // compilation result than doing so here, but for now
                // I just want something correct.

                // If dst_ptr_or_idx is an idx, then copy it to
                // dst_if_idx.
                meta.ingress.dst_if_idx = meta.ingress.dst_ptr_or_idx;
            }
        } /* fwd_lookup_bypass */

        // Determine output port for unicast
        // 2-Layer VPC
        // Unicast Portchannel Resolution
        if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_UC) {
#ifndef MERGE_2LAYER_VPC_RESOLUTION
            process_dst_vpc_0.apply(hdr, meta, standard_metadata);
#endif
            process_dst_pc_0.apply(hdr, meta, standard_metadata);
            process_dst_port_0.apply(hdr, meta, standard_metadata);
        }
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            process_double_exception_drop_0.apply(hdr, meta, standard_metadata);
        }
//#endif /*ACI_TOR_MODE*/

        // ACLs
        if (meta.bypass_info.acl_bypass == 0) {
            // MAC address compression
            src_mac_compression.apply();
            dst_mac_compression.apply();
            process_ingress_fstat0_0.apply(hdr, meta, standard_metadata);
        }
        // QoS
        process_ingress_qos_0.apply(hdr, meta, standard_metadata);

        //-------------------------------------------------------------------
        // Flooding/Multicast 
        //-------------------------------------------------------------------
        // if (meta.ingress.l2_fwd_mode == L2_FWD_MODE_FLOOD) {
        //     process_flood();
        //     // Get met_ptr for flood
        // }

        // SUP Redirection/Copy
        if (meta.bypass_info.sup_rx_bypass == 0) {
            process_ingress_sup_0.apply(hdr, meta, standard_metadata);
#ifndef DISABLE_COPP_TCAM
            // CoPP
            process_ingress_copp_0.apply(hdr, meta, standard_metadata);
#endif /*DISABLE_COPP_TCAM*/
            // Merge sup results with normal forwarding
        }
        // SPAN Filter
        process_rx_span_filter_0.apply(hdr, meta, standard_metadata);
        //process_tx_span_filter();

        // MAC Learning
        ////    process_mac_learning();

        // Form ingress output bundles
        process_ingress_rewrite_0.apply(hdr, meta, standard_metadata);
        // Stats
        process_ig_stats_update_0.apply(hdr, meta, standard_metadata);
    }
}
