
// TBDP416 - currently not called from anywhere.  It isn't called
// anywhere in the original P4_14 code, either.  Should it be?
control process_initial_pkt_len_calc(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // Assumption here is that IP packets are cut-through and rest
        // are store-n-forward Start with length from either IP header
        // or datapath
        if (hdr.ipv4.isValid()) {
            meta.egress.pkt_len = hdr.ipv4.totalLen;
        } else if (hdr.ipv6.isValid()) {
            meta.egress.pkt_len = hdr.ipv6.payloadLen + 40;
        } else {
            // TODO maybe_wrong_cast
            meta.egress.pkt_len = (bit<16>) meta.dp_eg_header.blen;
        }
        
        // Add L2 tags for IP packets
        if (hdr.ipv4.isValid() || hdr.ipv6.isValid()) {
            if (hdr.ethernet.isValid()) {
                meta.egress.pkt_len = meta.egress.pkt_len + 14;
            }
            if (hdr.vntag.isValid()) {
                meta.egress.pkt_len = meta.egress.pkt_len + 6;
            }
            if (hdr.qtag0.isValid()) {
                meta.egress.pkt_len = meta.egress.pkt_len + 4;
            }
            if (hdr.qtag1.isValid()) {
                meta.egress.pkt_len = meta.egress.pkt_len + 4;
            }
            if (hdr.cmd_sgt.isValid()) {
                meta.egress.pkt_len = meta.egress.pkt_len + 8;
            }
            if (hdr.timestamp.isValid()) {
                meta.egress.pkt_len = meta.egress.pkt_len + 8;
            }
        }
    }
}

control process_eg_span_session(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_span_session_info")
    action set_span_session_info(bit<10> ses, bit<2> gra, bit<1> dir,
                                 bit<1> erspan_t)
    {
        meta.eg_local.erspan_gra = gra;
        meta.eg_local.erspan_t = erspan_t;
        meta.eg_local.span_dir = dir;
        meta.eg_local.erspan_ses = ses;
    }
    @name("span_session_info") table span_session_info {
        actions = {
            set_span_session_info;
            @default_only NoAction;
        }
        key = {
            meta.dp_eg_header.spanvld     : exact;
            meta.dp_eg_header.spansess    : exact;
            meta.dp_eg_header.service_copy: exact;
            // TBDP416: In P4_14 version, the key field
            // meta.met.adj_vld had a mask of 0x1F, but it is only a
            // 1-bit wide field.  Why was a mask used on it?  Should
            // it have been used on a different field instead?
            meta.met.adj_vld     : exact;
        }
        size = SPAN_SESSION_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        span_session_info.apply();

        // ERSPAN header fields
        
        // // Alternate implementation for erspan ver2
        //meta.eg_local.erspan_ver = 0x3; // Assuming that qtag_bypass is set and hence qtag is left intact. Set en to vlanTagInPacket
        //meta.eg_local.erspan_vlan = hdr.qtag0.vid; // This assignment is not strictly necessary becase we left the qtag in the packet
        //meta.eg_local.erspan_cos =  hdr.qtag0.pcp; // This assignment is not strictly necessary becase we left the qtag in the packet
    }
}

control process_egress_bypass(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_eg_bypass_info")
    action set_eg_bypass_info(bit<1> vntag_bypass, bit<1> qtag_bypass,
                              bit<1> cmd_bypass, bit<1> l2_rw_bypass,
                              bit<1> ttl_dec_bypass, bit<1> qos_rw_bypass,
                              bit<1> acl_bypass, bit<1> switchport_block_bypass,
                              bit<1> service_rw_bypass,
                              bit<1> tunnel_encap_bypass,
                              bit<1> tunnel_decap_bypass,
                              bit<1> vlan_mbr_chk_bypass,
                              bit<1> same_if_check_bypass,
                              bit<1> same_vtep_check_bypass)
    {
        // meta.eg_bypass.keep_ieth = keep_ieth;
        // meta.eg_bypass.higig_qtag_bypass = higig_qtag_bypass;
        // meta.eg_bypass.passthru = passthru;
        // meta.eg_bypass.passthru_ecn_only = passthru_ecn_only;
        // meta.eg_bypass.encap_change_bypass = encap_change_bypass;
        // meta.eg_bypass.fcoe_mac_bypass = fcoe_mac_bypass;
        meta.eg_bypass.switchport_block_bypass = switchport_block_bypass;
        meta.eg_bypass.l2_rw_bypass = l2_rw_bypass;
        meta.eg_bypass.service_rw_bypass = service_rw_bypass;
        meta.eg_bypass.tunnel_decap_bypass = tunnel_decap_bypass;
        meta.eg_bypass.tunnel_encap_bypass = tunnel_encap_bypass;
        meta.eg_bypass.vntag_bypass = vntag_bypass;
        meta.eg_bypass.qtag_bypass = qtag_bypass;
        meta.eg_bypass.cmd_bypass = cmd_bypass;
        // meta.eg_bypass.ttag_bypass = ttag_bypass;
        // meta.eg_bypass.l3_bypass = l3_bypass;
        // meta.eg_bypass.l4_bypass = l4_bypass;
        meta.eg_bypass.ttl_dec_bypass = ttl_dec_bypass;
        // meta.eg_bypass.ecn_mark_bypass = ecn_mark_bypass;
        meta.eg_bypass.qos_rw_bypass = qos_rw_bypass;
        // meta.eg_bypass.nat_rw_bypass = nat_rw_bypass;
        meta.eg_bypass.acl_bypass = acl_bypass;
        // meta.eg_bypass.vlan_xlate_bypass = vlan_xlate_bypass;
        // meta.eg_bypass.outer_vlan_xlate_bypass = outer_vlan_xlate_bypass;
        // meta.eg_bypass.eg_mtu_check_bypass = eg_mtu_check_bypass;
        // meta.eg_bypass.drop_mask_sel = drop_mask_sel;
        // meta.eg_bypass.qtag_vif_setting = qtag_vif_setting;
        // meta.eg_bypass.inner_vntag_bypass = inner_vntag_bypass;
        // meta.eg_bypass.inner_qtag_bypass = inner_qtag_bypass;
        // meta.eg_bypass.inner_ttag_bypass = inner_ttag_bypass;
        // meta.eg_bypass.sup_tx_drop_mask_en = sup_tx_drop_mask_en;
        // meta.eg_bypass.sup_tx_drop_mask_idx = sup_tx_drop_mask_idx;
        meta.eg_bypass.vlan_mbr_chk_bypass = vlan_mbr_chk_bypass;
        meta.eg_bypass.same_if_check_bypass = same_if_check_bypass;
        meta.eg_bypass.same_vtep_check_bypass = same_vtep_check_bypass;
    }
    @name("eg_bypass_info_table") table eg_bypass_info_table {
        actions = {
            set_eg_bypass_info;
            @default_only NoAction;
        }
        key = {
            // SPAN
            meta.dp_eg_header.spanvld      : ternary;
            meta.dp_eg_header.spansess     : ternary;
            meta.ig_eg_header.erspan_term  : ternary;

            // Copy Service
            meta.dp_eg_header.service_copy : ternary;
            
            // Service Redirection
            meta.ig_eg_header.service_redir: ternary;

            // SUP - RX
            meta.dp_eg_header.localcpu     : ternary;
            
            // SUP - TX
            meta.ig_eg_header.ieth_sup_tx  : ternary;
            meta.ig_eg_header.ieth_sup_code: ternary;
            //meta.egress.bypass_code        : exact;
        }
        size = 64;
        default_action = NoAction();
    }
    apply {
        //    // Bypass code generation
        //if (meta.ig_eg_header.ieth_span == 1) {
	//    meta.egress.bypass_code = EGRESS_BYPASS_CODE_SPAN;
	// } else if (ig_eg_header.ieth_sup_tx == 1) {
	//    meta.egress.bypass_code = ig_eg_header.ieth_sup_code;
	// } else if (dp_eg_header.localcpu == 1) {
	//    meta.egress.bypass_code = EGRESS_BYPASS_CODE_SUP_RX_LOCAL;
	// #ifndef ACI_TOR_MODE
	// } else if (dp_eg_header.cpu == 1) {
	//    meta.egress.bypass_code = EGRESS_BYPASS_CODE_SUP_RX_REMOTE;
	// #endif /*ACI_TOR_MODE*/
	// } else if (met_metadata.service_vld == 1) {
	//    meta.egress.bypass_code = EGRESS_BYPASS_CODE_COPY_SERVICE;
	////TODO } else if (meta.egress.service_redirect == 1) {
	////    meta.egress.bypass_code = EGRESS_BYPASS_CODE_SERVICE;
	// } else if (ig_eg_header.erspan_term == 1) {
	//    meta.egress.bypass_code = EGRESS_BYPASS_CODE_ERSPAN_TERM;
	// }

        // Access Bypass Info table
        eg_bypass_info_table.apply();
    }
}

control process_remove_l2_tags(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // Remove vntag
        if (meta.eg_bypass.vntag_bypass == 0) {
            if (hdr.vntag.isValid()) {
                hdr.ethernet.etherType = hdr.vntag.etherType;
                hdr.vntag.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
                meta.egress.pkt_len = meta.egress.pkt_len - 6;
#endif /*DISABLE_PKT_LEN_CALC*/
            }
        }
        
        // Remove qtag unless packet arrived on a qinq customer port
        // Copy original header fields for later use in erspan encap
        if (hdr.qtag0.isValid()) {
            meta.eg_local.src_qtag0_vld = TRUE;
            meta.eg_local.src_qtag0_vid = hdr.qtag0.vid;
            meta.eg_local.src_qtag0_pcp = hdr.qtag0.pcp;
        }
        
        if (hdr.qtag0.isValid() && (meta.eg_bypass.qtag_bypass == 0) &&
            (meta.ig_eg_header.qinq_customer_port == 0))
        {
            if (hdr.vntag.isValid()) {
                hdr.vntag.etherType = hdr.qtag0.etherType;
            } else {
                hdr.ethernet.etherType = hdr.qtag0.etherType;
            }
            hdr.qtag0.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 4;
#endif /*DISABLE_PKT_LEN_CALC*/
        }
    }
}

control process_tunnel_decision(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
//#ifndef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 0) {
            // Decide if we want to use met
            if ((meta.dp_eg_header.met_v == 1) &&
                (meta.met.fm_bridge_only == 0))
            {
                meta.egress.use_met = TRUE;
            } else {
                meta.egress.use_met = FALSE;
            }
            
            // Decide if we want to use info from encap table
            if (meta.ig_eg_header.ieth_dst_is_tunnel == 1) {
                meta.egress.use_encap = TRUE;
                //	meta.egress.encap_idx = meta.ig_eg_header.encap_idx;
            } else if (meta.met.encap_vld == 1) {
                meta.egress.use_encap = TRUE;
                //	meta.egress.encap_idx = meta.met.encap_idx;
            } else {
                meta.egress.use_encap = FALSE;
                //	meta.egress.encap_idx = 0;
            }
        }
//#endif /*ACI_TOR_MODE*/

        // Decide if tunnel needs to be terminated
        if ((meta.ig_eg_header.ieth_src_is_tunnel == 1) &&
            (meta.eg_bypass.tunnel_decap_bypass == 0) &&
            // Unicast
            ((meta.dp_eg_header.met_v == 0) ||
             // MUlti-destination
             (meta.met.encap_vld == 0)))
        {
            // Assumptions : encap entries are programmed with
            // encap_vld=1. Native entries are programmed with
            // encap_vld=0. These settings may be different than
            // sugarbowl.
            meta.egress.tunnel_decap = TRUE;
        } else {
            meta.egress.tunnel_decap = FALSE;
        }
        
        // Decide if tunnel encap is needed
        if ((meta.eg_bypass.tunnel_encap_bypass == 0) &&
            // Unicast tunnel encap decided by ingress
            (((meta.dp_eg_header.met_v == 0) && (meta.ig_eg_header.ieth_dst_is_tunnel == 1)) ||
             // met0 replication and encapsulated entry
             ((meta.dp_eg_header.met_v == 1) && (meta.met.encap_vld == 1) && (meta.dp_eg_header.met1_v == 0))))
        {
            meta.egress.tunnel_encap = FALSE;
        }
        
        // if (meta.egress.use_met == 1) {
	//     meta.egress.tunnel_decap = meta.egress.use_encap; // If encap table is not used, it's a multicast transit case
	// } else {
	//     meta.egress.tunnel_decap = meta.ig_eg_header.ieth_dst_is_tunnel; // if dst_is_tunnel is set, it's a re-encap case
	// }
        
    }
}

control process_tunnel_decap_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // ~~~~~~ Remove outer L2 ~~~~~~
        hdr.ethernet.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
        meta.egress.pkt_len = meta.egress.pkt_len - 14;
#endif /*DISABLE_PKT_LEN_CALC*/
        
        ///// //ppp foreach my $l2_tag (@l2_tags) {
	///// if (hdr.$l2_tag_header.isValid()) {
        /////     hdr.$l2_tag_header.setInvalid();
        ///// 
        ///// }
	///// //ppp }
        if (hdr.ieth.isValid()) {
            hdr.ieth.setInvalid();
            //meta.egress.pkt_len = meta.egress.pkt_len - 16;
        }
        if (hdr.vntag.isValid()) {
            hdr.vntag.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 6;
#endif /*DISABLE_PKT_LEN_CALC*/
        }
        if (hdr.qtag0.isValid()) {
            meta.eg_local.outer_cos = hdr.qtag0.pcp;
            meta.eg_local.outer_de = hdr.qtag0.cfi;
            hdr.qtag0.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 4;
#endif /*DISABLE_PKT_LEN_CALC*/
        }
        if (hdr.qtag1.isValid()) {
            hdr.qtag1.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 4;
#endif /*DISABLE_PKT_LEN_CALC*/
        }
        if (hdr.cmd.isValid()) {
            hdr.cmd.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 8;
#endif /*DISABLE_PKT_LEN_CALC*/
        }
        if (hdr.timestamp.isValid()) {
            hdr.timestamp.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 8;
#endif /*DISABLE_PKT_LEN_CALC*/
        }
        
        // ~~~~~~ Remove outer IP ~~~~~~
        if (hdr.ipv4.isValid()) {
            meta.eg_local.outer_src_ttl = hdr.ipv4.ttl;
            meta.eg_local.outer_dscp = hdr.ipv4.dscp;
            meta.eg_local.outer_ecn = hdr.ipv4.ecn;
            meta.eg_local.outer_ipv4_sa = hdr.ipv4.srcAddr;
            hdr.ipv4.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 20;
#endif /*DISABLE_PKT_LEN_CALC*/
        } else if (hdr.ipv6.isValid()) {
            meta.eg_local.outer_src_ttl = hdr.ipv6.hopLimit;
            meta.eg_local.outer_dscp = hdr.ipv6.dscp;
            meta.eg_local.outer_ecn = hdr.ipv6.ecn;
            hdr.ipv6.setInvalid();
            meta.eg_local.outer_ipv6_sa = hdr.ipv6.srcAddr;
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 40;
#endif /*DISABLE_PKT_LEN_CALC*/
        }
        
        // ~~~~~~ Remove outer L4 ~~~~~~
	if (hdr.udp.isValid()) {
	    hdr.udp.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 4;
#endif /*DISABLE_PKT_LEN_CALC*/
	}
        
        // ~~~~~~ Remove tunnel header  ~~~~~~
	if (hdr.vxlan.isValid()) {
	    hdr.vxlan.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 8; // vxlan/ivxlan
#endif /*DISABLE_PKT_LEN_CALC*/
	}
	if (hdr.ivxlan.isValid()) {
	    hdr.ivxlan.setInvalid();
#ifndef DISABLE_PKT_LEN_CALC
            meta.egress.pkt_len = meta.egress.pkt_len - 8; // vxlan/ivxlan
#endif /*DISABLE_PKT_LEN_CALC*/
	}
        
        // ~~~~~~ copy inner L2 to outer L2 ~~~~~~
        hdr.ethernet = hdr.inner_ethernet;
        
	if (hdr.inner_qtag0.isValid()) {
	    hdr.qtag0 = hdr.inner_qtag0;
	}
	if (hdr.inner_cmd.isValid()) {
	    hdr.cmd = hdr.inner_cmd;
	}
	if (hdr.inner_timestamp.isValid()) {
	    hdr.timestamp = hdr.inner_timestamp;
	}
        
        // ~~~~~~ Copy Inner L3 header to outer L3 ~~~~~~
	if (hdr.ipv4.isValid()) {
	    hdr.ipv4 = hdr.inner_ipv4;
	}
	if (hdr.ipv6.isValid()) {
	    hdr.ipv6 = hdr.inner_ipv6;
	}
	if (hdr.fcoe.isValid()) {
	    hdr.fcoe = hdr.inner_fcoe;
	}
        if (hdr.ipv4.isValid()) {
            meta.l3.lkp_ip_dscp = hdr.ipv4.dscp;
            meta.l3.lkp_ip_ecn = hdr.ipv4.ecn;
            meta.l3.lkp_ip_ttl = hdr.ipv4.ttl;
        } else {
            meta.l3.lkp_ip_dscp = hdr.ipv6.dscp;
            meta.l3.lkp_ip_ecn = hdr.ipv6.ecn;
            meta.l3.lkp_ip_ttl = hdr.ipv6.hopLimit;
        }
        
        // ~~~~~~ Copy Inner L4 header to outer L4 ~~~~~~
	if (hdr.tcp.isValid()) {
	    hdr.tcp = hdr.inner_tcp;
	}
	if (hdr.udp.isValid()) {
	    hdr.udp = hdr.inner_udp;
	}
	if (hdr.icmp.isValid()) {
	    hdr.icmp = hdr.inner_icmp;
	}
        
        
        // tunnel_decap_outer_ip.apply();
        // tunnel_decap_outer_l4.apply();
        // if (meta.ig_eg_header.tunnel_encap == 0) { // skip for re-encap cases
	//	tunnel_decap_inner_to_outer_l2.apply();
	//	tunnel_decap_inner_to_outer_l3.apply();
	//	tunnel_decap_inner_to_outer_l4.apply();
	//	/* TODO. inner_to_outer_l4. We don't touch inner l4, do we need to explicitly copy inner to outer */
	//    }
    }
}

control process_dst_port_state(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_dst_port_state")
        action set_dst_port_state(//bit<8> dst_port_grp,
                                  bit<7> uc_vif_xlate_idx,
                                  bit<1> block_bc, bit<1> block_umc,
                                  bit<1> block_uuc,
                                  //bit<8> vnic_mcast_vif,
                                  bit<8> pcnum, bit<3> fabric_if_stats_idx,
#ifdef P4_DISABLE_FEX
                                  dst_if_label, vlan_mode,
                                  default_vlan, untag_default_vlan,
                                  priority_tag_default_vlan, bd_xlate_idx
#else
                                  bit<1> vnic_if
#endif /* P4_DISABLE_FEX */
                                  )
    {
        //meta.dst_port.if_idx =  if_idx;
        meta.dst_port.pcnum = pcnum;
        //meta.ingress.dst_port_grp = dst_port_grp;
        meta.dst_port.block_bc = block_bc;
        meta.dst_port.block_umc = block_umc;
        meta.dst_port.block_uuc = block_uuc;
        //dst_port.cts_override = cts_override;
#ifdef P4_DISABLE_FEX
        meta.dst_port.vnic_if = FALSE;
        meta.dst_if.bd_xlate_idx =              bd_xlate_idx;
        //meta.dst_if.dst_if_label =              dst_if_label;
        meta.dst_if.vlan_mode =                 vlan_mode;
        meta.dst_if.default_vlan =              default_vlan;
        meta.dst_if.untag_default_vlan =        untag_default_vlan;
        meta.dst_if.priority_tag_default_vlan = priority_tag_default_vlan;
#else
        meta.dst_port.vnic_if = vnic_if;
        meta.dst_port.uc_vif_xlate_idx = uc_vif_xlate_idx;
        meta.dst_port.fabric_if_stats_idx = fabric_if_stats_idx;
#endif /* P4_DISABLE_FEX */
    }
    @name("dst_port_state") table dst_port_state {
        actions = {
            set_dst_port_state;
            @default_only NoAction;
        }
        key = {
            meta.dp_eg_header.oport: exact;
        }
        size = DST_PORTMAP_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        dst_port_state.apply();
    }
}

#ifndef P4_DISABLE_FEX
control process_dst_if_state(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_dst_if_state")
        action set_dst_if_state(bit<13> bd_xlate_idx, bit<12> if_label,
                                bit<2> cts_mode, bit<12> default_vlan,
                                bit<1> untag_default_vlan,
                                bit<1> priority_tag_default_vlan,
                                bit<1> same_vtep_prune_en, bit<2> vlan_mode)
    {
        meta.dst_if.bd_xlate_idx = bd_xlate_idx;
        meta.dst_if.if_label = if_label;
        meta.dst_if.cts_mode = cts_mode;
        //meta.dst_if.vlan_xlate_bypass = vlan_xlate_bypass;
        //meta.dst_if.vntag_bypass = vntag_bypass;
        meta.dst_if.default_vlan = default_vlan;
        //meta.dst_if.is_l2_trunk = is_l2_trunk;
        meta.dst_if.untag_default_vlan = untag_default_vlan;
        meta.dst_if.priority_tag_default_vlan = priority_tag_default_vlan;
        //meta.dst_if.default_sgt = default_sgt;
        //meta.dst_if.vlan_xlate_miss_drop = vlan_xlate_miss_drop;
        //meta.dst_if.outer_vlan_xlate_miss_drop = outer_vlan_xlate_miss_drop;
        //meta.dst_if.erspan_term = erspan_term;
        //meta.dst_if.erspan_qtag_use_en = erspan_qtag_use_en;
        //meta.dst_if.vxlan_rewrite_mark = vxlan_rewrite_mark;
        //meta.dst_if.vxlan_clear_mark = vxlan_clear_mark;
        meta.dst_if.same_vtep_prune_en = same_vtep_prune_en;
        //meta.dst_if.sclass_sgt_xlate_miss_drop = sclass_sgt_xlate_miss_drop;
        //meta.dst_if.geneve_rewrite_mark = geneve_rewrite_mark;
        //meta.dst_if.geneve_clear_mark = geneve_clear_mark;
        //meta.dst_if.provider_type = provider_type;
        meta.dst_if.vlan_mode = vlan_mode;
    }
    @name("dst_if_state") table dst_if_state {
        actions = {
            set_dst_if_state;
            @default_only NoAction;
        }
        key = {
            meta.egress.dst_if_idx: exact;
        }
        size = DST_IF_STATE_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        if (meta.ig_eg_header.l2_fwd_mode == L2_FWD_MODE_UC) {
//	if (meta.ig_eg_header.ieth_dst_idx == 0) {
//	    //TODO : is this case real????
//	    meta.egress.dst_if_idx = meta.dst_port.default_vif;
//	} else {
            // TODO maybe_wrong_cast
	    meta.egress.dst_if_idx = (bit<13>) meta.ig_eg_header.ieth_dst_idx;
//	}
        } else {
//	if ((meta.egress.use_met == 1) && (meta.met.head_end_repl == 1)) {
	    meta.egress.dst_if_idx = meta.met.ovector_idx;
//	} else {
	    // Not sure if we need to differentiate between hrep and mcast here
//	    meta.egress.dst_if_idx = meta.dst_port.vnic_mcast_vif;
//	}
        }
        dst_if_state.apply();
    }
}
#endif /* P4_DISABLE_FEX */

control process_service_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_service_rw_info")
        action set_service_rw_info(
//#ifdef ACI_TOR_MODE
                                   bit<48> dmac, bit<1> dmac_rw,
                                   bit<1> smac_rw, bit<14> epg,
                                   bit<1> epg_rw,
                                   //bit<8> sclass,
                                   //bit<8> bd_label,
                                   bit<1> ttl_rw,
                                   bit<1> copy_service,
//#else  /*ACI_TOR_MODE*/
                                   //bit<48> dmac,
                                   //bit<1>  dmac_rw,
                                   //bit<1>  smac_rw,
                                   bit<10> rmac_idx,
                                   bit<3>  qiq_op,
                                   bit<12> vlan,
                                   //bit<1>  ttl_rw,
                                   bit<1>  cos_rw,
                                   bit<3>  cos,
                                   bit<1>  de_rw,
                                   bit<1>  de,
                                   bit<14> bd_label,
                                   bit<3>  padfield,
                                   bit<3>  adj_type,
                                   bit<1>  use_bd_label,
                                   bit<1>  truncation_en
//#endif /*ACI_TOR_MODE*/
                                   )
    {
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.service_rw.dmac = dmac;
            meta.service_rw.dmac_rw = dmac_rw;
            meta.service_rw.smac_rw = smac_rw;
            meta.service_rw.epg = epg;
            meta.service_rw.epg_rw = epg_rw;
            //meta.service_rw.sclass = sclass;
            //meta.service_rw.bd_label = bd_label; // not used in DOLs
            meta.service_rw.ttl_rw = ttl_rw;
            meta.egress.copy_service = copy_service;
//#else  /*ACI_TOR_MODE*/
        } else {
            meta.service_rw.dmac = dmac;
            meta.service_rw.dmac_rw = dmac_rw;
            meta.service_rw.smac_rw = smac_rw;
            meta.service_rw.rmac_idx = rmac_idx;
            meta.service_rw.qiq_op = qiq_op;
            meta.service_rw.vlan = vlan;
            meta.service_rw.ttl_rw = ttl_rw;
            meta.service_rw.cos_rw = cos_rw;
            meta.service_rw.cos = cos;
            meta.service_rw.de_rw = de_rw;
            meta.service_rw.de = de;
            meta.service_rw.bd_label = bd_label;
            // TODO maybe_wrong_cast
            meta.service_rw.padfield = (bit<28>) padfield;
            meta.service_rw.adj_type = adj_type;
            meta.service_rw.use_bd_label = use_bd_label;
            meta.service_rw.truncation_en = truncation_en;
        }
//#endif /*ACI_TOR_MODE*/
    }
    @name("service_rw") table service_rw {
        actions = {
            set_service_rw_info;
            @default_only NoAction;
        }
        key = {
            meta.egress.adj_idx: exact;
        }
        size = SERVICE_RW_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        // Access service rewrite info
        if (meta.egress.adj_vld == 1 &&
            meta.eg_bypass.service_rw_bypass == 0)
        {
            service_rw.apply();
        }
    }
}

control process_ipv4_nat_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_ipv4_nat_rewrite_info")
    action set_ipv4_nat_rewrite_info(bit<1> l3_src_rw, bit<1> l3_dst_rw,
                                     bit<1> l4_src_rw, bit<1> l4_dst_rw,
#ifndef DISABLE_SUBNET_NAT
                                     bit<32> l3_src_addr_mask,
                                     bit<32> l3_dst_addr_mask,
#endif /*DISABLE_SUBNET_NAT*/
                                     bit<32> l3_src_addr, bit<32> l3_dst_addr,
                                     bit<16> l4_src_addr, bit<16> l4_dst_addr)
    {
        meta.eg_l3.ipv4_nat_l3_src_rw = l3_src_rw;
        meta.eg_l3.ipv4_nat_l3_dst_rw = l3_dst_rw;
        meta.eg_l3.ipv4_nat_l3_src_addr = l3_src_addr;
        meta.eg_l3.ipv4_nat_l3_dst_addr = l3_dst_addr;
        meta.eg_l3.nat_l4_src_rw = l4_src_rw;
        meta.eg_l3.nat_l4_dst_rw = l4_dst_rw;
        meta.eg_l3.nat_l4_src_addr = l4_src_addr;
        meta.eg_l3.nat_l4_dst_addr = l4_dst_addr;
#ifndef DISABLE_SUBNET_NAT
	meta.eg_l3.ipv4_nat_l3_src_addr_mask = l3_src_addr_mask;
	meta.eg_l3.ipv4_nat_l3_dst_addr_mask = l3_dst_addr_mask;
#endif /*DISABLE_SUBNET_NAT*/
    }
    @name("ipv4_nat_rewrite_info") table ipv4_nat_rewrite_info {
        actions = {
            set_ipv4_nat_rewrite_info;
            @default_only NoAction;
        }
        key = {
            meta.ig_eg_header.nat_idx: exact;
        }
	size = IPV4_NAT_REWRITE_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        ipv4_nat_rewrite_info.apply();
        if (meta.eg_l3.ipv4_nat_l3_src_rw == 1) {
            hdr.ipv4.srcAddr = meta.eg_l3.ipv4_nat_l3_src_addr;
        }
        if (meta.eg_l3.ipv4_nat_l3_dst_rw == 1) {
            hdr.ipv4.dstAddr = meta.eg_l3.ipv4_nat_l3_dst_addr;
        }
	/*
	if ((meta.ig_eg_header.nat_idx & 0x1) == 1) {
	    ipv4_nat_rewrite1.apply();
	} else {
	    ip`$ip_ver_nat_rewrite0.apply();
	    if ((eg_l3_metadata.nat_l3_src_rw == 1) &&
                (eg_l3_metadata.nat_l3_dst_rw == 1))
            {
		dummy_inc_nat_idx.apply();
		ipv4_nat_rewrite1);
	    }
	}
	*/
    }
}

control process_l4_nat_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.eg_l3.nat_l4_src_rw == 1) {
            if (hdr.tcp.isValid()) {
                hdr.tcp.srcPort = meta.eg_l3.nat_l4_src_addr;
            }
            else {
                hdr.udp.srcPort = meta.eg_l3.nat_l4_src_addr;
            }
        }
        if (meta.eg_l3.nat_l4_dst_rw == 1) {
            if (hdr.tcp.isValid()) {
                hdr.tcp.dstPort = meta.eg_l3.nat_l4_dst_addr;
            }
            else {
                hdr.udp.dstPort = meta.eg_l3.nat_l4_dst_addr;
            }
        }
    }
}

control process_nat_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("process_ipv4_nat_rewrite") process_ipv4_nat_rewrite() process_ipv4_nat_rewrite_0;
    @name("process_l4_nat_rewrite") process_l4_nat_rewrite() process_l4_nat_rewrite_0;
    // NAT rewrite
    apply {
        if (meta.ig_eg_header.nat_idx != 0) {
            // Access rewrite info and rewrite IP header
            if (hdr.ipv4.isValid()) {
                process_ipv4_nat_rewrite_0.apply(hdr, meta, standard_metadata);
#ifndef DISABLE_IPV6_NAT
            } else if (hdr.ipv6.isValid()) {
                // TBD: control block process_ipv6_nat_rewrite was not
                // implemented in the original P4_14 version, either.
                process_ipv6_nat_rewrite_0.apply(hdr, meta, standard_metadata);
#endif /*DISABLE_IPV6_NAT*/
            }
	    // rewrite L4 header
            process_l4_nat_rewrite_0.apply(hdr, meta, standard_metadata);
        }
    }
}

control process_egress_input_qos(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_input_qos_info")
    action set_input_qos_info(bit<3> cos, bit<1> de, bit<6> dscp,
                              bit<4> tc, bit<1> cos_rw,
                              //bit<8> de_rw,
                              bit<1> dscp_rw, bit<1> tc_rw,
                              //bit<8> ol_cos,
                              //bit<8> ol_de,
                              //bit<8> ol_dscp,
                              //bit<8> ol_cos_rw,
                              //bit<8> ol_de_rw,
                              //bit<8> ol_dscp_rw,
                              bit<1> dscp_coi
                              //, bit<8> dscp_cio
                              )
    {
        meta.input_qos_info.cos = cos;
        meta.input_qos_info.de = de;
        meta.input_qos_info.dscp = dscp;
        meta.input_qos_info.tc = tc;
        meta.input_qos_info.cos_rw = cos_rw;
        //meta.input_qos_info.de_rw = de_rw;
        meta.input_qos_info.dscp_rw = dscp_rw;
        meta.input_qos_info.tc_rw = tc_rw;

        //meta.eg_qos.ol_cos = ol_cos;
        //meta.eg_qos.ol_de = ol_de;
        //meta.eg_qos.ol_dscp = ol_dscp;
        //meta.eg_qos.ol_cos_rw = ol_cos_rw;
        //meta.eg_qos.ol_de_rw = ol_de_rw;
        //meta.eg_qos.ol_dscp_rw = ol_dscp_rw;
        meta.input_qos_info.dscp_coi = dscp_coi;
        //meta.eg_qos.dscp_cio = dscp_cio;
    }
    @name("eg_input_qos_info") table eg_input_qos_info {
        actions = {
            set_input_qos_info;
            @default_only NoAction;
        }
        key = {
            //dirmap
            meta.ig_eg_header.qos_map_idx: exact;
        }
        size = EGRESS_QOS_INFO_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        // Get results of ingress qos classification
        eg_input_qos_info.apply();

        // Determine initial dscp/cos/de/tc

        // ~~~~~~ take initial dscp from either original packet, outer
        // header or qos_info ~~~~~~
        // TODO : add bypass condition
        if (meta.input_qos_info.dscp_rw == 1) {
            meta.eg_qos.dscp_rw = TRUE;
            if ((meta.egress.tunnel_decap == 1) &&
                (meta.input_qos_info.dscp_coi == 1))
            {
                // Uniform mode
                meta.eg_qos.dscp = meta.eg_local.outer_dscp;
            } else {
                // From QoS Info
                meta.eg_qos.dscp = meta.input_qos_info.dscp;
            }
        } else {
            // No change
            meta.eg_qos.dscp = meta.l3.lkp_ip_dscp;
        }

        // ~~~~~~ take cos/de from either packet or qos_info ~~~~~~
        if (meta.input_qos_info.cos_rw == 1) {
            meta.eg_qos.cos_rw = TRUE;
            // From QoS Info
            meta.eg_qos.cos = meta.input_qos_info.cos;
            meta.eg_qos.de = meta.input_qos_info.de;
        } else {
            // No change
            // TODO maybe_wrong_cast
            meta.eg_qos.cos = (bit<3>) meta.ig_eg_header.ieth_cos;
            // TODO maybe_wrong_cast
            meta.eg_qos.de = (bit<1>) meta.ig_eg_header.ieth_de;
        }

        // ~~~~~~ take tclass from either ieth or qos_info ~~~~~~
        if (meta.input_qos_info.tc_rw == 1) {
            meta.eg_qos.tc_rw = TRUE;
            meta.eg_qos.tc = meta.input_qos_info.tc;
        } else {
            meta.eg_qos.tc = meta.ig_eg_header.ieth_tclass;
        }

        // Copy qos_map_idx for further use
        meta.eg_qos.qos_map_idx = meta.ig_eg_header.qos_map_idx;
        meta.eg_qos.oqueue = meta.dp_eg_header.oqueue;
    }
}

/*****************************************************************************/
/* Egress : Determine BD and INNER_BD used for further processing            */
/*****************************************************************************/
control process_eg_dst_bd_select(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
#ifdef EXTRA_DEBUG
    table debug_process_eg_dst_bd_select {
        key = {
            meta.egress.epg_or_bd : exact;
            meta.egress.use_met : exact;
            meta.ig_eg_header.dst_epg_or_bd : exact;
            meta.ig_eg_header.ieth_bd : exact;
            meta.ig_eg_header.src_epg_or_bd : exact;
            meta.ig_eg_header.vnid_use_bd : exact;
            meta.met.bd : exact;
            meta.met.epg : exact;
            meta.met.fm_bridge_only : exact;
            meta.met.use_bd : exact;
            meta.met.use_epg_in : exact;
            meta.met.use_in : exact;
//#ifdef ACI_TOR_MODE
            meta.service_rw.epg : exact;
            meta.service_rw.epg_rw : exact;
//#endif /*ACI_TOR_MODE*/
        }
        actions = { NoAction; }
        default_action = NoAction;
    }
#endif /*EXTRA_DEBUG*/
    apply {
#ifdef EXTRA_DEBUG
        debug_process_eg_dst_bd_select.apply();
#endif /*EXTRA_DEBUG*/
        // ~~~~~~ Determine BD, EPG and key for vlan translation ~~~~~~

//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            // First decide if packet is going out on an EPG-vlan or BD-vlan
            if (meta.service_rw.epg_rw == 1) {
                meta.egress.epg_or_bd = meta.service_rw.epg;
                meta.egress.dst_epg = meta.service_rw.epg;
                meta.egress.dst_bd = 0;  // TODO : do we need BD to be valid ??
            } else if (meta.egress.use_met == 1) {
                if (meta.met.use_epg_in == 1) {
                    // ~~~~~~ Multi-Destination ~~~~~~
                    // Use incoming EPG
                    meta.egress.epg_or_bd = meta.ig_eg_header.src_epg_or_bd;
                    meta.egress.dst_epg = meta.ig_eg_header.src_epg_or_bd;
                    meta.egress.dst_bd = meta.ig_eg_header.ieth_bd;
	        //	} else if (meta.met.use_in == 1) {
	        //	    if (meta.ig_eg_header.vnid_use_bd == 0) {
		    //		// is this ever true???
		    //		meta.egress.epg_or_bd = ig_eg_header.src_epg_or_bd;
		    //		meta.egress.dst_epg = ig_eg_header.src_epg_or_bd;
		    //		meta.egress.dst_bd =    ig_eg_header.ieth_bd;
		    //	    } else {
		    //		if (met.use_bd == 1) {
		        //		    meta.egress.epg_or_bd = ig_eg_header.ieth_bd;
		        //		    meta.egress.dst_epg = 0;
		        //		    meta.egress.dst_bd =    ig_eg_header.ieth_bd;
		        //		} else {
		        //		    meta.egress.epg_or_bd = ig_eg_header.src_epg_or_bd;
		        //		    meta.egress.dst_epg = ig_eg_header.src_epg_or_bd;
		        //		    meta.egress.dst_bd =    ig_eg_header.ieth_bd;
		        //		}
		    //	    }
	        //	} else if (ig_eg_header.vnid_use_bd == 0) {
	        //	    // Use EPG
	        //	    meta.egress.epg_or_bd = met.epg;
	        //	    meta.egress.dst_epg =   met.epg;
	        //	    meta.egress.dst_bd =    met.bd;
                } else if (meta.met.use_bd == 1) {
                    // Use BD
                    meta.egress.epg_or_bd = meta.met.bd;
                    meta.egress.dst_epg = 0;
                    meta.egress.dst_bd = meta.met.bd;
                } else {
                    meta.egress.epg_or_bd = meta.met.epg;
                    meta.egress.dst_epg = meta.met.epg;
                    meta.egress.dst_bd = meta.met.bd;
                }
            } else {
                // ~~~~ Unicast ~~~~
                if (meta.ig_eg_header.vnid_use_bd == 1) {
                    meta.egress.epg_or_bd = meta.ig_eg_header.ieth_bd;
                    meta.egress.dst_epg = 0;
                    meta.egress.dst_bd = meta.ig_eg_header.ieth_bd;
                } else {
                    meta.egress.epg_or_bd = meta.ig_eg_header.dst_epg_or_bd;
                    meta.egress.dst_epg = meta.ig_eg_header.dst_epg_or_bd;
                    meta.egress.dst_bd = meta.ig_eg_header.ieth_bd;
                }       
            }
//#else  /*ACI_TOR_MODE*/
        } else {
            if (meta.egress.use_met == 1) {
                if ((meta.met.use_in == 1) || (meta.met.fm_bridge_only == 1)) {
                    meta.egress.epg_or_bd = meta.ig_eg_header.src_epg_or_bd;
                } else {
                    meta.egress.epg_or_bd = meta.met.bd;
                }
            } else {
                meta.egress.epg_or_bd = meta.ig_eg_header.ieth_bd;
            }
        }
//#endif /*ACI_TOR_MODE*/
        
        // ~~~~~~ outer bd ~~~~~~
        if (meta.egress.tunnel_encap == 1) {
	// ~~~~~~ copy bd/epg to inner ~~~~~~
	//	modify_field(egress.inner_dst_bd, egress.dst_bd);
	//	modify_field(egress.inner_dst_epg, egress.dst_epg);
            meta.egress.inner_epg_or_bd = meta.egress.epg_or_bd;
        } else {
            // ~~~~~~ copy bd to outer ~~~~~~
            meta.egress.outer_dst_bd = meta.egress.epg_or_bd;
        }
    }
}

/*****************************************************************************/
/* Forwarding mode update after MET lookup */
/*****************************************************************************/

control process_egress_fwd_mode(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // Forwarding mode update
        meta.egress.l2_fwd_mode = meta.ig_eg_header.l2_fwd_mode;
        
        if (meta.dp_eg_header.met_v == 1) {
            if (meta.met.force_route == 1) {
                meta.egress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
            } else if ((meta.met.force_bridge == 1) ||
                       (meta.met.fm_bridge_only == 1))
            {
                meta.egress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
            } else if (meta.egress.dst_bd == meta.ig_eg_header.ieth_bd) {
                meta.egress.l3_fwd_mode = L3_FWD_MODE_BRIDGE;
            } else {
                meta.egress.l3_fwd_mode = L3_FWD_MODE_ROUTE;
            }
        } else {
            meta.egress.l3_fwd_mode = meta.ig_eg_header.l3_fwd_mode;
        }
    }
}

control process_same_bd_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
	// Same EPG check
	if (meta.egress.dst_epg == meta.ig_eg_header.src_epg_or_bd) {
	    meta.egress.same_epg = TRUE;
	} else {
	    meta.egress.same_epg = FALSE;
	}

	// Same BD Check
	if (meta.egress.l2_fwd_mode == L2_FWD_MODE_UC) {
	    // src_bd is not available so relying on opcode
	    if (meta.egress.l3_fwd_mode == L3_FWD_MODE_BRIDGE) {
		meta.egress.same_bd = TRUE;
	    } else {
		meta.egress.same_bd = FALSE;
	    }
	} else {
	    if (meta.egress.dst_bd == meta.ig_eg_header.ieth_bd) {
		meta.egress.same_bd = TRUE;
	    } else {
		meta.egress.same_bd = FALSE;
	    }
	}
    }
}

//#ifdef ACI_TOR_MODE

control process_epg_crossing_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if ((meta.dp_eg_header.met_v == 1) &&
            (meta.met.epg_cross_drop == 1) &&
            (meta.ig_eg_header.block_epg_crossing == 1) &&
            (meta.dst_bd.sclass != meta.ig_eg_header.src_class))
        {
            meta.eg_drop.epg_cross = TRUE;
        }
    }
}

//#endif /*ACI_TOR_MODE*/

control process_egress_copp(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // No support for logging or sup copy/redirect
    @name(".egress_copp_deny") action egress_copp_deny(bit<12> hit_idx) {
        meta.eg_drop.acl_deny = 1;
        meta.eg_acl.copp_hit = 1;
        meta.eg_acl.copp_hit_idx = hit_idx;
    }
    @name(".egress_copp_permit") action egress_copp_permit(bit<12> hit_idx) {
        meta.eg_acl.copp_hit = 1;
        meta.eg_acl.copp_hit_idx = hit_idx;
    }
    @name("egress_ipv4_copp") table egress_ipv4_copp {
        actions = {
            egress_copp_deny;
            egress_copp_permit;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            EG_CMN_ACL_KEY
            EG_IPV4_FLOW_KEY
        }
        size = EGRESS_IPV4_COPP_TABLE_SIZE;
        default_action = NoAction();
        @name("egress_ipv4_copp_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    @name("egress_ipv6_copp") table egress_ipv6_copp {
        actions = {
            egress_copp_deny;
            egress_copp_permit;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            EG_CMN_ACL_KEY
            EG_IPV6_FLOW_KEY
        }
        size = EGRESS_IPV6_COPP_TABLE_SIZE;
        default_action = NoAction();
        @name("egress_ipv6_copp_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    @name("egress_mac_copp") table egress_mac_copp {
        actions = {
            egress_copp_deny;
            egress_copp_permit;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            EG_CMN_ACL_KEY
            EG_MAC_FLOW_KEY
        }
        size = EGRESS_MAC_COPP_TABLE_SIZE;
        default_action = NoAction();
        @name("egress_mac_copp_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    apply {
        if (meta.eg_bypass.acl_bypass == 0) {
            if (meta.l3.l3_type == L3TYPE_IPV4) {
                egress_ipv4_copp.apply();
            }
            else if (meta.l3.l3_type == L3TYPE_IPV6) {
                egress_ipv6_copp.apply();
            } else {
                egress_mac_copp.apply();
            }
        }
    }
}

/*---------------------------------------------------------------------------*/
/* COPP stats                                                                */
/*---------------------------------------------------------------------------*/
//counter egress_copp_stats {
//    type : packets_and_bytes;
//    instance_count : EGRESS_COPP_STATS_TABLE_SIZE;
//}
//
//action egress_copp_stats_update() {
//    count(egress_copp_stats, eg_acl_metadata.copp_hit_idx);
//}
//
//table egress_copp_stats {
//    reads {
//        eg_acl_metadata.copp_hit_idx : exact;
//    }
//    actions {
//        egress_copp_stats_update;
//    }
//    size = EGRESS_COPP_STATS_TABLE_SIZE;
//}
//
//control process_egress_copp_stats {
//    #ifndef STATS_DISABLE
//    apply(egress_copp_stats);
//    #endif /* STATS_DISABLE */
//}


control process_egress_qos_tcam(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("qos_meter") meter(256, MeterType.bytes) qos_meter;
    @name(".set_output_qos_info")
    action set_output_qos_info(bit<3> cos, bit<1> de, bit<6> dscp,
                               bit<4> tc, bit<1> cos_rw,
                               //bit<8> de_rw,
                               bit<1> dscp_rw, bit<1> tc_rw, bit<3> ol_cos,
                               bit<1> ol_de, bit<6> ol_dscp, bit<1> ol_cos_rw,
                               //bit<8> ol_de_rw,
                               bit<1> ol_dscp_rw,
                               //bit<8> dscp_coi,
                               bit<1> dscp_cio, bit<3> oqueue)
    {
        meta.eg_qos.oqueue = oqueue;
        meta.eg_qos.cos = cos;
        meta.eg_qos.de = de;
        meta.eg_qos.dscp = dscp;
        meta.eg_qos.tc = tc;
        meta.eg_qos.cos_rw = cos_rw;
        //meta.eq_qos.de_rw = de_rw;
        meta.eg_qos.dscp_rw = dscp_rw;
        meta.eg_qos.tc_rw = tc_rw;

        meta.eg_qos.ol_cos = ol_cos;
        meta.eg_qos.ol_de = ol_de;
        meta.eg_qos.ol_dscp = ol_dscp;
        meta.eg_qos.ol_cos_rw = ol_cos_rw;
        //meta.eq_qos.ol_de_rw = ol_de_rw;
        meta.eg_qos.ol_dscp_rw = ol_dscp_rw;
        //meta.eq_qos.dscp_coi = dscp_coi;
        meta.eg_qos.dscp_cio = dscp_cio;
    }
    @name(".eg_qos_drop") action eg_qos_drop(bit<1> drop) {
        meta.eg_drop.qos_drop = drop;
    }
    @name(".eg_qos_mark") action eg_qos_mark(//bit<8> qos_map_vld,
                                             bit<11> qos_map_idx)
    {
        meta.eg_qos.qos_map_idx = qos_map_idx;
    }
    @name(".eg_qos_drop_meter")
    action eg_qos_drop_meter(bit<8> policer_select) {
        qos_meter.execute_meter((bit<32>) policer_select,
                                meta.eg_drop.qos_policer_drop);
    }
    @name("eg_output_qos_info") table eg_output_qos_info {
        actions = {
            set_output_qos_info;
            @default_only NoAction;
        }
        key = {
	    //dirmap
            meta.eg_qos.qos_map_idx: exact;
        }
        size = EGRESS_QOS_INFO_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("egress_ipv4_qos") table egress_ipv4_qos {
        actions = {
            eg_qos_drop;
            eg_qos_mark;
            eg_qos_drop_meter;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            EG_CMN_ACL_KEY

            meta.eg_qos.cos             : ternary;
            meta.eg_qos.de              : ternary;
            meta.eg_qos.dscp            : ternary;
            
            // CoPP
            meta.ig_eg_header.sup_qnum           : ternary;

            // Span
            EG_IPV4_FLOW_KEY
        }
        size = EGRESS_IPV4_QOS_TABLE_SIZE;
        default_action = NoAction();
        @name("egress_ipv4_qos_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    @name("egress_ipv6_qos") table egress_ipv6_qos {
        actions = {
            eg_qos_drop;
            eg_qos_mark;
            eg_qos_drop_meter;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            EG_CMN_ACL_KEY

            meta.eg_qos.cos             : ternary;
            meta.eg_qos.de              : ternary;
            meta.eg_qos.dscp            : ternary;

            // CoPP
            meta.ig_eg_header.sup_qnum           : ternary;

            // Span
            EG_IPV6_FLOW_KEY
        }
        size = EGRESS_IPV6_QOS_TABLE_SIZE;
        default_action = NoAction();
        @name("egress_ipv6_qos_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    @name("egress_mac_qos") table egress_mac_qos {
        actions = {
            eg_qos_drop;
            eg_qos_mark;
            eg_qos_drop_meter;
            @default_only NoAction;
        }
        key = {
            // Common Key Fields
            EG_CMN_ACL_KEY

            meta.eg_qos.cos             : ternary;
            meta.eg_qos.de              : ternary;
            meta.eg_qos.dscp            : ternary;

            // CoPP
            meta.ig_eg_header.sup_qnum           : ternary;

            // Span
            EG_MAC_FLOW_KEY
        }
        size = EGRESS_MAC_QOS_TABLE_SIZE;
        default_action = NoAction();
        @name("egress_mac_qos_stats")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    apply {
        if (meta.l3.l3_type == L3TYPE_IPV4) {
            egress_ipv4_qos.apply();
        } else if (meta.l3.l3_type == L3TYPE_IPV6) {
            egress_ipv6_qos.apply();
        } else {
            egress_mac_qos.apply();
        }
	//if (meta.eg_qos_acl.qos_map_vld == 1) {
            eg_output_qos_info.apply();
        //}
    }
}

control process_sgt_derivation(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_sgt_from_sclass") action set_sgt_from_sclass(bit<16> sgt) {
        meta.rewrite.sgt = sgt;
    }
    @name("sclass_to_sgt_xlate_hash_tbl") table sclass_to_sgt_xlate_hash_tbl {
        actions = {
            set_sgt_from_sclass;
            @default_only NoAction;
        }
        key = {
            meta.dst_if.cts_mode: exact;
            meta.dst_bd.scope   : exact;
            meta.ig_eg_header.src_class  : exact;
        }
    	size = SCLASS_TO_SGT_XLATE_HASH_TBL_SIZE;
        // overflow TCAM size = SCLASS_TO_SGT_XLATE_OF_TCAM_SIZE
        default_action = NoAction();
    }
    apply {
        // SCLASS -> SGT translation
        if (!sclass_to_sgt_xlate_hash_tbl.apply().hit) {
            meta.eg_drop.sclass_sgt_xlate_miss = TRUE;
        }
    }
}


/*****************************************************************************/
/* CMD */
/*****************************************************************************/

// if cts_not_enabled_on_bd
// -- remove
// else if cts_override_set_on_port
// -- override from port
// else if encap
// -- take from encap_info
// else
// -- take from port

// remove on tunnel encap -- TODO : not sure why RW did this

control process_cmd_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.eg_bypass.cmd_bypass == 0) {
            // Note: DGT rewrite is not supported. It's assumend that
            // DGT is never carried in the packet
            
            // Decide if removal/insertion is needed
            if (meta.dst_bd.cts_en == 0) {
                meta.rewrite.cts_mode = CMD_RW_MODE_REMOVE;
            // TODO : do we really need this  
            //} else if (meta.dst_port.cts_override == 1) {
            } else if (meta.egress.tunnel_encap == 1) {
                meta.rewrite.cts_mode = meta.eg_tunnel.cts_mode;
            } else {
                meta.rewrite.cts_mode = meta.dst_if.cts_mode;
            }
            
            // CMD header removal/insertion. No rewrites
            if (meta.rewrite.cts_mode == CMD_RW_MODE_REMOVE) {
                if (hdr.cmd.isValid()) {
                    
                    // Copy ethertype from SGT header to prev tag
                    if (hdr.qtag1.isValid()) {
                        hdr.qtag1.etherType = hdr.cmd_sgt.etherType;
                    } else if (hdr.qtag0.isValid()) {
                        hdr.qtag0.etherType = hdr.cmd_sgt.etherType;
                    } else if (hdr.vntag.isValid()) {
                        hdr.vntag.etherType = hdr.cmd_sgt.etherType;
                    } else {
                        hdr.ethernet.etherType = hdr.cmd_sgt.etherType;
                    }
                    
                    // remove headers
                    hdr.cmd.setInvalid();
                    hdr.cmd_sgt.setInvalid();
                    meta.egress.pkt_len = meta.egress.pkt_len - 8;
                    
                    // adjust length
                    meta.rewrite.encap_ip_len = meta.rewrite.encap_ip_len - 8;
                }
            } else if (meta.rewrite.cts_mode == CMD_RW_MODE_INSERT) {
                if (hdr.cmd.isValid()) {
                    // if header exists, nop
                } else {
                    
                    // add cmd-sgt
                    hdr.cmd.setValid();
                    hdr.cmd_sgt.setValid();
                    meta.egress.pkt_len = meta.egress.pkt_len + 8;
                    
                    // fix ethertype
                    if (hdr.qtag1.isValid()) {
                        hdr.cmd_sgt.etherType = hdr.qtag1.etherType;
                        hdr.qtag1.etherType = ETHERTYPE_CMD;
                    } else if (hdr.qtag0.isValid()) {
                        hdr.cmd_sgt.etherType = hdr.qtag0.etherType;
                        hdr.qtag0.etherType = ETHERTYPE_CMD;
                    } else if (hdr.vntag.isValid()) {
                        hdr.cmd_sgt.etherType = hdr.vntag.etherType;
                        hdr.vntag.etherType = ETHERTYPE_CMD;
                    } else {
                        hdr.cmd_sgt.etherType = hdr.ethernet.etherType;
                        hdr.ethernet.etherType = ETHERTYPE_CMD;
                    }
                    
                    // rewrite header fields
                    hdr.cmd.version = 0x1;
                    hdr.cmd.length_cmd = 0x1;
                    hdr.cmd_sgt.length_sgt = 0x0;
                    hdr.cmd_sgt.optiontype_sgt = 0x1;
                    hdr.cmd_sgt.sgt = meta.rewrite.sgt;
                    
                    // adjust length
                    meta.rewrite.encap_ip_len = meta.rewrite.encap_ip_len + 8;
                }
            }
        }
    }
}


// TBDP416 - There are not one, not 2, but 3 (!) control blocks called
// process_mac_rewrite in the original P4_14 code.  Only the one in
// original P4_14 sug.p4 code file sug_eg_l3.p4 was actually
// #include'd in sug_top.p4.  The other two files were not #include'd
// by any others, so were probably there being developed for possible
// future use.

// File names where the original P4_14 versions are:
// sug_eg_l3.p4 (the one below)
// sug_ig_rewrite.p4
// sug_eg_rewrite.p4

control process_mac_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_smac") action set_smac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("smac_rewrite") table smac_rewrite {
        actions = {
            set_smac;
            @default_only NoAction;
        }
        key = {
            meta.dst_bd.rmac_index: exact;
        }
        size = SMAC_REWRITE_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        if (
#ifdef DISABLE_MPLS
            (meta.eg_bypass.l2_rw_bypass == 0) &&
            ((meta.egress.l3_fwd_mode == L3_FWD_MODE_ROUTE) ||
             (meta.service_rw.smac_rw == 1))
#else
            (meta.eg_bypass.l2_rw_bypass == 0) &&
            ((meta.egress.l3_fwd_mode == L3_FWD_MODE_MPLS) ||
             (meta.egress.l3_fwd_mode == L3_FWD_MODE_ROUTE))
#endif
            )
        {
            smac_rewrite.apply();

            //DMAC
            if (meta.service_rw.dmac_rw == 1) {
                hdr.ethernet.dstAddr = meta.service_rw.dmac;
            } else if ((meta.egress.l2_fwd_mode == L2_FWD_MODE_UC) ||
                       (meta.egress.l2_fwd_mode == L2_FWD_MODE_FLOOD))
            {
                hdr.ethernet.dstAddr = meta.ig_eg_header.dmac;
            } else if (meta.egress.l2_fwd_mode == L2_FWD_MODE_MC) {
                if (hdr.ipv4.isValid()) {
                    hdr.ethernet.dstAddr[47:23] = 0x01005E000000 >> 23;
                    hdr.ethernet.dstAddr[22:0] = hdr.ipv4.dstAddr[22:0];
                } else {
                    hdr.ethernet.dstAddr[47:23] = 0x333300000000 >> 23;
                    hdr.ethernet.dstAddr[31:0] = hdr.ipv6.dstAddr[31:0];
                }
            }
        }
    }
}

// ****************************
// rewrite qos fields of exposed header
// ****************************

control process_qos_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.eg_bypass.qos_rw_bypass == 0) {
            // DSCP
            if (meta.eg_qos.dscp_rw == 1) {
                if (hdr.ipv4.isValid()) {
                    hdr.ipv4.dscp = meta.eg_qos.dscp;
                } else {
                    hdr.ipv6.dscp = meta.eg_qos.dscp;
                }   
            }
            
            // COS/DE
            if (meta.eg_qos.cos_rw == 1) {
                if (hdr.qtag0.isValid()) {
                    hdr.qtag0.pcp = meta.eg_qos.cos;
                    hdr.qtag0.cfi = meta.eg_qos.de;
                }
                
                if (hdr.qtag1.isValid()) {
                    hdr.qtag1.pcp = meta.eg_qos.cos;
                    hdr.qtag1.cfi = meta.eg_qos.de;
                }
            }
            
            // TC
            if (meta.eg_qos.tc_rw == 1) {
                hdr.ieth.tclass = meta.eg_qos.tc;
            }
        }
        
//        // Store Inner DSCP for later use
//        if (hdr.ipv4.isValid()) {
//            meta.eg_qos.inner_dscp = hdr.ipv4.dscp;
//        } else if (hdr.ipv6.isValid()) {
//            meta.eg_qos.inner_dscp = hdr.ipv6.dscp;
//        } else {
//        }
    }
}

// chosen ttl
//  -- no tunnel - outermost ttl
//  -- tunnel encap - outermost ttl
//  -- tunnel decap - 
// inner ttl
// -- no tunnel - chosen ttl
// -- tunnel encap - if route, chosen ttl -1 else chosen ttl
// outer ttl
// -- no tunnel - if route, chosen ttl-1 else chosen ttl; if 0, drop; if chosen_ttl=0 drop;
// -- tunnel encap - if pipe , CFG else if route, chosen ttl-1 else chosen ttl; if 0, drop; if chosen_ttl=0 drop;

/*****************************************************************************/
/* TTL rewrite */
/*****************************************************************************/

control process_ttl_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // ~~~~~~~~ chosen ttl ~~~~~~~~
        
        // Tunnel decap
        if ((meta.egress.tunnel_decap == 1) &&
            // Uniform mode OR
            (((meta.ig_eg_header.ttl_coi == 1) &&
              (meta.eg_local.outer_src_ttl < meta.l3.lkp_ip_ttl)) ||
             // inner is non-IP
             (!(hdr.ipv4.isValid() || hdr.ipv6.isValid()))))
        {
            meta.eg_local.chosen_ttl = meta.eg_local.outer_src_ttl;
        } else {
            meta.eg_local.chosen_ttl = meta.l3.lkp_ip_ttl;
        }
        
        // ~~~~~~~ Decrement TTL if packet was routed ~~~~~~~~~
        if ((meta.egress.l3_fwd_mode == L3_FWD_MODE_ROUTE) &&
            (meta.eg_bypass.ttl_dec_bypass == 0))
        {
            // Drecrement TTL
            if (meta.eg_local.chosen_ttl != 0) {
                meta.eg_local.final_ttl = meta.eg_local.chosen_ttl - 1;
            }
            // If outgoing TTL is zero, drop the packet
            if (meta.eg_local.chosen_ttl == 1) {
                meta.eg_drop.ttl_expired = TRUE;
            }
            // Rewrite TTL value
            if (hdr.ipv4.isValid()) {
                hdr.ipv4.ttl = meta.eg_local.final_ttl;
            }
            if (hdr.ipv6.isValid()) {
                hdr.ipv6.hopLimit = meta.eg_local.final_ttl;
            }
        }
    }
}

control process_erspan_fields(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    register<bit<32>>(SPAN_SESSION_TABLE_SIZE) erspan_seq_num;
    apply {
        // VLAN fields
        if (meta.eg_local.span_dir == 1) {
            meta.eg_local.erspan_vlan = meta.eg_local.dst_qtag0_vid;
            meta.eg_local.erspan_cos = meta.eg_local.dst_qtag0_pcp;
            if (meta.eg_local.dst_qtag0_vld == 1) {
                meta.eg_local.erspan_en = 2;
            } else {
                meta.eg_local.erspan_en = 0;
            }
        } else {
            meta.eg_local.erspan_vlan = meta.eg_local.dst_qtag0_vid;
            meta.eg_local.erspan_cos = meta.eg_local.dst_qtag0_pcp;
            if (meta.eg_local.src_qtag0_vld == 1) {
                meta.eg_local.erspan_en = 2;
            } else {
                meta.eg_local.erspan_en = 0;
            }
        }
        
        // idx
        if (meta.eg_local.span_dir == 1) {
            // TODO maybe_wrong_cast
            meta.eg_local.erspan_idx = (bit<20>) meta.dp_eg_header.oport;
        } else {
            // TODO maybe_wrong_cast
            meta.eg_local.erspan_idx =
                (bit<20>) meta.ig_eg_header.ieth_src_port;
        }
        
        // sequence number
        erspan_seq_num.read(meta.eg_local.erspan_seq_num,
                            (bit<32>) meta.eg_local.erspan_ses);
    }
}


/*****************************************************************************/
/* Egress : Inner BD properties                                              */
/*****************************************************************************/
/*
action set_egress_inner_bd_state(smac_idx)
{
    modify_field(egress_metadata.smac_idx, smac_idx);
}

table egress_inner_bd_state {
    reads {
	egress_metadata.inner_dst_bd : exact;
    }

    actions {
	set_egress_inner_bd_state;
    }
    size = INNER_DST_BD_STATE_TABLE_SIZE;
}
*/

/*****************************************************************************/
/* Egress : Inner_BD -> VNID/Inner_VLAN translation                          */
/*****************************************************************************/

// action set_egress_inner_encap_vlan(encap_vlan) {
//   modify_field(egress_metadata.encap_vlan, encap_vlan);
// }

control process_egress_vnid_xlate(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".dst_vnid_xlate_miss") action dst_vnid_xlate_miss() {
        meta.eg_drop.vnid_xlate_miss = TRUE;
    }
    @name(".set_egress_vnid") action set_egress_vnid(bit<24> vnid) {
        meta.eg_tunnel.dst_vnid = vnid;
        meta.eg_drop.vnid_xlate_miss = FALSE;
    }
    @name("dst_vnid_xlate_hash_table") table dst_vnid_xlate_hash_table {
        actions = {
            dst_vnid_xlate_miss;
            set_egress_vnid;
            @default_only NoAction;
        }
        key = {
            meta.eg_tunnel.inner_dst_bd_xlate_idx: exact;
            meta.egress.inner_epg_or_bd          : exact;
        }
        size = DST_VNID_XLATE_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        dst_vnid_xlate_hash_table.apply();
    }
}

control process_outer_ttl_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.eg_tunnel.ttl_cio == 0) {
            // Pipe Mode
            meta.eg_local.outer_dst_ttl = 64;
        } else {
            // Drecrement TTL
            if (meta.eg_local.chosen_ttl != 0) {
                meta.eg_local.outer_dst_ttl = meta.eg_local.chosen_ttl - 1;
            }
            // If outgoing TTL is zero, drop the packet
            if (meta.eg_local.chosen_ttl == 1) {
                meta.eg_drop.ttl_expired = TRUE;
            }
            // Rewrite TTL value
            if (hdr.ipv4.isValid()) {
                hdr.ipv4.ttl = meta.eg_local.outer_dst_ttl;
            }
            if (hdr.ipv6.isValid()) {
                hdr.ipv6.hopLimit = meta.eg_local.outer_dst_ttl;
            }
        }
    }
}


///***************************************************************************/
///* Tunnel encap decision                                                   */
///***************************************************************************/
//control process_tunnel_encap_decision {
//
//    // ~~~~~~ Decide if tunnel encap is required 
//    if ((egress_metadata.use_encap==1) and (eg_bypass_metadata.tunnel_encap_bypass==0)) {
//        // dipo_ptr, sipo_ptr, encap type and other per-tunnel info
//        apply(encap_rewrite);
//
//	if (eg_tunnel_metadata.dst_encap_type != ENCAP_TYPE_NONE ) {
//	    modify_field(egress_metadata.tunnel_encap, TRUE);
//	}
//    } else {
//	modify_field(egress_metadata.tunnel_encap, FALSE);
//    }
//}
//
/*****************************************************************************/
/* Tunnel encap rewrite                                                      */
/*****************************************************************************/

#ifndef DISABLE_MPLS

/*****************************************************************************/
/* LSR Label operations                                             */
/*****************************************************************************/

control process_mpls_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    mpls_t tmp_mpls_headers0; // Outermost header
    mpls_t tmp_mpls_headers1;
    mpls_t tmp_mpls_headers2;
    mpls_t tmp_mpls_headers3;

// TTL
action label_rw_pipe_ttl() {
// TODO    tmp_mpls_headers0.ttl = MPLS_INITIAL_TTL-1;
    tmp_mpls_headers0.ttl = 63;
    tmp_mpls_headers1.ttl = MPLS_INITIAL_TTL;
    tmp_mpls_headers2.ttl = MPLS_INITIAL_TTL;
    tmp_mpls_headers3.ttl = MPLS_INITIAL_TTL;
}

action label_rw_uniform_ttl() {
    tmp_mpls_headers0.ttl = meta.l3.exposed_ttl;
    tmp_mpls_headers1.ttl = meta.l3.exposed_ttl;
    tmp_mpls_headers2.ttl = meta.l3.exposed_ttl;
    tmp_mpls_headers3.ttl = meta.l3.exposed_ttl;
}

table mpls_ttl_rw {
    key = {
	meta.mplsm.label_op : exact;
	meta.mplsm.ttl_mode : exact;
    }
    actions = {
	label_rw_pipe_ttl;
	label_rw_uniform_ttl;
        @default_only NoAction;
    }
    default_action = NoAction;
    size = 16;
}

// QOS : TODO

// Label value
 
    action label_rw_lable_val(bit<20> lbl0, bit<20> lbl1,
                              bit<20> lbl2, bit<20> lbl3)
    {
        tmp_mpls_headers0.label = lbl0;
        tmp_mpls_headers1.label = lbl1;
        tmp_mpls_headers2.label = lbl2;
        tmp_mpls_headers3.label = lbl3;
    }

table mpls_label_rw {
    key = {
	meta.ig_eg_header.encap_idx : exact;
    }
    actions = {
	label_rw_lable_val;
        @default_only NoAction;
    }
    default_action = NoAction;
//    size = MPLS_REWRITE_TABLE_SiZE;
}

// Label Push operation
action mpls_label_push1 () {
    hdr.mpls.push_front(1);
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
}

action mpls_label_push2 () {
    hdr.mpls.push_front(2);
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
    hdr.mpls[1].label = tmp_mpls_headers1.label;
    hdr.mpls[1].exp   = tmp_mpls_headers1.exp  ;
    hdr.mpls[1].bos   = tmp_mpls_headers1.bos  ;
    hdr.mpls[1].ttl   = tmp_mpls_headers1.ttl  ;
}

action mpls_label_push3 () {
    hdr.mpls.push_front(3);
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
    hdr.mpls[1].label = tmp_mpls_headers1.label;
    hdr.mpls[1].exp   = tmp_mpls_headers1.exp  ;
    hdr.mpls[1].bos   = tmp_mpls_headers1.bos  ;
    hdr.mpls[1].ttl   = tmp_mpls_headers1.ttl  ;
    hdr.mpls[2].label = tmp_mpls_headers2.label;
    hdr.mpls[2].exp   = tmp_mpls_headers2.exp  ;
    hdr.mpls[2].bos   = tmp_mpls_headers2.bos  ;
    hdr.mpls[2].ttl   = tmp_mpls_headers2.ttl  ;
}

action mpls_label_push4 () {
    hdr.mpls.push_front(4);
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
    hdr.mpls[1].label = tmp_mpls_headers1.label;
    hdr.mpls[1].exp   = tmp_mpls_headers1.exp  ;
    hdr.mpls[1].bos   = tmp_mpls_headers1.bos  ;
    hdr.mpls[1].ttl   = tmp_mpls_headers1.ttl  ;
    hdr.mpls[2].label = tmp_mpls_headers2.label;
    hdr.mpls[2].exp   = tmp_mpls_headers2.exp  ;
    hdr.mpls[2].bos   = tmp_mpls_headers2.bos  ;
    hdr.mpls[2].ttl   = tmp_mpls_headers2.ttl  ;
    hdr.mpls[3].label = tmp_mpls_headers3.label;
    hdr.mpls[3].exp   = tmp_mpls_headers3.exp  ;
    hdr.mpls[3].bos   = tmp_mpls_headers3.bos  ;
    hdr.mpls[3].ttl   = tmp_mpls_headers3.ttl  ;
}

// Label Pop operation
action mpls_label_pop1 () {
    hdr.mpls.pop_front(1);
}

action mpls_label_pop2 () {
    hdr.mpls.pop_front(2);
}

action mpls_label_pop3 () {
    hdr.mpls.pop_front(3);
}

action mpls_label_pop4 () {
    hdr.mpls.pop_front(4);
}

// Label Swap + [Push] operation
action mpls_label_swap () {
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
//    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
}

#ifndef DISABLE_MPLS_REWRITE
action mpls_label_swap_push1 () {
    hdr.mpls.push_front(1);
    hdr.mpls[0].label = tmp_mpls_headers1.label;
    hdr.mpls[0].exp   = tmp_mpls_headers1.exp  ;
//    hdr.mpls[0].bos   = tmp_mpls_headers1.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers1.ttl  ;
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
}

action mpls_label_swap_push2 () {
    hdr.mpls.push_front(2);
    hdr.mpls[0].label = tmp_mpls_headers2.label;
    hdr.mpls[0].exp   = tmp_mpls_headers2.exp  ;
//    hdr.mpls[0].bos   = tmp_mpls_headers2.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers2.ttl  ;
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
    hdr.mpls[1].label = tmp_mpls_headers1.label;
    hdr.mpls[1].exp   = tmp_mpls_headers1.exp  ;
    hdr.mpls[1].bos   = tmp_mpls_headers1.bos  ;
    hdr.mpls[1].ttl   = tmp_mpls_headers1.ttl  ;
}

action mpls_label_swap_push3 () {
    hdr.mpls.push_front(3);
    hdr.mpls[0].label = tmp_mpls_headers3.label;
    hdr.mpls[0].exp   = tmp_mpls_headers3.exp  ;
//    hdr.mpls[0].bos   = tmp_mpls_headers3.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers3.ttl  ;
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
    hdr.mpls[0].label = tmp_mpls_headers1.label;
    hdr.mpls[0].exp   = tmp_mpls_headers1.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers1.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers1.ttl  ;
    hdr.mpls[0].label = tmp_mpls_headers2.label;
    hdr.mpls[0].exp   = tmp_mpls_headers2.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers2.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers2.ttl  ;
}
#endif

// IP->MPLS Label Push operation
action ip_to_mpls_label_push1 () {
    hdr.mpls.push_front(1);
    hdr.ethernet.etherType = ETHERTYPE_MPLS;
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = 1  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
}

action ip_to_mpls_label_push2 () {
    hdr.mpls.push_front(2);
    hdr.ethernet.etherType = ETHERTYPE_MPLS;
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[1].label = tmp_mpls_headers1.label;
    hdr.mpls[1].exp   = tmp_mpls_headers1.exp  ;
    hdr.mpls[1].bos   = 1  ;
    hdr.mpls[1].ttl   = tmp_mpls_headers1.ttl  ;
}

action ip_to_mpls_label_push3 () {
    hdr.mpls.push_front(3);
    hdr.ethernet.etherType = ETHERTYPE_MPLS;
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
    hdr.mpls[1].label = tmp_mpls_headers1.label;
    hdr.mpls[1].exp   = tmp_mpls_headers1.exp  ;
    hdr.mpls[1].bos   = tmp_mpls_headers1.bos  ;
    hdr.mpls[1].ttl   = tmp_mpls_headers1.ttl  ;
    hdr.mpls[2].label = tmp_mpls_headers2.label;
    hdr.mpls[2].exp   = tmp_mpls_headers2.exp  ;
    hdr.mpls[2].bos   = 1  ;
    hdr.mpls[2].ttl   = tmp_mpls_headers2.ttl  ;
}

action ip_to_mpls_label_push4 () {
    hdr.mpls.push_front(4);
    hdr.ethernet.etherType = ETHERTYPE_MPLS;
    hdr.mpls[0].label = tmp_mpls_headers0.label;
    hdr.mpls[0].exp   = tmp_mpls_headers0.exp  ;
    hdr.mpls[0].bos   = tmp_mpls_headers0.bos  ;
    hdr.mpls[0].ttl   = tmp_mpls_headers0.ttl  ;
    hdr.mpls[1].label = tmp_mpls_headers1.label;
    hdr.mpls[1].exp   = tmp_mpls_headers1.exp  ;
    hdr.mpls[1].bos   = tmp_mpls_headers1.bos  ;
    hdr.mpls[1].ttl   = tmp_mpls_headers1.ttl  ;
    hdr.mpls[2].label = tmp_mpls_headers2.label;
    hdr.mpls[2].exp   = tmp_mpls_headers2.exp  ;
    hdr.mpls[2].bos   = tmp_mpls_headers2.bos  ;
    hdr.mpls[2].ttl   = tmp_mpls_headers2.ttl  ;
    hdr.mpls[3].label = tmp_mpls_headers3.label;
    hdr.mpls[3].exp   = tmp_mpls_headers3.exp  ;
    hdr.mpls[3].bos   = 1  ;
    hdr.mpls[3].ttl   = tmp_mpls_headers3.ttl  ;
}


// Label operations
table mpls_label_op {
    key = {
	meta.mplsm.label_op : exact;
	hdr.mpls[0].isValid() : exact;
    }
    actions = {
	mpls_label_push1;
	mpls_label_push2;
	mpls_label_push3;
	mpls_label_push4;
	mpls_label_pop1;
	mpls_label_pop2;
	mpls_label_pop3;
	mpls_label_pop4;
	mpls_label_swap;
#ifndef DISABLE_MPLS_REWRITE
	mpls_label_swap_push1;
	mpls_label_swap_push2;
	mpls_label_swap_push3;
#endif
	ip_to_mpls_label_push1;
	ip_to_mpls_label_push2;
	ip_to_mpls_label_push3;
	ip_to_mpls_label_push4;
        @default_only NoAction;
    }
    default_action = NoAction;
    size = 16;
}

    apply {
        mpls_ttl_rw.apply();
        mpls_label_rw.apply();
        mpls_label_op.apply();
    }
}
#endif /*DISABLE_MPLS*/

control process_tunnel_encap_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".f_insert_vxlan") action f_insert_vxlan() {
        hdr.udp.setValid();
        hdr.vxlan.setValid();

        hdr.udp.srcPort = meta.ig_eg_header.ol_udp_sp;
        hdr.udp.dstPort = UDP_PORT_VXLAN;
        hdr.udp.checksum = 0;
        //hdr.udp.length_ = meta.egress.payload_length + 30; // ??

        hdr.vxlan.flags = 0x8;
        hdr.vxlan.rsvd = 0;
        hdr.vxlan.vni = meta.eg_tunnel.dst_vnid;
        hdr.vxlan.rsvd2 = 0;
        //meta.eg_tunnel.encap_ip_len = meta.eg_tunnel.encap_ip_len + 16;
    }
    @name(".f_insert_ipv4") action f_insert_ipv4(bit<8> proto) {
        hdr.ethernet.setValid();
        hdr.ipv4.setValid();
        hdr.ipv4.protocol = proto;
        hdr.ipv4.version = 0x4;
        hdr.ipv4.ihl = 0x5;
        hdr.ipv4.identification = 0;
        //hdr.ipv4.totalLen = meta.egress.pkt_len + 20;
        //meta.egress.pkt_len = meta.egress.pkt_len + 34; // 20 + 14
    }
    @name(".encap_ipv4_vxlan_rewrite") action encap_ipv4_vxlan_rewrite() {
        f_insert_vxlan();
        f_insert_ipv4(IP_PROTOCOLS_UDP);
        hdr.ipv4.totalLen = meta.egress.pkt_len + 32; // IP + UDP + VXLAN
        meta.egress.pkt_len = meta.egress.pkt_len + 46; // ETH+IP+UDP+VXLAN
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }
    @name(".f_insert_ipv6") action f_insert_ipv6(bit<8> proto) {
        hdr.ethernet.setValid();
        hdr.ipv6.setValid();
        hdr.ipv6.version = 0x6;
        hdr.ipv6.nextHeader = proto;
        //hdr.ipv6.trafficClass = 0;
        hdr.ipv6.flowLabel = 0;
        //hdr.ipv6.payloadLen = meta.egress.pkt_len;
        //meta.egress.pkt_len = meta.egress.pkt_len + 54;  // 40 + 14
    }
    @name(".encap_ipv6_vxlan_rewrite") action encap_ipv6_vxlan_rewrite() {
        f_insert_vxlan();
        f_insert_ipv6(IP_PROTOCOLS_UDP);
        hdr.ipv6.payloadLen = meta.egress.pkt_len + 12; // UDP + VXLAN
        meta.egress.pkt_len = meta.egress.pkt_len + 66; // ETH+IP+UDP+VXLAN
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }
//#ifdef ACI_TOR_MODE
    @name(".f_insert_ivxlan") action f_insert_ivxlan() {
        hdr.udp.setValid();
        hdr.ivxlan.setValid();

        hdr.udp.srcPort = meta.ig_eg_header.ol_udp_sp;
        hdr.udp.dstPort = UDP_PORT_IVXLAN;
        hdr.udp.checksum = 0;
        //hdr.udp.length_ = meta.egress.payload_length + 30; //??

        hdr.ivxlan.flags_nonce = 0;
        hdr.ivxlan.flags_locator = 0;
        hdr.ivxlan.flags_color = 0;
        hdr.ivxlan.flags_ext_fb_lb_tag = 0;
        hdr.ivxlan.flags_instance = 1;
        hdr.ivxlan.flags_protocol = 0;
        hdr.ivxlan.flags_fcn = 0;
        hdr.ivxlan.flags_oam = 0;
        hdr.ivxlan.nonce_lb = 0;
        hdr.ivxlan.nonce_dl = 0;
        hdr.ivxlan.nonce_e = 0;
        hdr.ivxlan.nonce_sp = meta.ig_eg_header.ol_sp;
        hdr.ivxlan.nonce_dp = meta.ig_eg_header.ol_dp;
        hdr.ivxlan.nonce_dre = 0;
        hdr.ivxlan.nonce_sclass = meta.ig_eg_header.src_class;
        hdr.ivxlan.vni = meta.eg_tunnel.dst_vnid;
        hdr.ivxlan.lsb_m = 0;
        hdr.ivxlan.lsb_vpath = 0;
        hdr.ivxlan.lsb_metric = 0;
    }
//#else  /*ACI_TOR_MODE*/
    action f_insert_geneve_header() {
        hdr.udp.setValid();
        hdr.geneve.setValid();
        //meta.egress.pkt_len = meta.egress.pkt_len + 12;
        
        hdr.udp.srcPort = meta.ig_eg_header.ol_udp_sp;
        hdr.udp.dstPort = UDP_PORT_GENEVE;
        hdr.udp.checksum = 0;
        //hdr.udp.length_ = meta.egress.payload_length + 30;
        
        hdr.geneve.ver = 0;
        hdr.geneve.oam = 0;
        hdr.geneve.critical = 0;
        hdr.geneve.optLen = 0;
        hdr.geneve.protoType = ETHERTYPE_ETHERNET;
        hdr.geneve.vni = meta.eg_tunnel.dst_vnid;
        hdr.geneve.reserved = 0;
        hdr.geneve.reserved2 = 0;
        
        //meta.eg_tunnel.encap_ip_len = add(meta.eg_tunnel.encap_ip_len + 16;
    }
    
#ifndef DISABLE_NVGRE
    action f_insert_nvgre_header() {
        hdr.gre.setValid();
        hdr.nvgre.setValid();
        //meta.egress.pkt_len = meta.egress.pkt_len + 12;
        hdr.gre.proto = ETHERTYPE_ETHERNET;
        hdr.gre.recurse = 0;
        hdr.gre.flags = 0;
        hdr.gre.ver = 0;
        hdr.gre.R = 0;
        hdr.gre.K = 1;
        hdr.gre.C = 0;
        hdr.gre.S = 0;
        // TBDP416 - Intentional to have one field with capital S and
        // another with lower case s?  Why?
        hdr.gre.s = 0;
        
        hdr.nvgre.tni = meta.eg_tunnel.dst_vnid;
        //meta.eg_tunnel.encap_ip_len = meta.eg_tunnel.encap_ip_len + 8;
        //TODO  hdr.nvgre.flow_id = meta.ig_eg_header.od_udp_sp & 0xFF;
    }
#endif /*DISABLE_NVGRE*/

    action f_insert_gre_header() {
        hdr.gre.setValid();
        //meta.egress.pkt_len = meta.egress.pkt_len + 4;
    }
//#endif /*ACI_TOR_MODE*/

//#ifdef ACI_TOR_MODE
    // ~~~~~~ ivxlan ~~~~~~
    @name(".encap_ipv4_ivxlan_rewrite")
    action encap_ipv4_ivxlan_rewrite() {
        f_insert_ivxlan();
        f_insert_ipv4(IP_PROTOCOLS_UDP);
        hdr.ipv4.totalLen = meta.egress.pkt_len + 32; // IP + UDP + VXLAN
        meta.egress.pkt_len = meta.egress.pkt_len + 46; // ETH+IP+UDP+VXLAN
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }
    @name(".encap_ipv6_ivxlan_rewrite")
    action encap_ipv6_ivxlan_rewrite() {
        f_insert_ivxlan();
        f_insert_ipv6(IP_PROTOCOLS_UDP);
        hdr.ipv6.payloadLen = meta.egress.pkt_len + 12; // UDP + VXLAN
        meta.egress.pkt_len = meta.egress.pkt_len + 66; // ETH+IP+UDP+VXLAN
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

//////////////////////////////////////////////////////////////////////
//#else  /*ACI_TOR_MODE*/
    // ~~~~~~ geneve ~~~~~~
    action encap_ipv4_geneve_rewrite() {
	f_insert_geneve_header();
	f_insert_ipv4(IP_PROTOCOLS_UDP);
        hdr.ipv4.totalLen = meta.egress.pkt_len + 32; // IP + UDP + VXLAN
        meta.egress.pkt_len = meta.egress.pkt_len + 46; // ETH+IP+UDP+VXLAN
	hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }
    action encap_ipv6_geneve_rewrite() {
	f_insert_geneve_header();
	f_insert_ipv6(IP_PROTOCOLS_UDP);
        hdr.ipv6.payloadLen = meta.egress.pkt_len + 12; // UDP + VXLAN
        meta.egress.pkt_len = meta.egress.pkt_len + 66; // ETH+IP+UDP+VXLAN
	hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

#ifndef DISABLE_NVGRE
// ~~~~~~ nvgre ~~~~~~
    action encap_ipv4_nvgre_rewrite() {
	f_insert_nvgre_header();
	f_insert_ipv4(IP_PROTOCOLS_GRE);
        hdr.ipv4.totalLen = meta.egress.pkt_len + 28; // IP + GRE + Key
        meta.egress.pkt_len = meta.egress.pkt_len + 42; // ETH+IP+GRE+KEY
	hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action encap_ipv6_nvgre_rewrite() {
	f_insert_nvgre_header();
	f_insert_ipv6(IP_PROTOCOLS_GRE);
        hdr.ipv6.payloadLen = meta.egress.pkt_len + 8; // GRE + Key
        meta.egress.pkt_len = meta.egress.pkt_len + 62; // ETH+IP+GRE+KEY
	hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

#endif /*DISABLE_NVGRE*/

    // ~~~~~~ gre ~~~~~~
    action encap_ipv4_gre_rewrite() {
	f_insert_gre_header();
	hdr.gre.proto = hdr.ethernet.etherType;
	f_insert_ipv4(IP_PROTOCOLS_GRE);
        hdr.ipv4.totalLen = meta.egress.pkt_len + 24; // IP + GRE
        meta.egress.pkt_len = meta.egress.pkt_len + 38; // ETH+IP+GRE
	hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action encap_ipv6_gre_rewrite() {
	f_insert_gre_header();
	hdr.gre.proto = hdr.ethernet.etherType;
	f_insert_ipv6(IP_PROTOCOLS_GRE);
        hdr.ipv6.payloadLen = meta.egress.pkt_len + 4; // GRE
        meta.egress.pkt_len = meta.egress.pkt_len + 58; // ETH+IP+GRE
	hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

    // ~~~~~~ v4-in-v4 ~~~~~~
    action encap_ipv4_in_ipv4_rewrite() {
        f_insert_ipv4(IP_PROTOCOLS_IPV4);
        hdr.ipv4.totalLen = meta.egress.pkt_len + 20; // IP
        meta.egress.pkt_len = meta.egress.pkt_len + 34; // ETH+IP
	hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }
    
    // ~~~~~~ v6-in-v4 ~~~~~~
    action encap_ipv6_in_ipv4_rewrite() {
        f_insert_ipv4(IP_PROTOCOLS_IPV6);
        hdr.ipv4.totalLen = meta.egress.pkt_len + 20; // IP
        meta.egress.pkt_len = meta.egress.pkt_len + 34; // ETH+IP
	hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }
    
    // ~~~~~~ v4-in-v6 ~~~~~~
    action encap_ipv4_in_ipv6_rewrite() {
        f_insert_ipv6(IP_PROTOCOLS_IPV4);
        hdr.ipv6.payloadLen = meta.egress.pkt_len;
        meta.egress.pkt_len = meta.egress.pkt_len + 54; // ETH+IP
	hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }
    
    // ~~~~~~ v6-in-v6 ~~~~~~
    action encap_ipv6_in_ipv6_rewrite() {
        f_insert_ipv6(IP_PROTOCOLS_IPV6);
        hdr.ipv6.payloadLen = meta.egress.pkt_len;
        meta.egress.pkt_len = meta.egress.pkt_len + 54; // ETH+IP
	hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }
//#endif /*ACI_TOR_MODE*/

//////////////////////////////////////////////////////////////////////
    @name(".encap_dmac_rewrite")
    action encap_dmac_rewrite(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    @name(".encap_ipv4_dipo_rewrite")
    action encap_ipv4_dipo_rewrite(bit<32> dipo) {
        hdr.ipv4.dstAddr = dipo;
    }
    @name(".encap_ipv4_sipo_rewrite")
    action encap_ipv4_sipo_rewrite(bit<32> sipo) {
        hdr.ipv4.srcAddr = sipo;
    }
    @name(".encap_ipv6_dipo_rewrite")
    action encap_ipv6_dipo_rewrite(bit<128> dipo) {
        hdr.ipv6.dstAddr = dipo;
    }
    @name(".encap_ipv6_sipo_rewrite")
    action encap_ipv6_sipo_rewrite(bit<128> sipo) {
        hdr.ipv6.srcAddr = sipo;
    }
    @name(".rewrite_outer_smac")
    action rewrite_outer_smac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name(".set_encap_ipv4_rw_ptr")
    action set_encap_ipv4_rw_ptr(bit<13> dipo_rw_ptr, bit<4> encap_type,
                                 bit<2> encap_l3_type, bit<9> sipo_rw_ptr,
                                 bit<13> inner_dst_bd_xlate_idx, bit<1> ttl_cio,
                                 bit<2> cts_mode)
    {
        meta.eg_tunnel.ipv4_sipo_rw_ptr = sipo_rw_ptr;
        meta.eg_tunnel.ipv4_dipo_rw_ptr = dipo_rw_ptr;
        meta.eg_tunnel.dst_encap_type = encap_type;
        meta.eg_tunnel.inner_dst_bd_xlate_idx = inner_dst_bd_xlate_idx;
        meta.eg_tunnel.dst_encap_l3_type = encap_l3_type;
        meta.eg_tunnel.ttl_cio = ttl_cio;
        meta.eg_tunnel.cts_mode = cts_mode;
    }
    @name(".set_encap_ipv6_rw_ptr")
    action set_encap_ipv6_rw_ptr(bit<11> dipo_rw_ptr, bit<4> encap_type,
                                 bit<2> encap_l3_type, bit<7> sipo_rw_ptr,
                                 bit<13> inner_dst_bd_xlate_idx, bit<1> ttl_cio,
                                 bit<2> cts_mode)
    {
        meta.eg_tunnel.ipv6_sipo_rw_ptr = sipo_rw_ptr;
        meta.eg_tunnel.ipv6_dipo_rw_ptr = dipo_rw_ptr;
        meta.eg_tunnel.dst_encap_type = encap_type;
        meta.eg_tunnel.inner_dst_bd_xlate_idx = inner_dst_bd_xlate_idx;
        meta.eg_tunnel.dst_encap_l3_type = encap_l3_type;
        meta.eg_tunnel.ttl_cio = ttl_cio;
        meta.eg_tunnel.cts_mode = cts_mode;
    }
    @name("encap_ip_tunnel_header") table encap_ip_tunnel_header {
        actions = {
            encap_ipv4_vxlan_rewrite;
            encap_ipv6_vxlan_rewrite;
//#ifdef ACI_TOR_MODE
            encap_ipv4_ivxlan_rewrite;
            encap_ipv6_ivxlan_rewrite;
//#else  /*ACI_TOR_MODE*/
            encap_ipv4_geneve_rewrite;
            encap_ipv6_geneve_rewrite;
#ifndef DISABLE_NVGRE
            encap_ipv4_nvgre_rewrite;
            encap_ipv6_nvgre_rewrite;
#endif /*DISABLE_NVGRE*/
            encap_ipv4_gre_rewrite;
            encap_ipv6_gre_rewrite;
            encap_ipv4_in_ipv4_rewrite;
            encap_ipv4_in_ipv6_rewrite;
            encap_ipv6_in_ipv4_rewrite;
            encap_ipv6_in_ipv6_rewrite;
//#endif /*ACI_TOR_MODE*/
            @default_only NoAction;
        }
        key = {
            meta.eg_tunnel.dst_encap_type: exact;
        }
        size = 16;
        default_action = NoAction();
    }
    @name("encap_outer_dmac") table encap_outer_dmac {
        actions = {
            encap_dmac_rewrite;
            @default_only NoAction;
        }
        key = {
            meta.eg_tunnel.encap_l2_idx: exact;
        }
        size = OUTER_DMAC_REWRITE_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("encap_outer_ipv4_dip") table encap_outer_ipv4_dip {
        actions = {
            encap_ipv4_dipo_rewrite;
            @default_only NoAction;
        }
        key = {
            meta.eg_tunnel.ipv4_dipo_rw_ptr: exact;
        }
        size = IPV4_DIPO_REWRITE_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("encap_outer_ipv4_sip") table encap_outer_ipv4_sip {
        actions = {
            encap_ipv4_sipo_rewrite;
            @default_only NoAction;
        }
        key = {
            meta.eg_tunnel.ipv4_sipo_rw_ptr: exact;
            meta.ig_eg_header.l3_fwd_mode           : exact; /* use vip for unicast bridged sourced from a vpc port, pip for everything else */
            meta.ig_eg_header.l2_fwd_mode           : exact;
            meta.ig_eg_header.aa_multihomed         : exact;
        }
        size = IPV4_SIPO_REWRITE_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("encap_outer_ipv6_dip") table encap_outer_ipv6_dip {
        actions = {
            encap_ipv6_dipo_rewrite;
            @default_only NoAction;
        }
        key = {
            meta.eg_tunnel.ipv6_dipo_rw_ptr: exact;
        }
        size = IPV6_DIPO_REWRITE_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("encap_outer_ipv6_sip") table encap_outer_ipv6_sip {
        actions = {
            encap_ipv6_sipo_rewrite;
            @default_only NoAction;
        }
        key = {
            meta.eg_tunnel.ipv6_sipo_rw_ptr: exact;
            meta.ig_eg_header.l3_fwd_mode           : exact; /* use vip for unicast bridged sourced from a vpc port, pip for everything else */
            meta.ig_eg_header.l2_fwd_mode           : exact;
            meta.ig_eg_header.aa_multihomed         : exact;
        }
        size = IPV6_SIPO_REWRITE_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("encap_outer_smac") table encap_outer_smac {
        actions = {
            rewrite_outer_smac;
            @default_only NoAction;
        }
        key = {
            meta.outer_dst_bd.rmac_index: exact;
        }
        size = OUTER_SMAC_REWRITE_TABLE_SIZE;
        default_action = NoAction();
    }
#ifndef DISABLE_MPLS
    action set_mpls_rw_ptr(bit<14> label_rw_ptr,
                           bit<4> encap_type,
                           bit<2> encap_l3_type,
                           bit<1> ttl_cio,
                           bit<3> label_op) {
        meta.mplsm.label_rw_ptr = label_rw_ptr;
        meta.eg_tunnel.dst_encap_type = encap_type;
        //meta.eg_tunnel.inner_dst_bd_xlate_idx = inner_dst_bd_xlate_idx;
        meta.eg_tunnel.dst_encap_l3_type = encap_l3_type;
        meta.eg_tunnel.ttl_cio = ttl_cio;
        meta.mplsm.label_op = label_op;
    }
#endif
    @name("encap_rewrite") table encap_rewrite {
        actions = {
            set_encap_ipv4_rw_ptr;
            set_encap_ipv6_rw_ptr;
#ifndef DISABLE_MPLS
            set_mpls_rw_ptr;
#endif
            @default_only NoAction;
        }
        key = {
            meta.egress.encap_idx: exact;
        }
        size = TUNNEL_REWRITE_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("process_egress_vnid_xlate") process_egress_vnid_xlate() process_egress_vnid_xlate_0;
#ifndef DISABLE_MPLS
    @name("process_mpls_rewrite") process_mpls_rewrite() process_mpls_rewrite_0;
#endif /*DISABLE_MPLS*/
    @name("process_outer_ttl_rewrite") process_outer_ttl_rewrite() process_outer_ttl_rewrite_0;
    apply {
        encap_rewrite.apply();
        // ~~~~~~ Derive VNID ~~~~~~
#ifdef DISABLE_L3_TUNNELS
        process_egress_vnid_xlate_0.apply(hdr, meta, standard_metadata);
#else
        if (meta.eg_tunnel.l3_tunnel_encap == 0) {
            // vnid xlate
            process_egress_vnid_xlate_0.apply(hdr, meta, standard_metadata);
        }
#endif

        // ~~~~~~ tunnel header ~~~~~~~
#ifndef DISABLE_MPLS
        if (meta.eg_tunnel.dst_encap_l4_type == L3TYPE_MPLS) {
            process_mpls_rewrite_0.apply(hdr, meta, standard_metadata);
        } else {
#endif /*DISABLE_MPLS*/

	// ~~~~~~ Copy outer L4 header to inner and then remove it~~~~~~
        if (hdr.tcp.isValid()) {
            hdr.inner_tcp = hdr.tcp;
            hdr.tcp.setInvalid();
        }
        if (hdr.udp.isValid()) {
            hdr.inner_udp = hdr.udp;
            hdr.udp.setInvalid();
        }
        if (hdr.icmp.isValid()) {
            hdr.inner_icmp = hdr.icmp;
            hdr.icmp.setInvalid();
        }
        
	// ~~~~~~ Copy Outer L3 header to inner L3 ~~~~~~
        if (hdr.ipv4.isValid()) {
            hdr.inner_ipv4 = hdr.ipv4;
            hdr.ipv4.setInvalid();
        }
        if (hdr.ipv6.isValid()) {
            hdr.inner_ipv6 = hdr.ipv6;
            hdr.ipv6.setInvalid();
        }
        if (hdr.fcoe.isValid()) {
            hdr.inner_fcoe = hdr.fcoe;
            hdr.fcoe.setInvalid();
        }
        
#ifndef DISABLE_L3_TUNNELS
	if (meta.eg_tunnel.l3_tunnel_encap == 1) {
	    // leave ethernet header
	    // remove all tags
	    if (hdr.vntag.isValid()) {
		hdr.vntag.setInvalid();
		meta.egress.pkt_len = meta.egress.pkt_len - 6;
	    }
	    if (hdr.qtag0.isValid()) {
		hdr.qtag0.setInvalid();
		meta.egress.pkt_len = meta.egress.pkt_len - 4;
	    }
	    if (hdr.qtag1.isValid()) {
		hdr.qtag1.setInvalid();
		meta.egress.pkt_len = meta.egress.pkt_len - 4;
	    }
	    if (hdr.cmd.isValid()) {
		hdr.cmd.setInvalid();
		meta.egress.pkt_len = meta.egress.pkt_len - 8;
	    }
	    if (hdr.timestamp.isValid()) {
		hdr.timestamp.setInvalid();
		meta.egress.pkt_len = meta.egress.pkt_len - 8;
	    }
        } else {
#endif /*DISABLE_L3_TUNNELS*/
	// ~~~~~~ copy outer L2 to inner L2 ~~~~~~
        if (hdr.qtag0.isValid()) {
            hdr.inner_qtag0 = hdr.qtag0;
            hdr.qtag0.setInvalid();
        }
            
        if (hdr.cmd.isValid()) {
            hdr.inner_cmd = hdr.cmd;
            hdr.cmd.setInvalid();
        }
            
        if (hdr.timestamp.isValid()) {
            hdr.inner_timestamp = hdr.timestamp;
            hdr.timestamp.setInvalid();
        }
            
            
	// ~~~~~~ remove vntag/ieth ~~~~~~
	//// if (hdr.vntag.isValid()) {
        ////     hdr.vntag.setInvalid();
        //// }
	//// if (hdr.ieth.isValid()) {
        ////     hdr.ieth.setInvalid();
        //// }
#ifndef DISABLE_L3_TUNNELS
	}
#endif /*DISABLE_L3_TUNNELS*/

//	hdr.inner_ethernet = hdr.ethernet;
//	hdr.ethernet.setInvalid();
            
	// ~~~~~~ Generate Tunnel header(vxlan, gre etc) ~~~~~
        encap_ip_tunnel_header.apply();

	// ~~~~~~ DIPo, SIPo ~~~~~~
        if (meta.eg_tunnel.dst_encap_l3_type == L3TYPE_IPV4) {
            encap_outer_ipv4_sip.apply();
            encap_outer_ipv4_dip.apply();
        } else if (meta.eg_tunnel.dst_encap_l3_type == L3TYPE_IPV6) {
            encap_outer_ipv6_sip.apply();
            encap_outer_ipv6_dip.apply();
        }

	// ~~~~~~ TTL ~~~~~~
        process_outer_ttl_rewrite_0.apply(hdr, meta, standard_metadata);
//	encap_outer_ttl.apply();

	// ~~~~~~ DMACo, SMACo ~~~~~~
        encap_outer_dmac.apply();
        encap_outer_smac.apply();
#ifndef DISABLE_MPLS
        }
#endif /*DISABLE_MPLS*/
    }
}

control process_egress_vlan_xlate(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_egress_encap_vlan") action set_egress_encap_vlan(bit<12> encap_vlan) {
        meta.eg_local.encap_vlan = encap_vlan;
    }
    @name("egress_vlan_xlate_table") table egress_vlan_xlate_table {
        actions = {
            set_egress_encap_vlan;
            @default_only NoAction;
        }
        key = {
            meta.dst_if.bd_xlate_idx: exact;
            // TBD: Original P4_14 code had outer_dst_bd for hash
            // table, but dst_bd for overflow TCAM.  Which is correct?
            meta.egress.outer_dst_bd: exact;
        }
	size = DST_VLAN_XLATE_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        if (!egress_vlan_xlate_table.apply().hit) {
            meta.eg_drop.vlan_xlate_miss = TRUE;
        }

	// Check if outgoing vlan is port's default vlan
	if (meta.eg_local.encap_vlan == meta.dst_if.default_vlan) {
	    // meta.eg_local.is_default_vlan = TRUE;
	    meta.eg_local.encap_vlan = 0x0;
	}
    }
}

control process_egress_vlan_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".insert_qtag0") action insert_qtag0() {
        hdr.qtag0.setValid();
        hdr.qtag0.etherType = hdr.ethernet.etherType;
        hdr.ethernet.etherType = ETHERTYPE_QTAG;
    }
    @name(".push_qtag0") action push_qtag0() {
	// Push down qtag header
        hdr.qtag1 = hdr.qtag0;
	// Add new qtag header on top
        hdr.qtag0.setValid();
	// modify qtag0_header
        hdr.qtag0.etherType = hdr.ethernet.etherType;
        hdr.qtag0.vid = meta.eg_local.encap_vlan;
	// fix ethertype
        hdr.ethernet.etherType = ETHERTYPE_QTAG;
    }
    @name(".modify_qtag0_vlan") action modify_qtag0_vlan() {
        hdr.qtag0.vid = meta.eg_local.encap_vlan;
    }
    //action remove_qtag0_after_vntag() {
    //    hdr.vntag.etherType = hdr.qtag0.etherType;
    //    hdr.qtag0.setInvalid();
    //}
    //action remove_qtag0_after_ethernet() {
    //    hdr.ethernet.etherType, hdr.qtag0.etherType;
    //    hdr.qtag0.setInvalid();
    //}
    @name("egress_vlan_rewrite") table egress_vlan_rewrite {
        actions = {
            insert_qtag0;
            push_qtag0;
            modify_qtag0_vlan;
	    //remove_qtag0_after_vntag;
	    //remove_qtag0_after_ethernet;
            @default_only NoAction;
        }
        key = {
            hdr.qtag0.isValid()                    : exact;
            hdr.vntag.isValid()                    : exact;
	    hdr.qtag1.isValid()                    : exact;
            meta.dst_if.vlan_mode                : ternary;
            meta.dst_if.untag_default_vlan       : ternary;
            meta.dst_if.priority_tag_default_vlan: ternary;
        }
        size = 64;
        default_action = NoAction();
    }
    apply {
        if (meta.eg_bypass.qtag_bypass == 0) {
            egress_vlan_rewrite.apply();
        }

        //if (meta.egress.vlan_mode == VLAN_MODE_TRUNK) {
        //    if (hdr.qtag0.isValid()) {
        //        push_qtag0();
        //    } else {
        //        insert_qtag0();
        //    }
        //}

        if (hdr.qtag0.isValid()) {
            meta.eg_local.dst_qtag0_vld = TRUE;
            meta.eg_local.dst_qtag0_vid = hdr.qtag0.vid;
            meta.eg_local.dst_qtag0_pcp = hdr.qtag0.pcp;
        }
    }
}

// ******************************************
// rewrite qos fields of encap header
// ******************************************

control process_outer_qos_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.eg_bypass.qos_rw_bypass == 0) {
            // DSCP
            if (meta.eg_qos.ol_dscp_rw == 1) {
                if (hdr.ipv4.isValid()) {
                    if ((meta.eg_qos.dscp_cio == 1) && (hdr.inner_ipv4.isValid())) {
                        hdr.ipv4.dscp = hdr.inner_ipv4.dscp;
                    // TBD: next condition looks like repeat of one
                    // above.  Copy and past bug?  The original P4_14
                    // code seems to have it, too.
                    } else if ((meta.eg_qos.dscp_cio == 1) && (hdr.inner_ipv4.isValid())) {
                        hdr.ipv4.dscp = hdr.inner_ipv4.dscp;
                    } else {
                        hdr.ipv4.dscp = meta.eg_qos.ol_dscp;
                    }
                } else if (hdr.ipv6.isValid()) {
                    // TBD: next hdr.inner_ipv4 should be hdr.inner_ipv6?
                    if ((meta.eg_qos.dscp_cio == 1) && (hdr.inner_ipv4.isValid())) {
                        hdr.ipv6.dscp = hdr.inner_ipv6.dscp;
                    // TBD: similarly here looks like copy & paste
                    // bug, maybe.
                    } else if ((meta.eg_qos.dscp_cio == 1) && (hdr.inner_ipv6.isValid())) {
                        hdr.ipv6.dscp = hdr.inner_ipv6.dscp;
                    } else {
                        hdr.ipv6.dscp = meta.eg_qos.ol_dscp;
                    }
                }
            }
            
            // COS/DE
            if (meta.eg_qos.ol_cos_rw == 1) {
                if (hdr.qtag0.isValid()) {
                    hdr.qtag0.pcp = meta.eg_qos.ol_cos;
                    hdr.qtag0.cfi = meta.eg_qos.ol_de;
                }
            }
        }
    }
}

// same epg, bd, obd, same vtep checks
control process_self_fwd_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // same epg/bd checks are done in sug_eg_vlan.p4
        // not convinced that same_obd check is needed
        // same encap check
        if (meta.ig_tunnel.src_encap_type == meta.eg_tunnel.dst_encap_type) {
            meta.egress.same_encap = TRUE;
        } else {
            meta.egress.same_encap = FALSE;
        }

        // Layer 2 self forwarding check
        meta.rewrite.vntag_loop = FALSE;

        if (
            // bridged traffic
            (meta.egress.l3_fwd_mode == L3_FWD_MODE_BRIDGE) &&
            // same encap/bd/epg
            (meta.egress.same_encap == 1) &&
            (meta.egress.same_bd == 1) &&
            (meta.egress.same_epg == 1) &&
            // not bypassed
            (meta.dst_bd.bypass_self_fwd_check == 0) &&
            (meta.eg_bypass.same_if_check_bypass == 0) &&
            ((meta.egress.use_met == 0) ||
             (meta.met.same_if_check_bypass == 0)))
        {
            if (meta.dst_port.vnic_if == 1) {
                // for FEX->FEX communication, set the loop bit
                if (meta.eg_src_port.vnic_if == 1) {
                    meta.rewrite.vntag_loop = TRUE;
                }
            } else {
                // if src_port == dst_port, drop packet
                if (meta.dst_port.pcnum == meta.eg_src_port.pcnum) {
                    meta.eg_drop.same_if_check = TRUE;
                }
            }
        }
        
        // same vtep check
        if (
            // bridged traffic
            (meta.egress.l3_fwd_mode == L3_FWD_MODE_BRIDGE) &&
            // same encap
            (meta.egress.same_encap == 1) &&
            // not bypassed
            (meta.dst_bd.bypass_same_vtep_check == 0) &&
            //(eg_bypass.same_vtep_check_bypass == 0) &&
            (meta.dst_if.same_vtep_prune_en == 1) &&
            //((meta.egress.use_met == 0) ||
            // (meta.met.same_vtep_check_bypass == 0)) &&
            // tunnel decap operation
            ((meta.egress.tunnel_decap == 1) &&
             (meta.egress.tunnel_encap == 1)) &&
            ((hdr.ipv4.isValid() &&
              (meta.eg_local.outer_ipv4_sa == hdr.ipv4.dstAddr))))
            //((hdr.ipv4.isValid() && (meta.eg_local.outer_ipv4_sa == hdr.ipv4.dstAddr)) ||
            //(hdr.ipv6.isValid() && (meta.eg_local.outer_ipv6_sa == hdr.ipv6.dstAddr))))
        {
            meta.eg_drop.same_vtep = TRUE;
        } else {
            // TBD: The original code assigned TRUE here, but that
            // looks like a copy and paste bug.
            meta.eg_drop.same_vtep = FALSE;
        }
    }
}

#ifndef P4_DISABLE_FEX
/*****************************************************************************/
/* SVIF Derivation                                                           */
/*****************************************************************************/

control process_derive_vntag_svif(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_svif") action set_svif(bit<12> svif) {
        meta.rewrite.svif = svif;
    }
    @name("svif_hash_table") table svif_hash_table {
        actions = {
            set_svif;
            @default_only NoAction;
        }
        key = {
            meta.dst_port.uc_vif_xlate_idx: exact;
            meta.ig_eg_header.ieth_src_idx         : exact;
        }
        size = SVIF_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        if (!svif_hash_table.apply().hit) {
	    meta.eg_drop.svif_xlate_miss = TRUE;
        }
    }
}
#endif /* P4_DISABLE_FEX */  

/*****************************************************************************/
/* Unicast DVIF Derivation                                                   */
/*****************************************************************************/

control process_derive_vntag_uc_dvif(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_uc_dvif") action set_uc_dvif(bit<12> uc_dvif) {
        meta.rewrite.uc_dvif = uc_dvif;
    }
    @name("uc_dvif_hash_table") table uc_dvif_hash_table {
        actions = {
            set_uc_dvif;
            @default_only NoAction;
        }
        key = {
            meta.dst_port.uc_vif_xlate_idx: exact;
            meta.ig_eg_header.ieth_dst_idx         : ternary;
        }
        size = UC_DVIF_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        if (!uc_dvif_hash_table.apply().hit) {
	    meta.eg_drop.uc_dvif_xlate_miss = TRUE;
        }
    }
}

control process_derive_vntag_mc_dvif(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_mc_dvif") action set_mc_dvif(bit<14> mc_dvif) {
        meta.rewrite.mc_dvif = mc_dvif;
    }
    @name("mc_dvif_hash_table") table mc_dvif_hash_table {
        actions = {
            set_mc_dvif;
            @default_only NoAction;
        }
        key = {
            meta.eg_local.mc_dvif_key_mc_idx   : exact;
            //meta.dst_port.mc_vif_xlate_idx     : exact;
            meta.eg_local.mc_dvif_key_alt_vntag: exact;
        }
        size = MC_DVIF_HASH_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
        // Alt-Vntag bit
        if (meta.egress.copy_service == 1) {
            meta.eg_local.mc_dvif_key_alt_vntag = 0;
        } else if (meta.ig_eg_header.ieth_vpc_df == 0) {
            meta.eg_local.mc_dvif_key_alt_vntag = TRUE;
        }
        // mc-idx
        if (meta.dp_eg_header.met_v == 1) {
            meta.eg_local.mc_dvif_key_mc_idx = meta.met.ovector_idx;
        } else {
            // TODO maybe_wrong_cast
            meta.eg_local.mc_dvif_key_mc_idx[12:0] =
                (bit<13>) meta.dp_eg_header.met_index;
        }

        if (!mc_dvif_hash_table.apply().hit) {
	    meta.eg_drop.mc_dvif_xlate_miss = TRUE;
        }
    }
}

/*****************************************************************************/
/* VNTAG Fields                                                              */
/*****************************************************************************/

control process_vntag_rewrite(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("process_derive_vntag_svif") process_derive_vntag_svif() process_derive_vntag_svif_0;
    @name("process_derive_vntag_uc_dvif") process_derive_vntag_uc_dvif() process_derive_vntag_uc_dvif_0;
    @name("process_derive_vntag_mc_dvif") process_derive_vntag_mc_dvif() process_derive_vntag_mc_dvif_0;
    apply {
        if (meta.eg_bypass.vntag_bypass == 0 && meta.dst_port.vnic_if == 1) {
            // Derive vntag fields
            process_derive_vntag_svif_0.apply(hdr, meta, standard_metadata);
            if (meta.egress.l2_fwd_mode == L2_FWD_MODE_UC) {
                process_derive_vntag_uc_dvif_0.apply(hdr, meta, standard_metadata);
            } else {
                process_derive_vntag_mc_dvif_0.apply(hdr, meta, standard_metadata);
            }

            // Add header and fix ethertypes
            hdr.vntag.setValid();
            hdr.vntag.etherType = hdr.ethernet.etherType;
            hdr.ethernet.etherType = ETHERTYPE_VNTAG;
            
            // default fields
            hdr.vntag.direction = 1;
            hdr.vntag.reserved = 0;
            hdr.vntag.version = 0;
            
            // Unicast vs multicast
            if (meta.egress.l2_fwd_mode == L2_FWD_MODE_UC) {
                hdr.vntag.pointer = 0;
                // TODO maybe_wrong_cast
                hdr.vntag.destVif = (bit<14>) meta.rewrite.uc_dvif;
            } else {
                hdr.vntag.pointer = 1;
                hdr.vntag.destVif = meta.rewrite.mc_dvif;
            }
            
            // Loop-bit
            if (meta.rewrite.vntag_loop == 1) {
                hdr.vntag.looped = 1;
                hdr.vntag.srcVif = meta.rewrite.svif;
            }
        }
    }
}

control process_dst_vlan_mbr_check(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".dst_vlan_mbr_drop") action dst_vlan_mbr_drop() {
        meta.eg_drop.vlan_mbr = TRUE;
    }
    @name("dst_vlan_mbr") table dst_vlan_mbr {
        actions = {
            dst_vlan_mbr_drop;
            @default_only NoAction;
        }
        key = {
            meta.egress.outer_dst_bd: exact;
            meta.dp_eg_header.oport          : exact;
        }
        size = EGRESS_VLAN_MBR_TABLE_SIZE;
        default_action = NoAction();
    }
    apply {
#ifdef ALTERNATE_EGRESS_CBL_METHOD
        meta.eg_local.cbl_state = (bit<1>) (meta.outer_dst_bd.ifmbr >>
                                            dp_eg_header.oport);
        if ((meta.eg_bypass.vlan_mbr_chk_bypass == 0) &&
            (meta.eg_local.cbl_state==0))
        {
            meta.eg_drop.vlan_mbr, TRUE);
        } else {
            meta.eg_drop.vlan_mbr, FALSE);
        }
#else
        if (meta.eg_bypass.vlan_mbr_chk_bypass == 0) {
            dst_vlan_mbr.apply();
        }
#endif
    }
}

/*****************************************************************************/
/* SwitchPort Block                                                          */
/*****************************************************************************/
/*
counter switchport_block_counts {
    type : packets;
    direct : switchport_block;
}

action switchport_block_drop() {
    drop();
//    count(switchport_block_bc_count, 0);
    
}
*/

control process_switchport_block(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.eg_bypass.switchport_block_bypass == 0) {
            if (meta.ig_eg_header.l2_fwd_mode == L2_FWD_MODE_FLOOD) {
                if ((hdr.ethernet.dstAddr == 0xFFFFFFFFFFFF) &&
                    (meta.dst_port.block_bc == 1))
                {
                    meta.eg_drop.switchport_block_bc = 1;
                } else if (((hdr.ethernet.dstAddr & 0x010000000000) == 0x0) &&
                           (meta.dst_port.block_uuc == 1))
                {
                    meta.eg_drop.switchport_block_uuc = 1;
                } else if (meta.dst_port.block_umc == 1) {
                    meta.eg_drop.switchport_block_umc = 1;
                }
            }
        }
    }
}

/*****************************************************************************/
/*  Drop Masking */
/*****************************************************************************/

control process_egress_drop(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (
            /////    //ppp foreach my $cond (@eg_drop_conditions) {
            /////	(meta.eg_drop.`cond` == 1) ||
            /////	//ppp }
            (meta.eg_drop.acl_deny == 1) ||
            (meta.eg_drop.switchport_block_bc == 1) ||
            (meta.eg_drop.switchport_block_umc == 1) ||
            (meta.eg_drop.switchport_block_uuc == 1) ||
            (meta.eg_drop.vlan_mbr == 1) ||
            (meta.eg_drop.same_if_check == 1) ||
            //(meta.eg_drop.same_vif_uc == 1) ||
            //(meta.eg_drop.ttl_expire == 1) ||
            //(meta.eg_drop.sup_policer_drop == 1) ||
            (meta.eg_drop.mc_dvif_xlate_miss == 1) ||
            (meta.eg_drop.uc_dvif_xlate_miss == 1) ||
            (meta.eg_drop.vlan_xlate_miss == 1) ||
            (meta.eg_drop.vnid_xlate_miss == 1) ||
            //(meta.eg_drop.mc_met_core_if_prune == 1) ||
            //(meta.eg_drop.l3_same_if_mc == 1) ||
            //(meta.eg_drop.sup_tx_mask == 1) ||
            (meta.eg_drop.same_vtep == 1) ||
            //(meta.eg_drop.sclass_sgt_xlate_miss == 1) ||
            (meta.eg_drop.epg_cross == 1) ||
            (meta.eg_drop.svif_xlate_miss == 1) ||
            (meta.eg_drop.qos_drop == 1) ||
            //(meta.eg_drop.qos_policer_drop == 1) ||
            false)
        {
            meta.eg_dp_header.drop = TRUE;
            //drop();
        }
    }
}

// ~~~~~~~~~~~ BD Stats ~~~~~~~~~~~~~~~~~~
#ifndef DISABLE_DST_BD_STATS
//counter dst_bd_stats {
//    type : packets_and_bytes;
//    instance_count : BD_STATS_TABLE_SIZE;
//    min_width : 96;
//}
//
//counter dst_bd_drop_stats {
//    type : packets_and_bytes;
//    instance_count : BD_STATS_TABLE_SIZE;
//}
#endif /*DISABLE_DST_BD_STATS*/


control process_eg_stats_update(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // TBDP416 - What to do with all commented-out calls to
        // count() in this control block?

        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // OR all the drop conditions
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if (
            (meta.eg_drop.acl_deny == 1) ||
            (meta.eg_drop.switchport_block_bc == 1) ||
            (meta.eg_drop.switchport_block_umc == 1) ||
            (meta.eg_drop.switchport_block_uuc == 1) ||
            (meta.eg_drop.vlan_mbr == 1) ||
            (meta.eg_drop.same_if_check == 1) ||
            (meta.eg_drop.same_vif_uc == 1) ||
            (meta.eg_drop.ttl_expired == 1) ||
            (meta.eg_drop.sup_policer_drop == 1) ||
            (meta.eg_drop.mc_dvif_xlate_miss == 1) ||
            (meta.eg_drop.uc_dvif_xlate_miss == 1) ||
            (meta.eg_drop.vlan_xlate_miss == 1) ||
            (meta.eg_drop.vnid_xlate_miss == 1) ||
            (meta.eg_drop.mc_met_core_if_prune == 1) ||
            (meta.eg_drop.l3_same_if_mc == 1) ||
            (meta.eg_drop.sup_tx_mask == 1) ||
            (meta.eg_drop.same_vtep == 1) ||
            (meta.eg_drop.sclass_sgt_xlate_miss == 1) ||
            (meta.eg_drop.epg_cross == 1) ||
            (meta.eg_drop.svif_xlate_miss == 1) ||
            (meta.eg_drop.qos_drop == 1) ||
            (meta.eg_drop.qos_policer_drop == 1) ||
            false) {
            meta.eg_drop.inc_drop_counters = TRUE;
        }
        
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //   Egress UMF
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        // -- per-port, byte_n_packets, non-atomic
        // set_umf/drop/cos - 64 ports x 4 (umf) x 2 (drop) x 8 (cos) x 2 (FC) = 8K
        
#ifndef DISABLE_DST_PORT_UMF_STATS
        // ~~~~~~~~~~ Port Stats ~~~~~~~~~~~~~
        // TODO maybe_wrong_cast
        meta.eg_local.dst_port_stats_idx = (bit<13>) meta.dp_eg_header.oport;
        
        // UC/MC/BC/Flood
        meta.eg_local.dst_port_stats_idx = (meta.eg_local.dst_port_stats_idx <<
                                            meta.egress.l2_fwd_mode);
        
        // cos.
        // TBD: Should this same metadata field be shifted left two
        // times like this?  Why?
        meta.eg_local.dst_port_stats_idx = (meta.eg_local.dst_port_stats_idx <<
                                            meta.eg_qos.cos);
        
        // Total
        if (hdr.fcoe.isValid()) {
            //count(dst_port_fc_total_stats, meta.eg_local.dst_port_stats_idx);
        } else {
            //count(dst_port_eth_total_stats, meta.eg_local.dst_port_stats_idx);
        }
        
        // Dropped
        if (meta.eg_drop.inc_drop_counters == 1) {
            if (hdr.fcoe.isValid()) {
                //count(dst_port_fc_drop_stats, meta.eg_local.dst_port_stats_idx);
            } else {
                //count(dst_port_eth_drop_stats, meta.eg_local.dst_port_stats_idx);
            }
        }
#endif /*DISABLE_DST_PORT_UMF_STATS*/

        
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Port-Class
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
        // -- per-port - 64 x 10 (in_class) x 2 (drop) x 2 (FC) = 2K
        // pkt_class set in_class/drop
        
#ifndef DISABLE_DST_PORT_CLASS_STATS
        // ~~~~~~~~~~ Port Stats ~~~~~~~~~~~~~
        // TODO maybe_wrong_cast
        meta.eg_local.dst_port_class_stats_idx =
            (bit<11>) meta.dp_eg_header.oport;
        
        // Eth/FC
        if (hdr.fcoe.isValid()) {
            meta.eg_local.dst_port_class_stats_idx =
                meta.eg_local.dst_port_class_stats_idx << 1;
        }
        
        // oclass.
        meta.eg_local.dst_port_class_stats_idx =
            meta.eg_local.dst_port_class_stats_idx << meta.dp_eg_header.oqueue;
        
        // Total
        //count(dst_port_class_total_stats, meta.eg_local.dst_port_class_stats_idx);
        // Dropped
        if (meta.eg_drop.inc_drop_counters == 1) {
            //count(dst_port_class_drop_stats, meta.eg_local.dst_port_class_stats_idx);
        }
#endif /*DISABLE_DST_PORT_UMF_STATS*/
        
#ifndef DISABLE_DST_TEP_STATS
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // TEP RX
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // per dst-tep, packets and bytes, atomic
        // mask - mytep, outer_uc, ivxlan_e=0, not_span
        // pkt-class - set drop, fabric_if
        // 256 teps x 2 (mark) x 8 (fabric_if) x 2 (drop)  = 8K
        
        // TEP ID
        // TODO maybe_wrong_cast
        meta.eg_local.dst_tep_stats_idx[7:0] =
            (bit<8>) meta.eg_tunnel.encap_idx;
        
        // Fabric port
        meta.eg_local.dst_tep_stats_idx = (meta.eg_local.dst_tep_stats_idx <<
                                           meta.dst_port.fabric_if_stats_idx);
        
        if ((meta.eg_tunnel.encap == 1) &&
            (meta.dp_eg_header.met_v == 0) && // Used as indiciation of unicast tunnel encap
            hdr.ivxlan.isValid() &&
            (hdr.ivxlan.nonce_e == 0)) { // TODO : add span transit here. we dont want to count span copies
            if (meta.eg_drop.inc_drop_counters == 1) {
                if (meta.ig_eg_header.ieth_mark == 0) {
                    //count(dst_tep_mark0_drop_stats, meta.eg_local.dst_tep_stats_idx);
                } else {
                    //count(dst_tep_mark1_drop_stats, meta.eg_local.dst_tep_stats_idx);
                }
            } else {
                if (meta.ig_eg_header.ieth_mark == 0) {
                    //count(dst_tep_mark0_total_stats, meta.eg_local.dst_tep_stats_idx);
                } else {
                    //count(dst_tep_mark1_total_stats, meta.eg_local.dst_tep_stats_idx);
                }
            }
        }
#endif /*DISABLE_DST_TEP_STATS*/
        
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // EPG_IN
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // pkt_class - drop
        // 4K EPG x 2 (drop) = 8K
        
#ifndef DISABLE_DST_BD_STATS
        
        // Total
        //count(dst_bd_stats, meta.dst_bd.bd_stats_idx);
        
        // Dropped
        if (meta.eg_drop.inc_drop_counters == 1) {
            //count(dst_bd_drop_stats, meta.dst_bd.bd_stats_idx);
        }
#endif /*DISABLE_DST_BD_STATS*/
        
    }
}


control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action read_CFG_eg_aci_tor_mode(bit<1> enable) {
        // Make the value bool so I don't have to compare it for
        // equality with 1 all over the place.
        meta.CFG_aci_tor_mode.enable = enable;
    }
    table CFG_eg_aci_tor_mode {
        key = { }
        actions = { read_CFG_eg_aci_tor_mode; }
        default_action = read_CFG_eg_aci_tor_mode(0);
    }
    @name(".set_eg_dst_bd_state")
    action set_eg_dst_bd_state(bit<10> rmac_index, bit<14> bd_label,
                               bit<1> cts_en, bit<14> bd_stats_idx,
                               //ifmbr,
//#ifdef ACI_TOR_MODE
                               bit<1> bypass_self_fwd_check,
                               bit<1> bypass_same_vtep_check, bit<16> sclass,
                               bit<14> scope,
//#else  /*ACI_TOR_MODE*/
                               bit<4> mtu_idx,
                               bit<1> l2mp_en,
                               bit<3> vft_idx,
                               bit<1> dce_bd_bypass,
                               bit<1> provider_bd,
                               bit<1> keep_inner_qtag
//#endif /*ACI_TOR_MODE*/
                               )
    {
	//meta.dst_bd.ifmbr = ifmbr;
	//meta.dst_bd.mtu_idx = mtu_idx;
        meta.dst_bd.bd_stats_idx = bd_stats_idx;
        meta.dst_bd.rmac_index = rmac_index;
        meta.dst_bd.bd_label = bd_label;
        meta.dst_bd.cts_en = cts_en;

//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            meta.dst_bd.bypass_self_fwd_check = bypass_self_fwd_check;
            meta.dst_bd.bypass_same_vtep_check = bypass_same_vtep_check;
            meta.dst_bd.sclass = sclass;
            meta.dst_bd.scope = scope;
//#else  /*ACI_TOR_MODE*/
        } else {
            meta.dst_bd.mtu_idx = mtu_idx;
            meta.dst_bd.l2mp_en = l2mp_en;
            meta.dst_bd.vft_idx = vft_idx;
            meta.dst_bd.dce_bd_bypass = dce_bd_bypass;
            meta.dst_bd.provider_bd = provider_bd;
            meta.dst_bd.keep_inner_qtag = keep_inner_qtag;
        }
//#endif /*ACI_TOR_MODE*/
    }
    @name("eg_dst_bd_state") table eg_dst_bd_state {
        actions = {
            set_eg_dst_bd_state;
            @default_only NoAction;
        }
        key = {
            meta.egress.epg_or_bd: exact;
        }
	size = DST_BD_STATE_TABLE_SIZE;
        default_action = NoAction();
        @name("eg_dst_bd_stats") counters = direct_counter(CounterType.packets);
    }

    /************************************************************************/
    /* Source Port properties */
    /************************************************************************/
    @name(".set_eg_src_port_state")
    action set_eg_src_port_state(bit<8> pcnum,
                                 //bit<8> l3if, bit<8> core_if,
                                 //bit<8> domain, bit<8> keep_inner_qtag,
                                 //bit<8> ttag_rw,
                                 //bit<8> provider_port_type,
                                 bit<1> vnic_if)
    {
        meta.eg_src_port.pcnum = pcnum;
        //meta.eg_src_port.l3if = l3if;
        //meta.eg_src_port.core_if = core_if;
        //meta.eg_src_port.domain = domain;
        //meta.eg_src_port.keep_inner_qtag = keep_inner_qtag;
        //meta.eg_src_port.ttag_rw = ttag_rw;
        //meta.eg_src_port.provider_port_type = provider_port_type;
        meta.eg_src_port.vnic_if = vnic_if;
    }
    @name("eg_src_port_state") table eg_src_port_state {
        actions = {
            set_eg_src_port_state;
            @default_only NoAction;
        }
        key = {
            meta.ig_eg_header.ieth_src_port: exact;
        }
        size = EG_SRC_PORT_STATE_TABLE_SIZE;
        default_action = NoAction();
    }

    /************************************************************************/
    /* Read MET entry */
    /************************************************************************/

    @name(".set_met_fields")
    action set_met_fields(bit<1> force_route, bit<1> force_bridge,
                          //bit<8> force_same_encap,
                          bit<1> ttl_dec_disable,
                          //bit<8> flood,
                          //bit<8> l2mc,
                          bit<14> bd,
                          bit<14> outer_bd, bit<13> ovector_idx,
                          bit<1> encap_vld, bit<14> encap_idx,
                          //bit<8> head_end_repl,
                          //bit<8> keep_ttag,
                          bit<1> fm_bridge_only,
                          //bit<8> bridge_svi,
                          //bit<8> use_bd_in,
                          //bit<8> shg,
                          //bit<8> source_addr_shg_en,
                          //bit<8> drop_if_from_core,
                          bit<1> use_bd, bit<1> use_in, bit<1> adj_vld,
                          bit<14> adj_idx, bit<14> encap_l2_idx,
//#ifdef ACI_TOR_MODE
                          //bit<8> force_same_epg,
                          //bit<8> epg_not_vld,
                          bit<14> epg,
                          //bit<8> ftag_grp,
                          bit<1> use_epg_in,
                          bit<1> epg_cross_drop, bit<1> mc_ftag_mode,
                          bit<1> service_vld,
//#endif /*ACI_TOR_MODE*/
                          bit<1> same_if_check_bypass)
    {
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            //meta.met.force_same_epg = force_same_epg;
            //meta.met.epg_not_vld = epg_not_vld;
            meta.met.epg_cross_drop = epg_cross_drop;
            meta.met.mc_ftag_mode = mc_ftag_mode;
            meta.met.epg = epg;
            meta.met.use_epg_in = use_epg_in;
            //meta.met.ftag_grp = ftag_grp;
            meta.met.service_vld = service_vld;
        }
//#endif /*ACI_TOR_MODE*/
        meta.met.force_route = force_route;
        meta.met.force_bridge = force_bridge;
        //meta.met.force_same_encap = force_same_encap;
        meta.met.ttl_dec_disable = ttl_dec_disable;
        //meta.met.flood = flood;
        //meta.met.l2mc = l2mc;
        meta.met.bd = bd;
        meta.met.outer_bd = outer_bd;
        meta.met.ovector_idx = ovector_idx;
        meta.met.encap_vld = encap_vld;
        meta.met.encap_idx = encap_idx;
        meta.met.encap_l2_idx = encap_l2_idx;
        //meta.met.head_end_repl = head_end_repl;
        //meta.met.keep_ttag = keep_ttag;
        meta.met.fm_bridge_only = fm_bridge_only;
        //meta.met.bridge_svi = bridge_svi;
        //meta.met.use_bd_in = use_bd_in;
        //meta.met.shg = shg;
        //meta.met.source_addr_shg_en = source_addr_shg_en;
        //meta.met.drop_if_from_core = drop_if_from_core;
        meta.met.use_bd = use_bd;
        meta.met.use_in = use_in;
        meta.met.adj_vld = adj_vld;
        meta.met.adj_idx = adj_idx;
        meta.met.same_if_check_bypass = same_if_check_bypass;
    }
    @name("met") table met {
        actions = {
            set_met_fields;
            @default_only NoAction;
        }
        key = {
            meta.dp_eg_header.met_index: exact;
        }
        size = MET_TABLE_SIZE;
        default_action = NoAction();
    }

    @name(".set_eg_outer_bd_state")
    action set_eg_outer_bd_state(bit<10> rmac_index, bit<50> ifmbr,
                                 bit<4> mtu_idx
//#ifdef ACI_TOR_MODE
                                 //bypass_self_fwd_check,
                                 //bypass_same_vtep_check
                                 //sclass,
                                 //scope
//#else  /*ACI_TOR_MODE*/
                                 ,
                                 bit<1> cts_en,
                                 bit<1> l2mp_en,
                                 bit<3> vft_idx,
                                 bit<1> dce_bd_bypass,
                                 bit<1> provider_bd
                                 //bit<1> keep_outer_qtag
//#endif /*ACI_TOR_MODE*/
                                 )
    {
        meta.outer_dst_bd.ifmbr = ifmbr;
        meta.outer_dst_bd.rmac_index = rmac_index;
        //meta.outer_dst_bd.bd_label = bd_label;
        meta.outer_dst_bd.mtu_idx = mtu_idx;

//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            //meta.outer_dst_bd.bypass_self_fwd_check = bypass_self_fwd_check;
            //meta.outer_dst_bd.bypass_same_vtep_check = bypass_same_vtep_check;
            //meta.outer_dst_bd.sclass = sclass;
            //meta.outer_dst_bd.scope = scope;
//#else  /*ACI_TOR_MODE*/
        } else {
            meta.outer_dst_bd.cts_en = cts_en;
            meta.outer_dst_bd.l2mp_en = l2mp_en;
            meta.outer_dst_bd.vft_idx = vft_idx;
            meta.outer_dst_bd.dce_bd_bypass = dce_bd_bypass;
            meta.outer_dst_bd.provider_bd = provider_bd;
            // TBD: This is the only occurrence of the string
            // 'keep_outer_qtag' in the original P4_14 code.  It is not
            // defined as a member of the outer_dst_bd_t struct.  Should
            // the following line use keep_inner_qtag instead?
            //meta.outer_dst_bd.keep_outer_qtag = keep_outer_qtag;
        }
//#endif /*ACI_TOR_MODE*/
    }
    @name("outer_dst_bd_state") table outer_dst_bd_state {
        actions = {
            set_eg_outer_bd_state;
            @default_only NoAction;
        }
        key = {
            meta.egress.outer_dst_bd: exact;
        }
        size = DST_BD_STATE_TABLE_SIZE;
        default_action = NoAction();
    }
    @name("process_eg_span_session") process_eg_span_session() process_eg_span_session_0;
    @name("process_egress_bypass") process_egress_bypass() process_egress_bypass_0;
    @name("process_remove_l2_tags") process_remove_l2_tags() process_remove_l2_tags_0;
    @name("process_tunnel_decision") process_tunnel_decision() process_tunnel_decision_0;
    @name("process_tunnel_decap_rewrite") process_tunnel_decap_rewrite() process_tunnel_decap_rewrite_0;
    @name("process_dst_port_state") process_dst_port_state() process_dst_port_state_0;
    @name("process_dst_if_state") process_dst_if_state() process_dst_if_state_0;
    @name("process_service_rewrite") process_service_rewrite() process_service_rewrite_0;
    @name("process_nat_rewrite") process_nat_rewrite() process_nat_rewrite_0;
    @name("process_egress_input_qos") process_egress_input_qos() process_egress_input_qos_0;
    @name("process_eg_dst_bd_select") process_eg_dst_bd_select() process_eg_dst_bd_select_0;
    @name("process_egress_fwd_mode") process_egress_fwd_mode() process_egress_fwd_mode_0;
    @name("process_same_bd_check") process_same_bd_check() process_same_bd_check_0;
//#ifdef ACI_TOR_MODE
    @name("process_epg_crossing_check") process_epg_crossing_check() process_epg_crossing_check_0;
//#endif /*ACI_TOR_MODE*/
    @name("process_egress_copp") process_egress_copp() process_egress_copp_0;
    @name("process_egress_qos_tcam") process_egress_qos_tcam() process_egress_qos_tcam_0;
    @name("process_sgt_derivation") process_sgt_derivation() process_sgt_derivation_0;
    @name("process_cmd_rewrite") process_cmd_rewrite() process_cmd_rewrite_0;
    @name("process_mac_rewrite") process_mac_rewrite() process_mac_rewrite_0;
    @name("process_qos_rewrite") process_qos_rewrite() process_qos_rewrite_0;
    @name("process_ttl_rewrite") process_ttl_rewrite() process_ttl_rewrite_0;
    @name("process_erspan_fields") process_erspan_fields() process_erspan_fields_0;
    @name("process_tunnel_encap_rewrite") process_tunnel_encap_rewrite() process_tunnel_encap_rewrite_0;
    @name("process_egress_vlan_xlate") process_egress_vlan_xlate() process_egress_vlan_xlate_0;
    @name("process_egress_vlan_rewrite") process_egress_vlan_rewrite() process_egress_vlan_rewrite_0;
    @name("process_outer_qos_rewrite") process_outer_qos_rewrite() process_outer_qos_rewrite_0;
    @name("process_self_fwd_check") process_self_fwd_check() process_self_fwd_check_0;
    @name("process_vntag_rewrite") process_vntag_rewrite() process_vntag_rewrite_0;
    @name("process_dst_vlan_mbr_check") process_dst_vlan_mbr_check() process_dst_vlan_mbr_check_0;
    @name("process_switchport_block") process_switchport_block() process_switchport_block_0;
    @name("process_egress_drop") process_egress_drop() process_egress_drop_0;
    @name("process_eg_stats_update") process_eg_stats_update() process_eg_stats_update_0;
#ifdef EXTRA_DEBUG
    table debug_egress_start {
        key = {
            meta.ig_eg_header.erspan_term : exact;
            meta.ig_eg_header.qinq_customer_port : exact;
            meta.ig_eg_header.tstmp : exact;
            meta.ig_eg_header.ingress_port : exact;
            meta.ig_eg_header.cap_1588 : exact;
            meta.ig_eg_header.len_type : exact;
            meta.ig_eg_header.pkt_type : exact;
            meta.ig_eg_header.vnid_use_bd : exact;
            meta.ig_eg_header.l2_fwd_mode : exact;
            meta.ig_eg_header.l3_fwd_mode : exact;
            meta.ig_eg_header.tunnel_encap : exact;
            meta.ig_eg_header.tunnel_decap : exact;
            meta.ig_eg_header.l2_tunnel_decap : exact;
            meta.ig_eg_header.ieth_fwd : exact;
            meta.ig_eg_header.aa_multihomed : exact;
            meta.ig_eg_header.encap_vld : exact;
            meta.ig_eg_header.encap_idx : exact;
            meta.ig_eg_header.encap_l2_idx : exact;
            meta.ig_eg_header.adj_vld : exact;
            meta.ig_eg_header.adj_idx : exact;
            meta.ig_eg_header.dmac : exact;
            meta.ig_eg_header.mpls_frr_fwd : exact;
            meta.ig_eg_header.mpls_frr_idx : exact;
            meta.ig_eg_header.mpls_label0_vld : exact;
            meta.ig_eg_header.mpls_label0_lbl : exact;
            meta.ig_eg_header.service_redir : exact;
            meta.ig_eg_header.nat_idx : exact;
            meta.ig_eg_header.ol_ecn : exact;
            meta.ig_eg_header.ol_udp_sp : exact;
            meta.ig_eg_header.ol_lb : exact;
            meta.ig_eg_header.ol_dl : exact;
            meta.ig_eg_header.ol_e : exact;
            meta.ig_eg_header.ol_sp : exact;
            meta.ig_eg_header.ol_dp : exact;
            meta.ig_eg_header.ol_vpath : exact;
            meta.ig_eg_header.ol_dre : exact;
            meta.ig_eg_header.ol_fb_vpath : exact;
            meta.ig_eg_header.ol_fb_metric : exact;
            meta.ig_eg_header.lat_index : exact;
            meta.ig_eg_header.lat_update : exact;
            meta.ig_eg_header.qos_map_idx : exact;
            meta.ig_eg_header.ttl_cio : exact;
            meta.ig_eg_header.ttl_coi : exact;
            meta.ig_eg_header.ecn_cio : exact;
            meta.ig_eg_header.ecn_coi : exact;
            meta.ig_eg_header.sup_code : exact;
            meta.ig_eg_header.sup_qnum : exact;
            meta.ig_eg_header.src_class : exact;
            meta.ig_eg_header.dst_class : exact;
            meta.ig_eg_header.src_epg_or_bd : exact;
            meta.ig_eg_header.dst_epg_or_bd : exact;
            meta.ig_eg_header.pif_block_type : exact;
            meta.ig_eg_header.bounce : exact;
            meta.ig_eg_header.cap_access : exact;
            meta.ig_eg_header.lat_index_msb : exact;
            meta.ig_eg_header.block_epg_crossing : exact;
            meta.ig_eg_header.nat_port : exact;
            meta.ig_eg_header.nat_type : exact;
            meta.ig_eg_header.ieth_l2_fwd_mode : exact;
            meta.ig_eg_header.ieth_l3_fwd_mode : exact;
            meta.ig_eg_header.ieth_src_idx : exact;
            meta.ig_eg_header.ieth_dst_idx : exact;
            meta.ig_eg_header.ieth_src_chip : exact;
            meta.ig_eg_header.ieth_src_port : exact;
            meta.ig_eg_header.ieth_dst_chip : exact;
            meta.ig_eg_header.ieth_dst_port : exact;
            meta.ig_eg_header.ieth_outer_bd : exact;
            meta.ig_eg_header.ieth_bd : exact;
            meta.ig_eg_header.ieth_mark : exact;
            meta.ig_eg_header.ieth_dont_lrn : exact;
            meta.ig_eg_header.ieth_span : exact;
            meta.ig_eg_header.ieth_alt_if_profile : exact;
            meta.ig_eg_header.ieth_ip_ttl_bypass : exact;
            meta.ig_eg_header.ieth_src_is_tunnel : exact;
            meta.ig_eg_header.ieth_dst_is_tunnel : exact;
            meta.ig_eg_header.ieth_sup_tx : exact;
            meta.ig_eg_header.ieth_sup_code : exact;
            meta.ig_eg_header.ieth_cos : exact;
            meta.ig_eg_header.ieth_de : exact;
            meta.ig_eg_header.ieth_tclass : exact;
            meta.ig_eg_header.ieth_vpc_df : exact;
            meta.ig_eg_header.ieth_pkt_hash : exact;
        }
        actions = { NoAction; }
        default_action = NoAction;
    }
#endif /*EXTRA_DEBUG*/
    apply {
        CFG_eg_aci_tor_mode.apply();
#ifdef EXTRA_DEBUG
        debug_egress_start.apply();
#endif /*EXTRA_DEBUG*/
        //-------------------------------------------------------------------
        // QSMT Functionality
        // -------------------------------------------------------------------
        // Assume that MET walkthrough happens somewhere else and
        // egress.met_ptr is assigned there Assume that L2 replication
        // happens somewhere else
        
        //----------------------------------------
        // Derive source port/inteface properties
        //---------------------------------------
        
        // src_chip_state - Will not implement for ACI
        // src_global_port_state
        // src_local_port_state
        // src_outer_bd_state
        // src_if_state - will not implement for ACI
        // Egress Outer BD
        
        
        // MET Lookup
        if (meta.dp_eg_header.met_v == 1) {
            met.apply();
        }

        // SPAN Session lookup
        // Assume that a valid met pointer was generated for span copies.
        process_eg_span_session_0.apply(hdr, meta, standard_metadata);

        //------------------------------------------------------------
        // Decide where the rewrite information will come from
        //------------------------------------------------------------

        if (meta.dp_eg_header.met_v == 1) {
            meta.egress.outer_dst_bd = meta.met.outer_bd;
            //meta.egress.encap_vld = met.encap_vld;
            meta.egress.encap_idx = meta.met.encap_idx;
            meta.egress.adj_vld = meta.met.adj_vld;
            meta.egress.adj_idx = meta.met.adj_idx;
            // TODO maybe_wrong_cast
            meta.eg_tunnel.encap_l2_idx = (bit<13>) meta.met.encap_l2_idx;
        } else {
            // TODO maybe_wrong_cast
            meta.egress.outer_dst_bd =
                (bit<14>) meta.ig_eg_header.ieth_outer_bd;
            //meta.egress.encap_vld = meta.ig_eg_header.encap_vld;
            meta.egress.encap_idx = meta.ig_eg_header.encap_idx;
            meta.egress.adj_vld = meta.ig_eg_header.adj_vld;
            meta.egress.adj_idx = meta.ig_eg_header.adj_idx;
            meta.eg_tunnel.encap_l2_idx = meta.ig_eg_header.encap_l2_idx;
        }

        // TODO : Bypass code
        process_egress_bypass_0.apply(hdr, meta, standard_metadata);

        //------------------------------------------------------------
        // Remove 64B internal header
        //-----------------------------------------------------------

        // Remove iETH header
        // How to do this ???

        // Remove vntag/qtag
        process_remove_l2_tags_0.apply(hdr, meta, standard_metadata);

        // Decide if tunnel encap/decap operation is needed
        process_tunnel_decision_0.apply(hdr, meta, standard_metadata);

        // Tunnel decap rewrite
        if (meta.egress.tunnel_decap == 1) {
            process_tunnel_decap_rewrite_0.apply(hdr, meta, standard_metadata);
        }

        // Ingress/Egress Port/Interface
        eg_src_port_state.apply();
        process_dst_port_state_0.apply(hdr, meta, standard_metadata);

#ifndef P4_DISABLE_FEX
        process_dst_if_state_0.apply(hdr, meta, standard_metadata);
#endif // P4_DISABLE_FEX

        //---------------------------------
        // Inner/Native packet processing
        //---------------------------------
        
        // Rewrite Adjacency table
        // -- Service/NSH Rewrite
        process_service_rewrite_0.apply(hdr, meta, standard_metadata);

        // -- FC Rewrite
        // -- ERSPAN rewrite
        // -- Openflow rewrite

#ifndef DISABLE_NAT
        process_nat_rewrite_0.apply(hdr, meta, standard_metadata);
#endif
        
        // QoS
        process_egress_input_qos_0.apply(hdr, meta, standard_metadata);

        // Egress BD/EPG Selection and same EPG/BD check
        process_eg_dst_bd_select_0.apply(hdr, meta, standard_metadata);
        eg_dst_bd_state.apply();

        // Forwarding mode update
        process_egress_fwd_mode_0.apply(hdr, meta, standard_metadata);
        process_same_bd_check_0.apply(hdr, meta, standard_metadata);
//#ifdef ACI_TOR_MODE
        if (meta.CFG_aci_tor_mode.enable == 1) {
            process_epg_crossing_check_0.apply(hdr, meta, standard_metadata);
        }
//#endif /*ACI_TOR_MODE*/

        // Egress ACLs ( PACL, VACL, QoS). Applied on exposed header
        process_egress_copp_0.apply(hdr, meta, standard_metadata);
        process_egress_qos_tcam_0.apply(hdr, meta, standard_metadata);

        //-----------------------------------------------
        // L2 rewrite
        //-----------------------------------------------
        
        // Sclass->SGT translation
        process_sgt_derivation_0.apply(hdr, meta, standard_metadata);
        process_cmd_rewrite_0.apply(hdr, meta, standard_metadata);

        // Ethernet header rewrite
        process_mac_rewrite_0.apply(hdr, meta, standard_metadata);

        // QoS/TTL rewrite
        process_qos_rewrite_0.apply(hdr, meta, standard_metadata);
        process_ttl_rewrite_0.apply(hdr, meta, standard_metadata);

        // SPAN/CPU Rewrite
        process_erspan_fields_0.apply(hdr, meta, standard_metadata);

        // Tunnel Encap rewrite
        if (meta.egress.tunnel_encap == 1) {
            process_tunnel_encap_rewrite_0.apply(hdr, meta, standard_metadata);
        }

        // CPU Rewrite
#ifndef DISABLE_LCPU_INSERTION
        process_lcpu_rewrite();
#endif /*DISABLE_LCPU_INSERION*/

        // VLAN Derivation
        outer_dst_bd_state.apply();
        process_egress_vlan_xlate_0.apply(hdr, meta, standard_metadata);
        process_egress_vlan_rewrite_0.apply(hdr, meta, standard_metadata);

        // Outer QoS rewrite
        if (meta.egress.tunnel_encap == 1) {
            process_outer_qos_rewrite_0.apply(hdr, meta, standard_metadata);
        }

        // Self-forwarding check
        process_self_fwd_check_0.apply(hdr, meta, standard_metadata);

#ifndef P4_DISABLE_FEX
        // VNTAG Derivation
        process_vntag_rewrite_0.apply(hdr, meta, standard_metadata);
#endif
        
        // CBL Check
        process_dst_vlan_mbr_check_0.apply(hdr, meta, standard_metadata);

        // Policers
        process_switchport_block_0.apply(hdr, meta, standard_metadata);

        // Final QoS rewrite

        // LCPU Header Insertion

        // ERSPAN

        // iETH Header insertion

        // Latency Measurement

        process_egress_drop_0.apply(hdr, meta, standard_metadata);

        // Stats
        process_eg_stats_update_0.apply(hdr, meta, standard_metadata);
    }
}

// TODO : lcpu, erspan, qinq, ttag, snap??, 
