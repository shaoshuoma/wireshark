/* packet-gtpv2.c
 *
 * Routines for GTPv2 dissection
 * Copyright 2009 - 2021, Anders Broman <anders.broman [at] ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: 3GPP TS 29.274 V18.7.0 (2024-06-26)
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/to_str.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>
#include <epan/addr_resolv.h>
#include <epan/tap.h>
#include <epan/srt_table.h>
#include <epan/tfs.h>
#include <proto.h>
#include <unit_strings.h>

#include "packet-gsm_a_common.h"
#include "packet-gsm_map.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-s1ap.h"
#include "packet-ranap.h"
#include "packet-bssgp.h"
#include "packet-ngap.h"
#include "packet-gtpv2.h"
#include "packet-radius.h"
#include "packet-diameter.h"
#include "packet-diameter_3gpp.h"
#include "packet-ip.h"
#include "packet-http2.h"

void proto_register_gtpv2(void);
void proto_reg_handoff_gtpv2(void);

static dissector_handle_t nas_eps_handle;
static dissector_table_t gtpv2_priv_ext_dissector_table;


/*GTPv2 Message->GTP Header(SB)*/
static int proto_gtpv2;

static int hf_gtpv2_response_in;
static int hf_gtpv2_response_to;
static int hf_gtpv2_response_time;
static int hf_gtpv2_spare_half_octet;
//static int hf_gtpv2_spare_b7_b1;
static int hf_gtpv2_spare_b7_b2;
static int hf_gtpv2_spare_b7_b3;
static int hf_gtpv2_spare_b7_b4;
static int hf_gtpv2_spare_b7_b5;

static int hf_gtpv2_spare_bits;
static int hf_gtpv2_flags;
static int hf_gtpv2_version;
static int hf_gtpv2_p;
static int hf_gtpv2_t;
static int hf_gtpv2_mp;
static int hf_gtpv2_message_type;
static int hf_gtpv2_msg_length;
static int hf_gtpv2_teid;
static int hf_gtpv2_seq;
static int hf_gtpv2_msg_prio;
static int hf_gtpv2_spare;
static int hf_gtpv2_spare_w0;

static int hf_gtpv2_ie;
static int hf_gtpv2_ie_len;
static int hf_gtpv2_cr;
static int hf_gtpv2_instance;
static int hf_gtpv2_cause;
static int hf_gtpv2_cause_cs;
static int hf_gtpv2_cause_bce;
static int hf_gtpv2_cause_pce;
static int hf_gtpv2_cause_off_ie_t;
static int hf_gtpv2_rec;
/*Start SRVCC Messages*/
static int hf_gtpv2_stn_sr;
static int hf_gtpv2_len_trans_con;
static int hf_gtpv2_eksi;
static int hf_gtpv2_ck;
static int hf_gtpv2_ik;
static int hf_gtpv2_len_ms_classmark2;
static int hf_gtpv2_len_ms_classmark3;
static int hf_gtpv2_len_supp_codec_list;
static int hf_gtpv2_ksi;
/*static int hf_gtpv2_kc; */
static int hf_gtpv2_cksn;
static int hf_gtpv2_srvcc_cause;
static int hf_gtpv2_rac;
static int hf_gtpv2_rnc_id;
static int hf_gtpv2_ext_rnc_id;
static int hf_gtpv2_lac;
static int hf_gtpv2_sac;
static int hf_gtpv2_tgt_g_cell_id;
static int hf_gtpv2_teid_c;
static int hf_gtpv2_sv_sti;
static int hf_gtpv2_sv_ics;
static int hf_gtpv2_sv_emind;
/*End SRVCC Messages*/
static int hf_gtpv2_apn;
static int hf_gtpv2_ebi;
static int hf_gtpv2_daf;
static int hf_gtpv2_dtf;
static int hf_gtpv2_hi;
static int hf_gtpv2_dfi;
static int hf_gtpv2_oi;
static int hf_gtpv2_isrsi;
static int hf_gtpv2_israi;
static int hf_gtpv2_sgwci;
static int hf_gtpv2_sqci;
static int hf_gtpv2_uimsi;
static int hf_gtpv2_cfsi;
static int hf_gtpv2_crsi;
static int hf_gtpv2_pt;
static int hf_gtpv2_ps;
static int hf_gtpv2_si;
static int hf_gtpv2_msv;
static int hf_gtpv2_retloc;
static int hf_gtpv2_pbic;
static int hf_gtpv2_srni;
static int hf_gtpv2_s6af;
static int hf_gtpv2_s4af;
static int hf_gtpv2_mbmdt;
static int hf_gtpv2_israu;
static int hf_gtpv2_ccrsi;
static int hf_gtpv2_cprai;
static int hf_gtpv2_arrl;
static int hf_gtpv2_ppof;
static int hf_gtpv2_ppon_ppei;
static int hf_gtpv2_ppsi;
static int hf_gtpv2_csfbi;
static int hf_gtpv2_clii;
static int hf_gtpv2_cpsr;
static int hf_gtpv2_nsi;
static int hf_gtpv2_uasi;
static int hf_gtpv2_dtci;
static int hf_gtpv2_bdwi;
static int hf_gtpv2_psci;
static int hf_gtpv2_pcri;
static int hf_gtpv2_aosi;
static int hf_gtpv2_aopi;
static int hf_gtpv2_roaai;
static int hf_gtpv2_epcosi;
static int hf_gtpv2_cpopci;
static int hf_gtpv2_pmtsmi;
static int hf_gtpv2_s11tf;
static int hf_gtpv2_pnsi;
static int hf_gtpv2_unaccsi;
static int hf_gtpv2_wpmsi;

static int hf_gtpv2_5gsnn26;
static int hf_gtpv2_reprefi;
static int hf_gtpv2_5gsiwk;
static int hf_gtpv2_eevrsi;
static int hf_gtpv2_ltemui;
static int hf_gtpv2_ltempi;
static int hf_gtpv2_enbcrsi;
static int hf_gtpv2_tspcmi;
static int hf_gtpv2_ethpdn;

static int hf_gtpv2_csrmfi;
static int hf_gtpv2_mtedtn;
static int hf_gtpv2_mtedta;
static int hf_gtpv2_n5gnmi;
static int hf_gtpv2_5gcnrs;
static int hf_gtpv2_5gcnri;
static int hf_gtpv2_5srhoi;

static int hf_gtpv2_nspusi;
static int hf_gtpv2_pgwrnsi;
static int hf_gtpv2_rppcsi;
static int hf_gtpv2_pgwchi;
static int hf_gtpv2_sissme;
static int hf_gtpv2_nsenbi;
static int hf_gtpv2_idfupf;
static int hf_gtpv2_emci;

static int hf_gtpv2_lapcosi;
static int hf_gtpv2_ltemsai;
static int hf_gtpv2_srtpi;
static int hf_gtpv2_upipsi;

static int hf_gtpv2_pdn_type;
static int hf_gtpv2_pdn_ipv4;
static int hf_gtpv2_pdn_ipv6_len;
static int hf_gtpv2_pdn_ipv6;
static int hf_gtpv2_pdn_numbers_nsapi;
static int hf_gtpv2_p_tmsi;
static int hf_gtpv2_p_tmsi_sig;
static int hf_gtpv2_mmbr_ul;
static int hf_gtpv2_mmbr_dl;

static int hf_gtpv2_rat_type;
static int hf_gtpv2_uli_ext_macro_enb_id_flg;
static int hf_gtpv2_uli_macro_enb_id_flg;
static int hf_gtpv2_uli_lai_flg;
static int hf_gtpv2_uli_ecgi_flg;
static int hf_gtpv2_uli_tai_flg;
static int hf_gtpv2_uli_rai_flg;
static int hf_gtpv2_uli_sai_flg;
static int hf_gtpv2_uli_cgi_flg;
static int hf_gtpv2_glt;
static int hf_gtpv2_cng_rep_act;

static int hf_gtpv2_selec_mode;
static int hf_gtpv2_source_type;
static int hf_gtpv2_f_teid_v4;
static int hf_gtpv2_f_teid_v6;
static int hf_gtpv2_f_teid_interface_type;
static int hf_gtpv2_f_teid_gre_key;
static int hf_gtpv2_f_teid_ipv4;
static int hf_gtpv2_f_teid_ipv6;
static int hf_gtpv2_tmsi;
static int hf_gtpv2_hsgw_addr_f_len;
static int hf_gtpv2_hsgw_addr_ipv4;
static int hf_gtpv2_hsgw_addr_ipv6;
static int hf_gtpv2_gre_key;
static int hf_gtpv2_sgw_addr_ipv4;
static int hf_gtpv2_sgw_addr_ipv6;
static int hf_gtpv2_sgw_s1u_teid;
static int hf_gtpv2_ipv4_addr;


static int hf_gtpv2_ambr_up;
static int hf_gtpv2_ambr_down;
static int hf_gtpv2_ip_address_ipv4;
static int hf_gtpv2_ip_address_ipv6;
static int hf_gtpv2_mei;

/* Trace Information */
/* static int hf_gtpv2_tra_info; */
static int hf_gtpv2_tra_info_msc_momt_calls;
static int hf_gtpv2_tra_info_msc_momt_sms;
static int hf_gtpv2_tra_info_msc_lu_imsi_ad;
static int hf_gtpv2_tra_info_msc_handovers;
static int hf_gtpv2_tra_info_msc_ss;
static int hf_gtpv2_tra_info_mgw_context;
static int hf_gtpv2_tra_info_sgsn_pdp_context;
static int hf_gtpv2_tra_info_sgsn_momt_sms;
static int hf_gtpv2_tra_info_sgsn_rau_gprs_ad;
static int hf_gtpv2_tra_info_sgsn_mbms;
static int hf_gtpv2_tra_info_sgsn_reserved;
static int hf_gtpv2_tra_info_ggsn_pdp;
static int hf_gtpv2_tra_info_ggsn_mbms;
static int hf_gtpv2_tra_info_bm_sc;
static int hf_gtpv2_tra_info_mme_sgw_ss;
static int hf_gtpv2_tra_info_mme_sgw_sr;
static int hf_gtpv2_tra_info_mme_sgw_iataud;
static int hf_gtpv2_tra_info_mme_sgw_ue_init_pdn_disc;
static int hf_gtpv2_tra_info_mme_sgw_bearer_act_mod_del;
static int hf_gtpv2_tra_info_mme_sgw_ho;
static int hf_gtpv2_tra_info_sgw_pdn_con_creat;
static int hf_gtpv2_tra_info_sgw_pdn_con_term;
static int hf_gtpv2_tra_info_sgw_bearer_act_mod_del;
static int hf_gtpv2_tra_info_pgw_pdn_con_creat;
static int hf_gtpv2_tra_info_pgw_pdn_con_term;
static int hf_gtpv2_tra_info_pgw_bearer_act_mod_del;
static int hf_gtpv2_tra_info_lne_msc_s;
static int hf_gtpv2_tra_info_lne_mgw;
static int hf_gtpv2_tra_info_lne_sgsn;
static int hf_gtpv2_tra_info_lne_ggsn;
static int hf_gtpv2_tra_info_lne_rnc;
static int hf_gtpv2_tra_info_lne_bm_sc;
static int hf_gtpv2_tra_info_lne_mme;
static int hf_gtpv2_tra_info_lne_sgw;
static int hf_gtpv2_tra_info_lne_pdn_gw;
static int hf_gtpv2_tra_info_lne_enb;
static int hf_gtpv2_tra_info_lne_amf;
static int hf_gtpv2_tra_info_lne_smf;
static int hf_gtpv2_tra_info_lne_pcf;
static int hf_gtpv2_tra_info_lne_upf;
static int hf_gtpv2_tra_info_tra_info_ng_ran_node;
static int hf_gtpv2_tra_info_tdl;
static int hf_gtpv2_tra_info_lmsc_a;
static int hf_gtpv2_tra_info_lmsc_lu;
static int hf_gtpv2_tra_info_lmsc_mc;
static int hf_gtpv2_tra_info_lmsc_map_g;
static int hf_gtpv2_tra_info_lmsc_map_b;
static int hf_gtpv2_tra_info_lmsc_map_e;
static int hf_gtpv2_tra_info_lmsc_map_f;
static int hf_gtpv2_tra_info_lmsc_cap;
static int hf_gtpv2_tra_info_lmsc_map_d;
static int hf_gtpv2_tra_info_lmsc_map_c;
static int hf_gtpv2_tra_info_lmgw_mc;
static int hf_gtpv2_tra_info_lmgw_nb_up;
static int hf_gtpv2_tra_info_lmgw_lu_up;
static int hf_gtpv2_tra_info_lsgsn_gb;
static int hf_gtpv2_tra_info_lsgsn_lu;
static int hf_gtpv2_tra_info_lsgsn_gn;
static int hf_gtpv2_tra_info_lsgsn_map_gr;
static int hf_gtpv2_tra_info_lsgsn_map_gd;
static int hf_gtpv2_tra_info_lsgsn_map_gf;
static int hf_gtpv2_tra_info_lsgsn_gs;
static int hf_gtpv2_tra_info_lsgsn_ge;
static int hf_gtpv2_tra_info_lggsn_gn;
static int hf_gtpv2_tra_info_lggsn_gi;
static int hf_gtpv2_tra_info_lggsn_gmb;
static int hf_gtpv2_tra_info_lrnc_lu;
static int hf_gtpv2_tra_info_lrnc_lur;
static int hf_gtpv2_tra_info_lrnc_lub;
static int hf_gtpv2_tra_info_lrnc_uu;
static int hf_gtpv2_tra_info_lbm_sc_gmb;
static int hf_gtpv2_tra_info_lmme_s1_mme;
static int hf_gtpv2_tra_info_lmme_s3;
static int hf_gtpv2_tra_info_lmme_s6a;
static int hf_gtpv2_tra_info_lmme_s10;
static int hf_gtpv2_tra_info_lmme_s11;
static int hf_gtpv2_tra_info_lsgw_s4;
static int hf_gtpv2_tra_info_lsgw_s5;
static int hf_gtpv2_tra_info_lsgw_s8b;
static int hf_gtpv2_tra_info_lsgw_s11;
static int hf_gtpv2_tra_info_lpdn_gw_s2a;
static int hf_gtpv2_tra_info_lpdn_gw_s2b;
static int hf_gtpv2_tra_info_lpdn_gw_s2c;
static int hf_gtpv2_tra_info_lpdn_gw_s5;
static int hf_gtpv2_tra_info_lpdn_gw_s6c;
static int hf_gtpv2_tra_info_lpdn_gw_gx;
static int hf_gtpv2_tra_info_lpdn_gw_s8b;
static int hf_gtpv2_tra_info_lpdn_gw_sgi;
static int hf_gtpv2_tra_info_lenb_s1_mme;
static int hf_gtpv2_tra_info_lenb_x2;
static int hf_gtpv2_tra_info_lenb_uu;

static int hf_gtpv2_ti;

static int hf_gtpv2_bearer_qos_pci;
static int hf_gtpv2_bearer_qos_pl;
static int hf_gtpv2_bearer_qos_pvi;
static int hf_gtpv2_bearer_qos_label_qci;
static int hf_gtpv2_bearer_qos_mbr_up;
static int hf_gtpv2_bearer_qos_mbr_down;
static int hf_gtpv2_bearer_qos_gbr_up;
static int hf_gtpv2_bearer_qos_gbr_down;
static int hf_gtpv2_flow_qos_label_qci;
static int hf_gtpv2_flow_qos_mbr_up;
static int hf_gtpv2_flow_qos_mbr_down;
static int hf_gtpv2_flow_qos_gbr_up;
static int hf_gtpv2_flow_qos_gbr_down;

static int hf_gtpv2_delay_value;
static int hf_gtpv2_charging_id;
static int hf_gtpv2_charging_characteristic;
static int hf_gtpv2_bearer_flag_ppc;
static int hf_gtpv2_bearer_flag_vb;
static int hf_gtpv2_ue_time_zone_dst;
static int hf_gtpv2_fq_csid_type;
static int hf_gtpv2_fq_csid_nr;
static int hf_gtpv2_fq_csid_ipv4;
static int hf_gtpv2_fq_csid_ipv6;
static int hf_gtpv2_fq_csid_id;
static int hf_gtpv2_complete_req_msg_type;
static int hf_gtpv2_mme_grp_id;
static int hf_gtpv2_mme_code;
static int hf_gtpv2_m_tmsi;
static int hf_gtpv2_container_type;
static int hf_gtpv2_cause_type;
static int hf_gtpv2_CauseRadioNetwork;
static int hf_gtpv2_CauseTransport;
static int hf_gtpv2_CauseNas;
static int hf_gtpv2_CauseProtocol;
static int hf_gtpv2_CauseMisc;
static int hf_gtpv2_target_type;
static int hf_gtpv2_macro_enodeb_id;
static int hf_gtpv2_smenb;
static int hf_gtpv2_ext_macro_enodeb_id;
static int hf_gtpv2_ext_macro_ng_enodeb_id;
static int hf_gtpv2_enodebid;
static int hf_gtpv2_cellid;

static int hf_gtpv2_node_type;
static int hf_gtpv2_fqdn;
static int hf_gtpv2_enterprise_id;
static int hf_gtpv2_apn_rest;
static int hf_gtpv2_pti;
static int hf_gtpv2_mm_context_sm;
static int hf_gtpv2_mm_context_nhi;
static int hf_gtpv2_mm_context_drxi;
static int hf_gtpv2_mm_context_cksn;
static int hf_gtpv2_mm_context_cksn_ksi;
static int hf_gtpv2_mm_context_kasme;
static int hf_gtpv2_mm_context_rand;
static int hf_gtpv2_mm_context_xres_len;
static int hf_gtpv2_mm_context_xres;
static int hf_gtpv2_mm_context_autn_len;
static int hf_gtpv2_mm_context_autn;
static int hf_gtpv2_mm_context_drx;
static int hf_gtpv2_mm_context_ue_net_cap_len;
static int hf_gtpv2_mm_context_ms_net_cap_len;
static int hf_gtpv2_mm_context_mei_len;
static int hf_gtpv2_mm_context_vdp_len;
static int hf_gtpv2_mm_contex_nhi_old;
static int hf_gtpv2_mm_context_old_ksiasme;
static int hf_gtpv2_mm_context_old_ncc;
static int hf_gtpv2_mm_context_old_kasme;
static int hf_gtpv2_mm_context_old_nh;
static int hf_gtpv2_mm_context_higher_br_16mb_flg_len;
static int hf_gtpv2_mm_context_higher_br_16mb_flg;
static int hf_gtpv2_vdp_length;
static int hf_gtpv2_mm_context_paging_len;
static int hf_gtpv2_mm_context_ex_access_res_data_len;
static int hf_gtpv2_mm_context_ue_add_sec_cap_len;
static int hf_gtpv2_mm_context_ue_nr_sec_cap_len;
static int hf_gtpv2_mm_context_apn_rte_ctrl_sts_len;
static int hf_gtpv2_mm_context_cnr_len;
static int hf_gtpv2_mm_context_ue_radio_cap_len;
static int hf_gtpv2_uci_csg_id;
static int hf_gtpv2_uci_csg_id_spare;
static int hf_gtpv2_uci_access_mode;
static int hf_gtpv2_uci_lcsg;
static int hf_gtpv2_uci_csg_membership;

static int hf_gtpv2_una;
static int hf_gtpv2_gena;
static int hf_gtpv2_gana;
static int hf_gtpv2_ina;
static int hf_gtpv2_ena;
static int hf_gtpv2_hnna;
static int hf_gtpv2_hbna;
static int hf_gtpv2_mm_context_ksi_a;
static int hf_gtpv2_mm_context_ksi;
static int hf_gtpv2_mm_context_nr_tri;
static int hf_gtpv2_mm_context_used_cipher;
static int hf_gtpv2_mm_context_nr_qui;
static int hf_gtpv2_mm_context_nr_qua;
static int hf_gtpv2_mm_context_uamb_ri;
static int hf_gtpv2_mm_context_osci;
static int hf_gtpv2_mm_context_nruna;
static int hf_gtpv2_mm_context_nrusrna;
static int hf_gtpv2_mm_context_nrna;
static int hf_gtpv2_mm_context_ussrna;
static int hf_gtpv2_mm_context_nrsrna;
static int hf_gtpv2_mm_context_ensct;

static int hf_gtpv2_mm_context_samb_ri;
static int hf_gtpv2_mm_context_unipa;
static int hf_gtpv2_mm_context_unc;
static int hf_gtpv2_mm_context_nas_dl_cnt;
static int hf_gtpv2_mm_context_nas_ul_cnt;

static int hf_gtpv2_uli_cgi_lac;
static int hf_gtpv2_uli_cgi_ci;
static int hf_gtpv2_sai_lac;
static int hf_gtpv2_sai_sac;
static int hf_gtpv2_rai_lac;
static int hf_gtpv2_rai_rac;
static int hf_gtpv2_tai_tac;
static int hf_gtpv2_5gs_tai_tac;
static int hf_gtpv2_ecgi_eci;
static int hf_gtpv2_ncgi_nrci;
static int hf_gtpv2_uli_lai_lac;
static int hf_gtpv2_ecgi_eci_spare;
static int hf_gtpv2_nsapi;
static int hf_gtpv2_bearer_control_mode;

static int hf_gtpv2_bss_container_phx;
static int hf_gtpv2_bss_con_sapi_flg;
static int hf_gtpv2_bss_con_rp_flg;
static int hf_gtpv2_bss_con_pfi_flg;
static int hf_gtpv2_bss_con_pfi;
static int hf_gtpv2_bss_con_rp;
static int hf_gtpv2_bss_con_sapi;
static int hf_gtpv2_bss_con_xid_len;
static int hf_gtpv2_bss_con_xid;
static int hf_gtpv2_home_enodeb_id;
static int hf_gtpv2_tac;

/* MBMS */
static int hf_gtpv2_mbms_service_area_nr;
static int hf_gtpv2_mbms_service_area_id;
static int hf_gtpv2_mbms_session_id;
static int hf_gtpv2_mbms_flow_id;
static int hf_gtpv2_cteid;
static int hf_gtpv2_ip_addr_type;
static int hf_gtpv2_ip_addr_len;
static int hf_gtpv2_mbms_ip_mc_dist_addrv4;
static int hf_gtpv2_mbms_ip_mc_dist_addrv6;
static int hf_gtpv2_mbms_ip_mc_src_addrv4;
static int hf_gtpv2_mbms_ip_mc_src_addrv6;
static int hf_gtpv2_mbms_hc_indicator;
static int hf_gtpv2_mbms_dist_indication;
static int hf_gtpv2_subscriber_rfsp;
static int hf_gtpv2_rfsp_inuse;
static int hf_gtpv2_mbms_service_id;
static int hf_gtpv2_add_flags_for_srvcc_ics;
static int hf_gtpv2_vsrvcc_flag;
static int hf_gtpv2_abs_time_mbms_data;
static int hf_gtpv2_henb_info_report_fti;
static int hf_gtpv2_ip4cp_subnet_prefix_len;
static int hf_gtpv2_ip4cp_ipv4;
static int hf_gtpv2_change_report_flags_sncr;
static int hf_gtpv2_change_report_flags_tzcr;
static int hf_gtpv2_action_indication_val;
static int hf_gtpv2_uli_timestamp;
static int hf_gtpv2_mbms_session_duration_days;
static int hf_gtpv2_mbms_session_duration_secs;
static int hf_gtpv2_csg_id;
static int hf_gtpv2_cmi;
static int hf_gtpv2_service_indicator;
static int hf_gtpv2_detach_type;
static int hf_gtpv2_ldn;
static int hf_gtpv2_node_features_prn;
static int hf_gtpv2_node_features_mabr;
static int hf_gtpv2_node_features_ntsr;
static int hf_gtpv2_node_features_ciot;
static int hf_gtpv2_node_features_s1un;
static int hf_gtpv2_node_features_eth;
static int hf_gtpv2_node_features_mtedt;
static int hf_gtpv2_node_features_psset;
static int hf_gtpv2_time_to_data_xfer;
static int hf_gtpv2_arp_pvi;
static int hf_gtpv2_arp_pl;
static int hf_gtpv2_arp_pci;
static int hf_gtpv2_timer_unit;
static int hf_gtpv2_throttling_delay_unit;
static int hf_gtpv2_throttling_delay_value;
static int hf_gtpv2_timer_value;
static int hf_gtpv2_lapi;

static int hf_gtpv2_pres_rep_area_act_inapra;
static int hf_gtpv2_pres_rep_area_action;
static int hf_gtpv2_pres_rep_area_id;
static int hf_gtpv2_pres_rep_area_act_no_tai;
static int hf_gtpv2_pres_rep_area_act_no_rai;
static int hf_gtpv2_pres_rep_area_act_no_m_enodeb;
static int hf_gtpv2_pres_rep_area_act_no_h_enodeb;
static int hf_gtpv2_pres_rep_area_act_no_ecgi;
static int hf_gtpv2_pres_rep_area_act_no_sai;
static int hf_gtpv2_pres_rep_area_act_no_cgi;
static int hf_gtpv2_pres_rep_area_act_no_ext_m_enodeb;
static int hf_gtpv2_ksi_ps;
static int hf_gtpv2_ck_ps;
static int hf_gtpv2_ik_ps;
static int hf_gtpv2_kc_ps;
static int hf_gtpv2_cksn_ps;

static int hf_gtpv2_pres_rep_area_info_id;
static int hf_gtpv2_pres_rep_area_info_additional_id;
static int hf_gtpv2_pres_rep_area_info_flags;
static int hf_gtpv2_pres_rep_area_info_flags_no_inapra;
static int hf_gtpv2_pres_rep_area_info_flags_b4_b7_spare;
static int hf_gtpv2_pres_rep_area_info_flags_b3_b7_spare;
static int hf_gtpv2_pres_rep_area_info_flags_b3_inapra;
static int hf_gtpv2_pres_rep_area_info_flags_b2_apra;
static int hf_gtpv2_pres_rep_area_info_flags_b1_opra;
static int hf_gtpv2_pres_rep_area_info_flags_b0_ipra;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_gtpv2_downlink_subscribed_ue_ambr;
static int hf_gtpv2_mm_context_sres;
static int hf_gtpv2_iksrvcc;
static int hf_gtpv2_nsapi08;
static int hf_gtpv2_voice_domain_and_ue_usage_setting;
static int hf_gtpv2_ue_radio_capability_for_paging_information;
static int hf_gtpv2_port_number;
static int hf_gtpv2_uplink_used_ue_ambr;
static int hf_gtpv2_tmsi_bytes;
static int hf_gtpv2_dl_gtp_u_sequence_number;
static int hf_gtpv2_mm_context_nh;
static int hf_gtpv2_teid_c_spare;
static int hf_gtpv2_uplink_subscribed_ue_ambr;
static int hf_gtpv2_transparent_container;
static int hf_gtpv2_packet_flow_id;
static int hf_gtpv2_utran_srvcc_ik_cs;
static int hf_gtpv2_downlink_used_ue_ambr;
static int hf_gtpv2_hop_counter;
static int hf_gtpv2_ul_gtp_u_sequence_number;
static int hf_gtpv2_authentication_quadruplets;
static int hf_gtpv2_utran_srvcc_kc;
static int hf_gtpv2_spare_bytes;
static int hf_gtpv2_metric;
static int hf_gtpv2_throttling_factor;
static int hf_gtpv2_relative_capacity;
static int hf_gtpv2_apn_length;
static int hf_gtpv2_sequence_number;
static int hf_gtpv2_receive_n_pdu_number;
static int hf_gtpv2_trace_id;
static int hf_gtpv2_drx_parameter;
static int hf_gtpv2_charging_characteristic_remaining_octets;
static int hf_gtpv2_mm_context_ncc;
static int hf_gtpv2_proprietary_value;
static int hf_gtpv2_mobile_station_classmark2;
static int hf_gtpv2_rrc_container;
static int hf_gtpv2_send_n_pdu_number;
static int hf_gtpv2_mobile_station_classmark3;
static int hf_gtpv2_eps_bearer_id_number;
static int hf_gtpv2_geographic_location;
static int hf_gtpv2_cn_id;
static int hf_gtpv2_utran_srvcc_ck_cs;
static int hf_gtpv2_authentication_quintuplets;
static int hf_gtpv2_serving_gw_address_length;
static int hf_gtpv2_supported_codec_list;
static int hf_gtpv2_cksrvcc;
static int hf_gtpv2_mm_context_kc;
static int hf_gtpv2_dl_pdcp_sequence_number;
static int hf_gtpv2_ul_pdcp_sequence_number;
static int hf_gtpv2_fq_csid_node_id;
static int hf_gtpv2_fq_csid_mcc_mnc;
static int hf_gtpv2_ppi_value;
static int hf_gtpv2_ppi_flag;
static int hf_gtpv2_session;
static int hf_gtpv2_twan_id_ts;
static int hf_gtpv2_twan_flags;
static int hf_gtpv2_twan_bssidi;
static int hf_gtpv2_twan_civai;
static int hf_gtpv2_twan_plmni;
static int hf_gtpv2_twan_opnai;
static int hf_gtpv2_twan_laii;
static int hf_gtpv2_twan_ssid_len;
static int hf_gtpv2_twan_ssid;
static int hf_gtpv2_twan_bssid;
static int hf_gtpv2_twan_civa_len;
static int hf_gtpv2_twan_civa;
static int hf_gtpv2_twan_plmnid;
static int hf_gtpv2_twan_op_name_len;
static int hf_gtpv2_twan_op_name;
static int hf_gtpv2_twan_relay_id_type;
static int hf_gtpv2_twan_relay_id_len;
static int hf_gtpv2_twan_relay_id;
static int hf_gtpv2_twan_relay_id_ipv4;
static int hf_gtpv2_twan_relay_id_ipv6;
static int hf_gtpv2_twan_circuit_id_len;
static int hf_gtpv2_twan_circuit_id;
static int hf_gtpv2_integer_number_val;
static int hf_gtpv2_maximum_wait_time;
static int hf_gtpv2_dl_buf_sug_pkt_cnt;
static int hf_gtpv2_ue_usage_type;
static int hf_gtpv2_rem_run_serv_gap_t;
static int hf_gtpv2_ran_nas_protocol_type;
static int hf_gtpv2_ran_nas_cause_type;
static int hf_gtpv2_ran_nas_cause_value;
static int hf_gtpv2_emm_cause;
static int hf_gtpv2_esm_cause;
static int hf_gtpv2_diameter_cause;
static int hf_gtpv2_ikev2_cause;

static int hf_gtpv2_ciot_support_ind;
static int hf_gtpv2_ciot_support_ind_spare_bits;
static int hf_gtpv2_ciot_support_ind_bit4;
static int hf_gtpv2_ciot_support_ind_bit3;
static int hf_gtpv2_ciot_support_ind_bit2;
static int hf_gtpv2_ciot_support_ind_bit1;

static int hf_gtpv2_length_of_node_name;
static int hf_gtpv2_node_name;
static int hf_gtpv2_length_of_node_realm;
static int hf_gtpv2_node_realm;
static int hf_gtpv2_ms_ts;
static int hf_gtpv2_origination_ts;
static int hf_gtpv2_mon_event_inf_nsur;
static int hf_gtpv2_mon_event_inf_nsui;
static int hf_gtpv2_mon_event_inf_nscf;
static int hf_gtpv2_mon_event_inf_srie;
static int hf_gtpv2_mon_event_inf_scef_reference_id;
static int hf_gtpv2_mon_event_inf_scef_reference_id_ext;
static int hf_gtpv2_mon_event_inf_scef_id_length;
static int hf_gtpv2_mon_event_inf_scef_id;
static int hf_gtpv2_mon_event_inf_remaining_number_of_reports;
static int hf_gtpv2_mon_event_ext_inf_lrtp;
static int hf_gtpv2_mon_event_ext_inf_srie;
static int hf_gtpv2_mon_event_ext_inf_scef_reference_id;
static int hf_gtpv2_mon_event_ext_inf_scef_id_length;
static int hf_gtpv2_mon_event_ext_inf_scef_id;
static int hf_gtpv2_mon_event_ext_inf_remain_min_period_loc_report_type;
static int hf_gtpv2_mon_event_ext_inf_scef_reference_id_ext;
static int hf_gtpv2_rohc_profiles_bit0;
static int hf_gtpv2_rohc_profiles_bit1;
static int hf_gtpv2_rohc_profiles_bit2;
static int hf_gtpv2_rohc_profiles_bit3;
static int hf_gtpv2_rohc_profiles_bit4;
static int hf_gtpv2_rohc_profiles_bit5;
static int hf_gtpv2_rohc_profiles_bit6;
static int hf_gtpv2_rohc_profiles_bit7;
static int hf_gtpv2_max_cid;
static int hf_gtpv2_uplink_rate_limit;
static int hf_gtpv2_downlink_rate_limit;
static int hf_gtpv2_timestamp_value;
static int hf_gtpv2_counter_value;
static int hf_gtpv2_mapped_ue_usage_type;
static int hf_gtpv2_uli_flags;
static int hf_gtpv2_rohc_profile_flags;
static int hf_gtpv2_dcnr;

static int hf_gtpv2_secondary_rat_usage_data_report;
static int hf_gtpv2_secondary_rat_usage_data_report_spare_bits;
static int hf_gtpv2_secondary_rat_usage_data_report_bit3;
static int hf_gtpv2_secondary_rat_usage_data_report_bit2;
static int hf_gtpv2_secondary_rat_usage_data_report_bit1;
static int hf_gtpv2_secondary_rat_usage_data_report_rat_type;
static int hf_gtpv2_secondary_rat_usage_data_report_start_timestamp;
static int hf_gtpv2_secondary_rat_usage_data_report_end_timestamp;
static int hf_gtpv2_secondary_rat_usage_data_report_usage_data_dl;
static int hf_gtpv2_secondary_rat_usage_data_report_usage_data_ul;
static int hf_gtpv2_secondary_rat_usage_data_report_srudn_length;
static int hf_gtpv2_secondary_rat_usage_data_report_srudn_value;
static int hf_gtpv2_csg_info_rep_action_b0;
static int hf_gtpv2_csg_info_rep_action_b1;
static int hf_gtpv2_csg_info_rep_action_b2;
static int hf_gtpv2_gnodeb_id_len;
static int hf_gtpv2_gnodeb_id;
static int hf_gtpv2_macro_ng_enodeb_id;
static int hf_gtpv2_5gs_tac;
static int hf_gtpv2_en_gnb_id_len;
static int hf_gtpv2_5tac;
static int hf_gtpv2_etac;
static int hf_gtpv2_en_gnb_id;
static int hf_gtpv2_trig_event_len;
static int hf_gtpv2_ne_list_len;
static int hf_gtpv2_ses_trs_depth;
static int hf_gtpv2_list_of_if_len;
static int hf_gtpv2_trs_coll_ip_addr_len;
static int hf_gtpv2_trs_coll_ipv4_addr;
static int hf_gtpv2_trs_coll_ipv6_addr;

static int hf_gtpv2_ext_tra_info_loi_mscs_cap;
static int hf_gtpv2_ext_tra_info_loi_mscs_map_f;
static int hf_gtpv2_ext_tra_info_loi_mscs_map_e;
static int hf_gtpv2_ext_tra_info_loi_mscs_map_b;
static int hf_gtpv2_ext_tra_info_loi_mscs_map_g;
static int hf_gtpv2_ext_tra_info_loi_mscs_mc;
static int hf_gtpv2_ext_tra_info_loi_mscs_iu;
static int hf_gtpv2_ext_tra_info_loi_mscs_a;
static int hf_gtpv2_ext_tra_info_loi_mscs_map_c;
static int hf_gtpv2_ext_tra_info_loi_mscs_map_d;
static int hf_gtpv2_ext_tra_info_loi_mgw_iuup;
static int hf_gtpv2_ext_tra_info_loi_mgw_nbup;
static int hf_gtpv2_ext_tra_info_loi_mgw_mc;
static int hf_gtpv2_ext_tra_info_loi_sgsn_ge;
static int hf_gtpv2_ext_tra_info_loi_sgsn_gs;
static int hf_gtpv2_ext_tra_info_loi_sgsn_map_gf;
static int hf_gtpv2_ext_tra_info_loi_sgsn_map_gd;
static int hf_gtpv2_ext_tra_info_loi_sgsn_map_gr;
static int hf_gtpv2_ext_tra_info_loi_sgsn_gn;
static int hf_gtpv2_ext_tra_info_loi_sgsn_iu;
static int hf_gtpv2_ext_tra_info_loi_sgsn_gb;
static int hf_gtpv2_ext_tra_info_loi_sgsn_s13;
static int hf_gtpv2_ext_tra_info_loi_sgsn_s3;
static int hf_gtpv2_ext_tra_info_loi_sgsn_s4;
static int hf_gtpv2_ext_tra_info_loi_sgsn_s6d;
static int hf_gtpv2_ext_tra_info_loi_ggsn_gmb;
static int hf_gtpv2_ext_tra_info_loi_ggsn_gi;
static int hf_gtpv2_ext_tra_info_loi_ggsn_gn;
static int hf_gtpv2_ext_tra_info_loi_rnc_uu;
static int hf_gtpv2_ext_tra_info_loi_rnc_iub;
static int hf_gtpv2_ext_tra_info_loi_rnc_iur;
static int hf_gtpv2_ext_tra_info_loi_rnc_iu;
static int hf_gtpv2_ext_tra_info_loi_bm_sc_gmb;
static int hf_gtpv2_ext_tra_info_loi_mme_s13;
static int hf_gtpv2_ext_tra_info_loi_mme_s11;
static int hf_gtpv2_ext_tra_info_loi_mme_s10;
static int hf_gtpv2_ext_tra_info_loi_mme_s6a;
static int hf_gtpv2_ext_tra_info_loi_mme_s3;
static int hf_gtpv2_ext_tra_info_loi_mme_s1_mme;
static int hf_gtpv2_ext_tra_info_loi_sgw_gxc;
static int hf_gtpv2_ext_tra_info_loi_sgw_s11;
static int hf_gtpv2_ext_tra_info_loi_sgw_s8b;
static int hf_gtpv2_ext_tra_info_loi_sgw_s5;
static int hf_gtpv2_ext_tra_info_loi_sgw_s4;
static int hf_gtpv2_ext_tra_info_loi_pdn_gw_sgi;
static int hf_gtpv2_ext_tra_info_loi_pdn_gw_s8b;
static int hf_gtpv2_ext_tra_info_loi_pdn_gw_gx;
static int hf_gtpv2_ext_tra_info_loi_pdn_gw_s6b;
static int hf_gtpv2_ext_tra_info_loi_pdn_gw_s5;
static int hf_gtpv2_ext_tra_info_loi_pdn_gw_s2c;
static int hf_gtpv2_ext_tra_info_loi_pdn_gw_s2b;
static int hf_gtpv2_ext_tra_info_loi_pdn_gw_s2a;
static int hf_gtpv2_ext_tra_info_loi_enb_uu;
static int hf_gtpv2_ext_tra_info_loi_enb_x2;
static int hf_gtpv2_ext_tra_info_loi_enb_s1_mme;
static int hf_gtpv2_ext_tra_info_loi_hss_sh;
static int hf_gtpv2_ext_tra_info_loi_hss_s6a;
static int hf_gtpv2_ext_tra_info_loi_hss_s6d;
static int hf_gtpv2_ext_tra_info_loi_hss_cx;
static int hf_gtpv2_ext_tra_info_loi_hss_map_gr;
static int hf_gtpv2_ext_tra_info_loi_hss_map_gc;
static int hf_gtpv2_ext_tra_info_loi_hss_map_d;
static int hf_gtpv2_ext_tra_info_loi_hss_map_c;
static int hf_gtpv2_ext_tra_info_loi_eir_map_gf;
static int hf_gtpv2_ext_tra_info_loi_eir_s13p;
static int hf_gtpv2_ext_tra_info_loi_eir_s13;
static int hf_gtpv2_ext_tra_info_loi_eir_map_f;
static int hf_gtpv2_ext_tra_info_loi_amf_n20;
static int hf_gtpv2_ext_tra_info_loi_amf_n15;
static int hf_gtpv2_ext_tra_info_loi_amf_n14;
static int hf_gtpv2_ext_tra_info_loi_amf_n12;
static int hf_gtpv2_ext_tra_info_loi_amf_n11;
static int hf_gtpv2_ext_tra_info_loi_amf_n8;
static int hf_gtpv2_ext_tra_info_loi_amf_n2;
static int hf_gtpv2_ext_tra_info_loi_amf_n1;
static int hf_gtpv2_ext_tra_info_loi_amf_n22;
static int hf_gtpv2_ext_tra_info_loi_amf_n26;
static int hf_gtpv2_ext_tra_info_loi_pcf_n15;
static int hf_gtpv2_ext_tra_info_loi_pcf_n7;
static int hf_gtpv2_ext_tra_info_loi_pcf_n5;
static int hf_gtpv2_ext_tra_info_loi_smf_s5_c;
static int hf_gtpv2_ext_tra_info_loi_smf_n11;
static int hf_gtpv2_ext_tra_info_loi_smf_n10;
static int hf_gtpv2_ext_tra_info_loi_smf_n7;
static int hf_gtpv2_ext_tra_info_loi_smf_n4;
static int hf_gtpv2_ext_tra_info_loi_upf_n4;
static int hf_gtpv2_ext_tra_info_loi_ng_ran_node_e1_c;
static int hf_gtpv2_ext_tra_info_loi_ng_ran_node_f1_c;
static int hf_gtpv2_ext_tra_info_loi_ng_ran_node_Uu;
static int hf_gtpv2_ext_tra_info_loi_ng_ran_node_xn_c;
static int hf_gtpv2_ext_tra_info_loi_ng_ran_node_ng_c;

static int hf_gtpv2_nr_dl_pkts_all;
static int hf_gtpv2_nr_ul_pkts_all;
static int hf_gtpv2_nr_add_exception_rpts;
static int hf_apn_rte_cntrl_status_val_time;
static int hf_gtpv2_max_pkt_loss_rte_ul_flg;
static int hf_gtpv2_max_pkt_loss_rte_dl_flg;
static int hf_gtpv2_max_pkt_loss_rte_ul;
static int hf_gtpv2_max_pkt_loss_rte_dl;

static int hf_gtpv2_mm_context_iov_updates_counter;
static int hf_gtpv2_mm_context_ear_len;
static int hf_gtpv2_node_number_len;
static int hf_gtpv2_additional_rrm_policy_index;

static int hf_gtpv2_group_id;

static int hf_gtpv2_ie_pscell_id_spare;
static int hf_gtpv2_ie_pscell_id_nr_cgi;
static int hf_gtpv2_ie_up_security_policy_up_ip_policy;
static int hf_gtpv2_ie_up_security_policy_spare;
static int hf_gtpv2_nf_instance_id_nf_instance_id;
static int hf_gtpv2_nf_timer_in_seconds_timer_value;


static int ett_gtpv2;
static int ett_gtpv2_flags;
static int ett_gtpv2_uli_flags;
static int ett_gtpv2_uli_field;
static int ett_gtpv2_bearer_ctx;
static int ett_gtpv2_PDN_conn;
static int ett_gtpv2_overload_control_information;
static int ett_gtpv2_mm_context_flag;
static int ett_gtpv2_pdn_numbers_nsapi;
static int ett_gtpv2_tra_info_trigg;
static int ett_gtpv2_tra_info_trigg_msc_server;
static int ett_gtpv2_tra_info_trigg_mgw;
static int ett_gtpv2_tra_info_trigg_sgsn;
static int ett_gtpv2_tra_info_trigg_ggsn;
static int ett_gtpv2_tra_info_trigg_bm_sc;
static int ett_gtpv2_tra_info_trigg_sgw_mme;
static int ett_gtpv2_tra_info_trigg_sgw;
static int ett_gtpv2_tra_info_trigg_pgw;
static int ett_gtpv2_tra_info_interfaces;
static int ett_gtpv2_tra_info_interfaces_imsc_server;
static int ett_gtpv2_tra_info_interfaces_lmgw;
static int ett_gtpv2_tra_info_interfaces_lsgsn;
static int ett_gtpv2_tra_info_interfaces_lggsn;
static int ett_gtpv2_tra_info_interfaces_lrnc;
static int ett_gtpv2_tra_info_interfaces_lbm_sc;
static int ett_gtpv2_tra_info_interfaces_lmme;
static int ett_gtpv2_tra_info_interfaces_lsgw;
static int ett_gtpv2_tra_info_interfaces_lpdn_gw;
static int ett_gtpv2_tra_info_interfaces_lpdn_lenb;
static int ett_gtpv2_tra_info_ne_types;
static int ett_gtpv2_rai;
static int ett_gtpv2_ms_mark;
static int ett_gtpv2_stn_sr;
static int ett_gtpv2_supp_codec_list;
static int ett_gtpv2_bss_con;
static int ett_gtpv2_utran_con;
static int ett_gtpv2_eutran_con;
static int ett_gtpv2_son_con;
static int ett_gtpv2_endc_son_con;
static int ett_gtpv2_intersys_son_con;
static int ett_gtpv2_mm_context_auth_qua;
static int ett_gtpv2_mm_context_auth_qui;
static int ett_gtpv2_mm_context_auth_tri;
static int ett_gtpv2_mm_context_net_cap;
static int ett_gtpv2_ms_network_capability;
static int ett_gtpv2_mm_context_sc;
static int ett_gtpv2_vd_pref;
static int ett_gtpv2_access_rest_data;
static int ett_gtpv2_qua;
static int ett_gtpv2_qui;
static int ett_gtpv2_preaa_tais;
static int ett_gtpv2_preaa_menbs;
static int ett_gtpv2_preaa_henbs;
static int ett_gtpv2_preaa_ecgis;
static int ett_gtpv2_preaa_rais;
static int ett_gtpv2_preaa_sais;
static int ett_gtpv2_preaa_cgis;
static int ett_gtpv2_load_control_inf;
static int ett_gtpv2_eci;
static int ett_gtpv2_twan_flags;
static int ett_gtpv2_ciot_support_ind;
static int ett_gtpv2_rohc_profile_flags;
static int ett_gtpv2_secondary_rat_usage_data_report;
static int ett_gtpv2_pres_rep_area_info;
static int ett_gtpv2_preaa_ext_menbs;
static int ett_gtpv2_ue_nr_sec_cap_len;
static int ett_gtpv2_apn_rte_ctrl_sts_len;
static int ett_gtpv2_if_mgcs;
static int ett_gtpv2_if_mgw;
static int ett_gtpv2_if_sgsn;
static int ett_gtpv2_if_ggsn;
static int ett_gtpv2_if_rnc;
static int ett_gtpv2_if_bm_sc;
static int ett_gtpv2_if_mme;
static int ett_gtpv2_if_sgw;
static int ett_gtpv2_if_pdn_gw;
static int ett_gtpv2_if_enb;
static int ett_gtpv2_if_hss;
static int ett_gtpv2_if_eir;
static int ett_gtpv2_if_amf;
static int ett_gtpv2_if_pcf;
static int ett_gtpv2_if_smf;
static int ett_gtpv2_if_upf;
static int ett_gtpv2_if_ng_ran_node;
static int ett_gtpv2_PGW_change_info;


static expert_field ei_gtpv2_ie_data_not_dissected;
static expert_field ei_gtpv2_ie_len_invalid;
static expert_field ei_gtpv2_source_type_unknown;
static expert_field ei_gtpv2_fq_csid_type_bad;
static expert_field ei_gtpv2_mbms_session_duration_days;
static expert_field ei_gtpv2_mbms_session_duration_secs;
static expert_field ei_gtpv2_ie;
static expert_field ei_gtpv2_int_size_not_handled;
static expert_field ei_gtpv2_apn_too_long;

static int gtpv2_tap;

/* Definition of User Location Info (AVP 22) masks */
#define GTPv2_ULI_CGI_MASK              0x01
#define GTPv2_ULI_SAI_MASK              0x02
#define GTPv2_ULI_RAI_MASK              0x04
#define GTPv2_ULI_TAI_MASK              0x08
#define GTPv2_ULI_ECGI_MASK             0x10
#define GTPv2_ULI_LAI_MASK              0x20
#define GTPv2_ULI_MACRO_eNB_ID_MASK     0x40
#define GTPv2_ULI_EXT_MACRO_eNB_ID_MASK 0x80

#define GTPV2_PPI_VAL_MASK          0x3F

#define GTPV2_SRVCC_PS_TO_CS_REQUEST     25
#define GTPV2_SRVCC_PS_TO_CS_RESPONSE    26
#define GTPV2_SRVCC_PS_TO_CS_COMPLETE_NOTIFICATION 27
#define GTPV2_SRVCC_PS_TO_CS_COMPLETE_ACKNOWLEDGE  28
#define GTPV2_SRVCC_PS_TO_CS_CANCEL_NOTIFICATION   29
#define GTPV2_SRVCC_PS_TO_CS_CANCEL_ACKNOWLEDGE    30
#define GTPV2_CREATE_SESSION_REQUEST     32
#define GTPV2_CREATE_SESSION_RESPONSE    33
#define GTPV2_MODIFY_BEARER_REQUEST      34
#define GTPV2_MODIFY_BEARER_RESPONSE     35
#define GTPV2_DELETE_SESSION_REQUEST     36
#define GTPV2_DELETE_SESSION_RESPONSE    37
#define GTPV2_REMOTE_UE_REPORT_NOTIFICATION     40
#define GTPV2_REMOTE_UE_REPORT_ACKNOWLEDGE    41
#define GTPV2_MODIFY_BEARER_COMMAND      64
#define GTPV2_MODIFY_BEARER_FAILURE_INDICATION    65
#define GTPV2_DELETE_BEARER_COMMAND      66
#define GTPV2_DELETE_BEARER_FAILURE_INDICATION    67
#define GTPV2_BEARER_RESOURCE_COMMAND    68
#define GTPV2_BEARER_RESOURCE_FAILURE_INDICATION  69
#define GTPV2_CREATE_BEARER_REQUEST      95
#define GTPV2_CREATE_BEARER_RESPONSE     96
#define GTPV2_UPDATE_BEARER_REQUEST      97
#define GTPV2_UPDATE_BEARER_RESPONSE     98
#define GTPV2_DELETE_BEARER_REQUEST      99
#define GTPV2_DELETE_BEARER_RESPONSE    100
#define GTPV2_IDENTIFICATION_RESPONSE   129
#define GTPV2_CONTEXT_REQUEST           130
#define GTPV2_CONTEXT_RESPONSE          131
#define GTPV2_CONTEXT_ACKNOWLEDGE       132
#define GTPV2_FORWARD_RELOCATION_REQ    133
#define GTPV2_FORWARD_RELOCATION_RESP   134
#define GTPV2_FORWARD_RELOCATION_COMPLETE_NOTIFICATION    135
#define GTPV2_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE     136
#define GTPV2_FORWARD_CTX_NOTIFICATION  137
#define GTPV2_FORWARD_CTX_ACKNOWLEDGE   138
#define GTPV2_RELOCATION_CANCEL_REQUEST         139
#define GTPV2_RELOCATION_CANCEL_RESPONSE        140
#define GTPV2_CONFIGURATION_TRANSFER_TUNNEL        141
#define GTPV2_RAN_INFORMATION_RELAY     152
#define GTPV2_RELEASE_ACCESS_BEARERS_REQUEST      170
#define GTPV2_RELEASE_ACCESS_BEARERS_RESPONSE      171
#define GTPV2_DL_DATA_NOTIF            176
#define GTPV2_DL_DATA_NOTIF_ACK        177
#define GTPV2_MODIFY_ACESSS_BEARER_REQUEST      211
#define GTPV2_MODIFY_ACCESS_BEARER_RESPONSE     212

/* Table 6.1-1: Message types for GTPv2 */
static const value_string gtpv2_message_type_vals[] = {
    {  0, "Reserved"},
    {  1, "Echo Request"},
    {  2, "Echo Response"},
    {  3, "Version Not Supported Indication"},
    /* 4-24 Reserved for S101 interface TS 29.276 */
    {  4, "Node Alive Request"},
    {  5, "Node Alive Response"},
    {  6, "Redirection Request"},
    {  7, "Redirection Response"},
    /* 25-31 Reserved for Sv interface TS 29.280 */
/*Start SRVCC Messages ETSI TS 129 280 V10.1.0 (2011-06) 5.2.1*/
    { 25, "SRVCC PS to CS Request"},
    { 26, "SRVCC PS to CS Response"},
    { 27, "SRVCC PS to CS Complete Notification"},
    { 28, "SRVCC PS to CS Complete Acknowledge"},
    { 29, "SRVCC PS to CS Cancel Notification"},
    { 30, "SRVCC PS to CS Cancel Acknowledge"},
    { 31, "SRVCC CS to PS Request"},
/*End SRVCC Messages*/
    /* SGSN/MME to PGW (S4/S11, S5/S8) */
    { 32, "Create Session Request"},
    { 33, "Create Session Response"},
    { 34, "Modify Bearer Request"},
    { 35, "Modify Bearer Response"},
    { 36, "Delete Session Request"},
    { 37, "Delete Session Response"},
    /* SGSN/MME to PGW (S4/S11, S5/S8) */
    { 38, "Change Notification Request"},
    { 39, "Change Notification Response"},
    /* MME to PGW (S11, S5/S8) */
    { 40, "Remote UE Report Notification" },
    { 41, "Remote UE Report Acknowledge" },
    /* 42-63 For future use */
    /* Messages without explicit response */
    { 64, "Modify Bearer Command"},                          /* (MME/SGSN to PGW -S11/S4, S5/S8) */
    { 65, "Modify Bearer Failure Indication"},               /*(PGW to MME/SGSN -S5/S8, S11/S4) */
    { 66, "Delete Bearer Command"},                          /* (MME to PGW -S11, S5/S8) */
    { 67, "Delete Bearer Failure Indication"},               /* (PGW to MME -S5/S8, S11) */
    { 68, "Bearer Resource Command"},                        /* (MME/SGSN to PGW -S11/S4, S5/S8) */
    { 69, "Bearer Resource Failure Indication"},             /* (PGW to MME/SGSN -S5/S8, S11/S4) */
    { 70, "Downlink Data Notification Failure Indication"},  /*(SGSN/MME to SGW -S4/S11) */
    { 71, "Trace Session Activation"},
    { 72, "Trace Session Deactivation"},
    { 73, "Stop Paging Indication"},
    /* 74-94 For future use */
    /* PGW to SGSN/MME/ TWAN/ePDG (S5/S8, S4/S11, S2a, S2b) */
    { 95, "Create Bearer Request"},
    { 96, "Create Bearer Response"},
    { 97, "Update Bearer Request"},
    { 98, "Update Bearer Response"},
    { 99, "Delete Bearer Request"},
    {100, "Delete Bearer Response"},
    /* PGW to MME, MME to PGW, SGW to PGW, SGW to MME (S5/S8, S11) */
    {101, "Delete PDN Connection Set Request"},
    {102, "Delete PDN Connection Set Response"},
    /* PGW to SGSN/MME(S5, S4/S11) */
    {103, "PGW Downlink Triggering Notification" },
    {104, "PGW Downlink Triggering Acknowledge" },
    /* 105-127 For future use */
    /* MME to MME, SGSN to MME, MME to SGSN, SGSN to SGSN (S3/10/S16) */
    {128, "Identification Request"},
    {129, "Identification Response"},
    {130, "Context Request"},
    {131, "Context Response"},
    {132, "Context Acknowledge"},
    {133, "Forward Relocation Request"},
    {134, "Forward Relocation Response"},
    {135, "Forward Relocation Complete Notification"},
    {136, "Forward Relocation Complete Acknowledge"},
    {137, "Forward Access Context Notification"},
    {138, "Forward Access Context Acknowledge"},
    {139, "Relocation Cancel Request"},
    {140, "Relocation Cancel Response"},
    {141, "Configuration Transfer Tunnel"},
    /* 142-148 For future use */
    /* SGSN to MME, MME to SGSN (S3)*/
    {149, "Detach Notification"},
    {150, "Detach Acknowledge"},
    {151, "CS Paging Indication"},
    {152, "RAN Information Relay"},
    {153, "Alert MME Notification"},
    {154, "Alert MME Acknowledge"},
    {155, "UE Activity Notification"},
    {156, "UE Activity Acknowledge" },
    {157, "ISR Status Indication" },
    {158, "UE Registration Query Request" },
    {159, "UE Registration Query Response" },
    /* MME to SGW (S11) */
    {160, "Create Forwarding Tunnel Request"},
    {161, "Create Forwarding Tunnel Response"},
    {162, "Suspend Notification"},
    {163, "Suspend Acknowledge"},
    {164, "Resume Notification"},
    {165, "Resume Acknowledge"},
    {166, "Create Indirect Data Forwarding Tunnel Request"},
    {167, "Create Indirect Data Forwarding Tunnel Response"},
    {168, "Delete Indirect Data Forwarding Tunnel Request"},
    {169, "Delete Indirect Data Forwarding Tunnel Response"},
    {170, "Release Access Bearers Request"},
    {171, "Release Access Bearers Response"},
    /* 172-175 For future use */
    /* SGW to SGSN/MME (S4/S11) */
    {176, "Downlink Data Notification"},
    {177, "Downlink Data Notification Acknowledgement"},
    {178, "Reserved. Allocated in earlier version of the specification."},
    {179, "PGW Restart Notification"},
    {180, "PGW Restart Notification Acknowledge"},
    /* 181-199 For future use */
    /* SGW to PGW, PGW to SGW (S5/S8) */
    {200, "Update PDN Connection Set Request"},
    {201, "Update PDN Connection Set Response"},
    /* 202 to 210 For future use */
    /* MME to SGW (S11) */
    {211, "Modify Access Bearers Request"},
    {212, "Modify Access Bearers Response"},
    /* 213 to 230 For future use */
    /* MBMS GW to MME/SGSN (Sm/Sn) */
    {231, "MBMS Session Start Request"},
    {232, "MBMS Session Start Response"},
    {233, "MBMS Session Update Request"},
    {234, "MBMS Session Update Response"},
    {235, "MBMS Session Stop Request"},
    {236, "MBMS Session Stop Response"},
    /* 237 to 239 For future use */
    /* Reserved for Sv interface (see also types 25 to 31)    TS 29.280 */
    {240, "SRVCC CS to PS Response"},               /* 5.2.9  3GPP TS 29.280 V11.5.0 (2013-09) */
    {241, "SRVCC CS to PS Complete Notification"},  /* 5.2.10 3GPP TS 29.280 V11.5.0 (2013-09) */
    {242, "SRVCC CS to PS Complete Acknowledge"},   /* 5.2.11 3GPP TS 29.280 V11.5.0 (2013-09) */
    {243, "SRVCC CS to PS Cancel Notification"},    /* 5.2.12 3GPP TS 29.280 V11.5.0 (2013-09) */
    {244, "SRVCC CS to PS Cancel Acknowledge"},     /* 5.2.13 3GPP TS 29.280 V11.5.0 (2013-09) */
    /* 245 to 247       For future Sv interface use*/
    /* 248 to 255 For future use */
    {0, NULL}
};
static value_string_ext gtpv2_message_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_message_type_vals);

#define NUM_GTPV2_IES 256
static int ett_gtpv2_ies[NUM_GTPV2_IES];

#define GTPV2_IE_RESERVED                 0
#define GTPV2_IE_IMSI                     1
#define GTPV2_IE_CAUSE                    2
#define GTPV2_REC_REST_CNT                3
/*Start SRVCC Messages*/
#define GTPV2_IE_STN_SR                  51
#define GTPV2_IE_SRC_TGT_TRANS_CON       52
#define GTPV2_IE_TGT_SRC_TRANS_CON       53
#define GTPV2_IE_MM_CON_EUTRAN_SRVCC     54
#define GTPV2_IE_MM_CON_UTRAN_SRVCC      55
#define GTPV2_IE_SRVCC_CAUSE             56
#define GTPV2_IE_TGT_RNC_ID              57
#define GTPV2_IE_TGT_GLOGAL_CELL_ID      58
#define GTPV2_IE_TEID_C                  59
#define GTPV2_IE_SV_FLAGS                60
#define GTPV2_IE_SAI                     61
#define GTPV2_IE_MM_CTX_FOR_CS_TO_PS_SRVCC 62
/* 61 - 70 for future sv interface use*/
/*End SRVCC Messages*/
#define GTPV2_APN                        71
#define GTPV2_AMBR                       72
#define GTPV2_EBI                        73
#define GTPV2_IP_ADDRESS                 74
#define GTPV2_MEI                        75
#define GTPV2_IE_MSISDN                  76
#define GTPV2_INDICATION                 77
#define GTPV2_PCO                        78
#define GTPV2_PAA                        79
#define GTPV2_BEARER_QOS                 80
#define GTPV2_IE_FLOW_QOS                81
#define GTPV2_IE_RAT_TYPE                82
#define GTPV2_IE_SERV_NET                83
#define GTPV2_IE_BEARER_TFT              84
#define GTPV2_IE_TAD                     85
#define GTPV2_IE_ULI                     86
#define GTPV2_IE_F_TEID                  87
#define GTPV2_IE_TMSI                    88
#define GTPV2_IE_GLOBAL_CNID             89
#define GTPV2_IE_S103PDF                 90
#define GTPV2_IE_S1UDF                   91
#define GTPV2_IE_DEL_VAL                 92
#define GTPV2_IE_BEARER_CTX              93
#define GTPV2_IE_CHAR_ID                 94
#define GTPV2_IE_CHAR_CHAR               95
#define GTPV2_IE_TRA_INFO                96
#define GTPV2_BEARER_FLAG                97
/* define GTPV2_IE_PAGING_CAUSE          98 (void) */
#define GTPV2_IE_PDN_TYPE                99
#define GTPV2_IE_PTI                    100
#define GTPV2_IE_DRX_PARAM              101
#define GTPV2_IE_UE_NET_CAPABILITY      102
#define GTPV2_IE_MM_CONTEXT_GSM_T       103
#define GTPV2_IE_MM_CONTEXT_UTMS_CQ     104
#define GTPV2_IE_MM_CONTEXT_GSM_CQ      105
#define GTPV2_IE_MM_CONTEXT_UTMS_Q      106
#define GTPV2_IE_MM_CONTEXT_EPS_QQ      107
#define GTPV2_IE_MM_CONTEXT_UTMS_QQ     108
#define GTPV2_IE_PDN_CONNECTION         109
#define GTPV2_IE_PDN_NUMBERS            110
#define GTPV2_IE_P_TMSI                 111
#define GTPV2_IE_P_TMSI_SIG             112
#define GTPV2_IE_HOP_COUNTER            113
#define GTPV2_IE_UE_TIME_ZONE           114
#define GTPV2_IE_TRACE_REFERENCE        115
#define GTPV2_IE_COMPLETE_REQUEST_MSG   116
#define GTPV2_IE_GUTI                   117
#define GTPV2_IE_F_CONTAINER            118
#define GTPV2_IE_F_CAUSE                119
#define GTPV2_IE_PLMN_ID                120
#define GTPV2_IE_TARGET_ID              121
/* GTPV2_IE_NSAPI                       122 */
#define GTPV2_IE_PKT_FLOW_ID            123
#define GTPV2_IE_RAB_CONTEXT            124
#define GTPV2_IE_S_RNC_PDCP_CTX_INFO    125
#define GTPV2_IE_PORT_NR                 126
#define GTPV2_IE_APN_RESTRICTION        127
#define GTPV2_IE_SEL_MODE               128
#define GTPV2_IE_SOURCE_IDENT           129
#define GTPV2_IE_BEARER_CONTROL_MODE    130
#define GTPV2_IE_CNG_REP_ACT            131
#define GTPV2_IE_FQ_CSID                132
#define GTPV2_IE_CHANNEL_NEEDED         133
#define GTPV2_IE_EMLPP_PRI              134
#define GTPV2_IE_NODE_TYPE              135
#define GTPV2_IE_FQDN                   136
#define GTPV2_IE_TI                     137
#define GTPV2_IE_MBMS_SESSION_DURATION  138
#define GTPV2_IE_MBMS_SERVICE_AREA      139
#define GTPV2_IE_MBMS_SESSION_ID        140
#define GTPV2_IE_MBMS_FLOW_ID           141
#define GTPV2_IE_MBMS_IP_MC_DIST        142
#define GTPV2_IE_MBMS_DIST_ACK          143
#define GTPV2_IE_RFSP_INDEX             144
#define GTPV2_IE_UCI                    145
#define GTPV2_IE_CSG_INFO_REP_ACTION    146
#define GTPV2_IE_CSG_ID                 147
#define GTPV2_IE_CMI                    148
#define GTPV2_IE_SERVICE_INDICATOR      149
#define GTPV2_IE_DETACH_TYPE            150
#define GTPV2_IE_LDN                    151
#define GTPV2_IE_NODE_FEATURES          152
#define GTPV2_IE_MBMS_TIME_TO_DATA_XFER 153
#define GTPV2_IE_THROTTLING             154
#define GTPV2_IE_ARP                    155
#define GTPV2_IE_EPC_TIMER              156
#define GTPV2_IE_SIG_PRIO_IND           157
#define GTPV2_IE_TMGI                   158
#define GTPV2_IE_ADD_MM_CONT_FOR_SRVCC  159
#define GTPV2_IE_ADD_FLAGS_FOR_SRVCC    160
#define GTPV2_IE_MMBR                   161
#define GTPV2_IE_MDT_CONFIG             162
#define GTPV2_IE_APCO                   163
#define GTPV2_IE_ABS_MBMS_DATA_TF_TIME  164
#define GTPV2_IE_HENB_INFO_REPORT       165
#define GTPV2_IE_IP4CP                  166
#define GTPV2_IE_CHANGE_TO_REPORT_FLAGS 167
#define GTPV2_IE_ACTION_INDICATION      168
#define GTPV2_IE_TWAN_IDENTIFIER        169
#define GTPV2_IE_ULI_TIMESTAMP          170
#define GTPV2_IE_MBMS_FLAGS             171
#define GTPV2_IE_RAN_NAS_CAUSE          172
#define GTPV2_IE_CN_OP_SEL_ENT          173
#define GTPV2_IE_TRUST_WLAN_MODE_IND    174
#define GTPV2_IE_NODE_NUMBER            175
#define GTPV2_IE_NODE_IDENTIFIER        176
#define GTPV2_IE_PRES_REP_AREA_ACT      177
#define GTPV2_IE_PRES_REP_AREA_INF      178
#define GTPV2_IE_TWAN_ID_TS             179
#define GTPV2_IE_OVERLOAD_CONTROL_INF   180
#define GTPV2_IE_LOAD_CONTROL_INF       181
#define GTPV2_IE_METRIC                 182
#define GTPV2_IE_SEQ_NO                 183
#define GTPV2_IE_APN_AND_REL_CAP        184
#define GTPV2_IE_WLAN_OFFLOADABILITY_IND 185
#define GTPV2_IE_PAGING_AND_SERVICE_INF 186
#define GTPV2_IE_INTEGER_NUMBER         187
#define GTPV2_IE_MILLISECOND_TS         188
#define GTPV2_IE_MON_EVENT_INF          189
/*
190    ECGI List
191    Remote UE Context
192    Remote User ID
193    Remote UE IP information
*/
#define GTPV2_IE_CIOT_OPT_SUPPORT_IND       194
#define GTPV2_IE_SCEF_PDN_CONNECTION        195
#define GTPV2_IE_HEADER_COMP_CONF           196
#define GTPV2_IE_EXTENDED_PCO               197
#define GTPV2_IE_SERV_PLMN_RATE_CONTROL     198
#define GTPV2_IE_COUNTER                    199
#define GTPV2_IE_MAPPED_UE_USAGE_TYPE                200
#define GTPV2_IE_SECONDARY_RAT_USAGE_DATA_REPORT     201
#define GTPV2_IE_UP_FUNC_SEL_INDI_FLG                202
#define GTPV2_IE_MAX_PKT_LOSS_RTE                    203
#define GTPV2_IE_APN_RTE_CNTRL_STATUS                204
#define GTPV2_IE_EXT_TRS_INF                         205
#define GTPV2_IE_MON_EVENT_EXT_INF                   206
#define GTPV2_IE_ADDITIONAL_RRM_POLICY_INDEX         207
#define GTPV2_IE_V2X_CONTEXT                         208
#define GTPV2_IE_PC5_QOS_PARAMETERS                  209
#define GTPV2_IE_SERVICES_AUTHORIZED                 210
#define GTPV2_IE_BIT_RATE                            211
#define GTPV2_IE_PC5_QOS_FLOW                        212
#define GTPV2_IE_SGI_PTP_TUNNEL_ADDRESS              213
#define GTPV2_IE_PGW_CHANGE_INFO                     214
#define GTPV2_IE_PGW_FQDN                            215
#define GTPV2_IE_GROUP_ID                            216
#define GTPV2_IE_PSCELL_ID                           217
#define GTPV2_IE_UP_SECURITY_POLICY                  218
#define GTPV2_IE_ALT_IMSI                            219
#define GTPV2_IE_NF_INSTANCE_ID                      220
#define GTPV2_IE_TIMER_IN_SECONDS                    221
/*
220 to 253    Spare. For future use.
254    Special IE type for IE Type Extension
255    Private Extension
256 to 65535    Spare. For future use.

*/
/* 169 to 254 reserved for future use */
#define GTPV2_IE_PRIVATE_EXT            255

#define SPARE                               0X0
#define CREATE_NEW_TFT                      0X20
#define DELETE_TFT                          0X40
#define ADD_PACKET_FILTERS_TFT              0X60
#define REPLACE_PACKET_FILTERS_TFT          0X80
#define DELETE_PACKET_FILTERS_TFT           0XA0
#define NO_TFT_OPERATION                    0XC0
#define RESERVED                            0XE0

/* SRVCC PS-to-CS Transparent Container Preference */
#define PREF_DECODE_SRVCC_P2C_TRANS_CONT_NO            0
#define PREF_DECODE_SRVCC_P2C_TRANS_CONT_TARGET_UTRAN  1
static int pref_decode_srvcc_p2c_trans_cont = PREF_DECODE_SRVCC_P2C_TRANS_CONT_NO;

static unsigned pref_pair_matching_max_interval_ms; /* Default: disable */

/* Table 8.1-1: Information Element types for GTPv2 */
static const value_string gtpv2_element_type_vals[] = {
    {  0, "Reserved"},
    {  1, "International Mobile Subscriber Identity (IMSI)"},                   /* Variable Length / 8.3 */
    {  2, "Cause"},                                                             /* Variable Length / 8.4 */
    {  3, "Recovery (Restart Counter)"},                                        /* Variable Length / 8.5 */
                                                                                /* 4-34 Reserved for S101 interface Extendable / See 3GPP TS 29.276 [14] */
                                                                                /* 35-50  / See 3GPP TS 29.276 */
/*Start SRVCC Messages ETSI TS 129 280 V10.1.0 (2011-06) 6.1*/
    { 51, "STN-SR"},                                                            /* Variable Length / 6.2 */
    { 52, "Source to Target Transparent Container"},                            /* Variable Length / 6.3 */
    { 53, "Target to Source Transparent Container"},                            /* Variable Length / 6.4 */
    { 54, "MM Context for E-UTRAN SRVCC"},                                      /* Variable Length / 6.5 */
    { 55, "MM Context for UTRAN SRVCC"},                                        /* Variable Length / 6.6 */
    { 56, "SRVCC Cause"},                                                       /* Fixed Length / 6.7 */
    { 57, "Target RNC ID"},                                                     /* Variable Length / 6.8 */
    { 58, "Target Global Cell ID"},                                             /* Variable Length / 6.9 */
    { 59, "TEID-C"},                                                            /* Extendable / 6.10 */
    { 60, "Sv Flags" },                                                         /* Extendable / 6.11 */
    { 61, "Service Area Identifier" },                                          /* Extendable / 6.12 */
    { 62, "MM Context for CS to PS SRVCC" },                                    /* Extendable / 6.13 */
                                                                                /* 63-70 For future Sv interface use */
/*End SRVCC Messages*/
    { 71, "Access Point Name (APN)"},                                           /* Variable Length / 8.6 */
    { 72, "Aggregate Maximum Bit Rate (AMBR)"},                                 /* Fixed Length / 8.7 */
    { 73, "EPS Bearer ID (EBI)"},                                               /* Extendable / 8.8 */
    { 74, "IP Address"},                                                        /* Extendable / 8.9 */
    { 75, "Mobile Equipment Identity (MEI)"},                                   /* Variable Length / 8.10 */
    { 76, "MSISDN"},                                                            /* Variable Length / 8.11 */
    { 77, "Indication"},                                                        /* Extendable / 8.12 */
    { 78, "Protocol Configuration Options (PCO)"},                              /* Variable Length / 8.13 */
    { 79, "PDN Address Allocation (PAA)"},                                      /* Variable Length / 8.14 */
    { 80, "Bearer Level Quality of Service (Bearer QoS)"},                      /* Variable Length / 8.15 */
    { 81, "Flow Quality of Service (Flow QoS)"},                                /* Extendable / 8.16 */
    { 82, "RAT Type"},                                                          /* Extendable / 8.17 */
    { 83, "Serving Network"},                                                   /* Extendable / 8.18 */
    { 84, "EPS Bearer Level Traffic Flow Template (Bearer TFT)"},               /* Variable Length / 8.19 */
    { 85, "Traffic Aggregation Description (TAD)"},                             /* Variable Length / 8.20 */
    { 86, "User Location Info (ULI)"},                                          /* Variable Length / 8.21 */
    { 87, "Fully Qualified Tunnel Endpoint Identifier (F-TEID)"},               /* Extendable / 8.22 */
    { 88, "TMSI"},                                                              /* Variable Length / 8.23 */
    { 89, "Global CN-Id"},                                                      /* Variable Length / 8.24 */
    { 90, "S103 PDN Data Forwarding Info (S103PDF)"},                           /* Variable Length / 8.25 */
    { 91, "S1-U Data Forwarding Info (S1UDF)"},                                 /* Variable Length/ 8.26 */
    { 92, "Delay Value"},                                                       /* Extendable / 8.27 */
    { 93, "Bearer Context"},                                                    /* Extendable / 8.28 */
    { 94, "Charging ID"},                                                       /* Extendable / 8.29 */
    { 95, "Charging Characteristics"},                                          /* Extendable / 8.30 */
    { 96, "Trace Information"},                                                 /* Extendable / 8.31 */
    { 97, "Bearer Flags"},                                                      /* Extendable / 8.32 */
    { 98, "Paging Cause"},                                                      /* Variable Length / 8.33 */
    { 99, "PDN Type"},                                                          /* Extendable / 8.34 */
    {100, "Procedure Transaction ID"},                                          /* Extendable / 8.35 */
    {101, "DRX Parameter"},                                                     /* Variable Length/ 8.36 */
    {102, "UE Network Capability"},                                             /* Variable Length / 8.37 */
    {103, "MM Context (GSM Key and Triplets)"},                                 /* Variable Length / 8.38 */
    {104, "MM Context (UMTS Key, Used Cipher and Quintuplets)"},                /* Variable Length / 8.38 */
    {105, "MM Context (GSM Key, Used Cipher and Quintuplets)"},                 /* Variable Length / 8.38 */
    {106, "MM Context (UMTS Key and Quintuplets)"},                             /* Variable Length / 8.38 */
    {107, "MM Context (EPS Security Context, Quadruplets and Quintuplets)"},    /* Variable Length / 8.38 */
    {108, "MM Context (UMTS Key, Quadruplets and Quintuplets)"},                /* Variable Length / 8.38 */
    {109, "PDN Connection"},                                                    /* Extendable / 8.39 */
    {110, "PDU Numbers"},                                                       /* Extendable / 8.40 */
    {111, "P-TMSI"},                                                            /* Variable Length / 8.41 */
    {112, "P-TMSI Signature"},                                                  /* Variable Length / 8.42 */
    {113, "Hop Counter"},                                                       /* Extendable / 8.43 */
    {114, "UE Time Zone"},                                                      /* Variable Length / 8.44 */
    {115, "Trace Reference"},                                                   /* Fixed Length / 8.45 */
    {116, "Complete Request Message"},                                          /* Variable Length / 8.46 */
    {117, "GUTI"},                                                              /* Variable Length / 8.47 */
    {118, "F-Container"},                                                       /* Variable Length / 8.48 */
    {119, "F-Cause"},                                                           /* Variable Length / 8.49 */
    {120, "PLMN ID"},                                                           /* Variable Length / 8.50 */
    {121, "Target Identification"},                                             /* Variable Length / 8.51 */
    {122, "NSAPI"},                                                             /* Extendable / 8.52 */
    {123, "Packet Flow ID"},                                                    /* Variable Length / 8.53 */
    {124, "RAB Context"},                                                       /* Fixed Length / 8.54 */
    {125, "Source RNC PDCP Context Info"},                                      /* Variable Length / 8.55 */
    {126, "Port Number"},                                                       /* Extendable / 8.56 */
    {127, "APN Restriction"},                                                   /* Extendable / 8.57 */
    {128, "Selection Mode"},                                                    /* Extendable / 8.58 */
    {129, "Source Identification"},                                             /* Variable Length / 8.50 */
    {130, "Bearer Control Mode"},                                               /* Extendable / 8.60 */
    {131, "Change Reporting Action"},                                           /* Variable Length / 8.61 */
    {132, "Fully Qualified PDN Connection Set Identifier (FQ-CSID)"},           /* Variable Length / 8.62 */
    {133, "Channel needed"},                                                    /* Extendable / 8.63 */
    {134, "eMLPP Priority"},                                                    /* Extendable / 8.64 */
    {135, "Node Type"},                                                         /* Extendable / 8.65 */
    {136, "Fully Qualified Domain Name (FQDN)"},                                /* Variable Length / 8.66 */
    {137, "Transaction Identifier (TI)"},                                       /* Variable Length / 8.68 */
    {138, "MBMS Session Duration"},                                             /* Duration Extendable / 8.69 */
    {139, "MBMS Service Area"},                                                 /* Extendable / 8.70 */
    {140, "MBMS Session Identifier"},                                           /* Extendable / 8.71 */
    {141, "MBMS Flow Identifier"},                                              /* Extendable / 8.72 */
    {142, "MBMS IP Multicast Distribution"},                                    /* Extendable / 8.73 */
    {143, "MBMS Distribution Acknowledge"},                                     /* Extendable / 8.74 */
    {144, "RFSP Index"},                                                        /* Fixed Length / 8.77 */
    {145, "User CSG Information (UCI)"},                                        /* Extendable / 8.75 */
    {146, "CSG Information Reporting Action"},                                  /* Extendable / 8.76 */
    {147, "CSG ID"},                                                            /* Extendable / 8.78 */
    {148, "CSG Membership Indication (CMI)"},                                   /* Extendable / 8.79 */
    {149, "Service indicator"},                                                 /* Fixed Length / 8.80 */
    {150, "Detach Type"},                                                       /* Fixed Length / 8.81 */
    {151, "Local Distinguished Name (LDN)"},                                    /* Variable Length / 8.82 */
    {152, "Node Features"},                                                     /* Extendable / 8.83 */
    {153, "MBMS Time to Data Transfer"},                                        /* Extendable / 8.84 */
    {154, "Throttling"},                                                        /* Extendable / 8.85 */
    {155, "Allocation/Retention Priority (ARP)"},                               /* Extendable / 8.86 */
    {156, "EPC Timer"},                                                         /* Extendable / 8.87 */
    {157, "Signalling Priority Indication"},                                    /* Extendable / 8.88 */
    {158, "Temporary Mobile Group Identity"},                                   /* Extendable / 8.89 */
    {159, "Additional MM context for SRVCC"},                                   /* Extendable / 8.90 */
    {160, "Additional flags for SRVCC"},                                        /* Extendable / 8.91 */
    {161, "Max MBR/APN-AMBR (MMBR)"},                                           /* Extendable / 8.92 */
    {162, "MDT Configuration"},                                                 /* Extendable / 8.93 */
    {163, "Additional Protocol Configuration Options (APCO)"},                  /* Extendable / 8.94 */
    {164, "Absolute Time of MBMS Data Transfer"},                               /* Extendable / 8.95 */
    {165, "H(e)NB Information Reporting"},                                      /* Extendable / 8.96*/
    {166, "IPv4 Configuration Parameters (IP4CP)"},                             /* Extendable / 8.97*/
    {167, "Change to Report Flags"},                                            /* Extendable / 8.98 */
    {168, "Action Indication"},                                                 /* Extendable / 8.99 */
    {169, "TWAN Identifier "},                                                  /* Extendable / 8.100 */
    {170, "ULI Timestamp"},                                                     /* Extendable / 8.101 */
    {171, "MBMS Flags"},                                                        /* Extendable / 8.102 */
    {172, "RAN/NAS Cause"},                                                     /* Extendable / 8.103 */
    {173, "CN Operator Selection Entity"},                                      /* Extendable / 8.104 */
    {174, "Trusted WLAN Mode Indication"},                                      /* Extendable / 8.105 */
    {175, "Node Number"},                                                       /* Extendable / 8.106 */
    {176, "Node Identifier"},                                                   /* Extendable / 8.107 */
    {177, "Presence Reporting Area Action"},                                    /* Extendable / 8.108 */
    {178, "Presence Reporting Area Information"},                               /* Extendable / 8.109 */
    {179, "TWAN Identifier Timestamp"},                                         /* Extendable / 8.110 */
    {180, "Overload Control Information"},                                      /* Extendable / 8.111 */
    {181, "Load Control Information"},                                          /* Extendable / 8.112 */
    {182, "Metric"},                                                            /* Fixed Length / 8.113 */
    {183, "Sequence Number"},                                                   /* Fixed Length / 8.114 */
    {184, "APN and Relative Capacity"},                                         /* Extendable / 8.115 */
    {185, "WLAN Offloadability Indication"},                                    /* Extendable / 8.116 */
    {186, "Paging and Service Information"},                                    /* Extendable / 8.117 */
    {187, "Integer Number" },                                                   /* Variable / 8.118 */
    {188, "Millisecond Time Stamp" },                                           /* Extendable / 8.119 */
    {189, "Monitoring Event Information"},                                      /* Extendable / 8.120 */
    {190, "ECGI List"},                                                         /* Extendable / 8.121 */
    {191, "Remote UE Context"},                                                 /* Extendable / 8.122 */
    {192, "Remote User ID"},                                                    /* Extendable / 8.123 */
    {193, "Remote UE IP information"},                                          /* Variable Length / 8.124 */
    {194, "CIoT Optimizations Support Indication"},                             /* Extendable / 8.125 */
    {195, "SCEF PDN Connection"},                                               /* Extendable / 8.126 */
    {196, "Header Compression Configuration"},                                  /* Extendable / 8.127 */
    {197, "Extended Protocol Configuration Options(ePCO)"},                     /* Variable Length / 8.128 */
    {198, "Serving PLMN Rate Control"},                                         /* Extendable / 8.129 */
    {199, "Counter" },                                                          /* Extendable / 8.130 */
    {200, "Mapped UE Usage Type" },                                             /* Extendable / 8.131 */
    {201, "Secondary RAT Usage Data Report" },                                  /* Extendable / 8.132 */
    {202, "UP Function Selection Indication Flags" },                           /* Extendable / 8.133 */
    {203, "Maximum Packet Loss Rate" },                                         /* Extendable / 8.134 */
    {204, "APN Rate Control Status" },                                          /* Extendable / 8.135 */
    {205, "Extended Trace Information" },                                       /* Extendable / 8.136 */
    {206, "Monitoring Event Extension Information" },                           /* Extendable / 8.137 */
    {207, "Additional RRM Policy Index" },                                      /* Fixed Length / 8.138 */
    {208, "V2X Context" },                                                      /* Extendable / 8.139 */
    {209, "PC5 QoS Parameters" },                                               /* Extendable / 8.140 */
    {210, "Services Authorized" },                                              /* Extendable / 8.141 */
    {211, "Bit Rate" },                                                         /* Extendable / 8.142 */
    {212, "PC5 QoS Flow" },                                                     /* Extendable / 8.143 */
    {213, "SGi PtP Tunnel Address" },                                           /* Extendable / 8.144 */
    {214, "PGW Change Info" },                                                  /* Extendable / 8.145 */
    {215, "PGW FQDN" },                                                         /* Extendable / 8.146 */
    {216, "Group Id" },                                                         /* Variable Length / 8.147 */
    {217, "PSCell ID" },                                                        /* Fixed Length / 8.148*/
    {218, "UP Security Policy" },                                               /* Extendable / 8.149*/
    {219, "Alternative IMSI" },                                                 /* Variable Length / 8.150 */
    {220, "NF Instance ID" },                                                   /* Fixed Length / 8.151 */
    {221, "Timer in Seconds"},                                                  /* Variable Length / 8.152 */
                                                                                /* 222 to 254    Spare. For future use.    */
    {255, "Private Extension"},                                                 /* Variable Length / 8.67 */
    {0, NULL}
};
static value_string_ext gtpv2_element_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_element_type_vals);

typedef struct _gtpv2_hdr {
    uint8_t flags;   /* GTP header flags */
    uint8_t message; /* Message type */
    uint16_t length; /* Length of header */
    int64_t teid;    /* Tunnel End-point ID */
} gtpv2_hdr_t;

/* Data structure attached to a  conversation,
to keep track of request/response-pairs
*/
typedef struct gtpv2_conv_info_t {
    wmem_map_t             *unmatched;
    wmem_map_t             *matched;
} gtpv2_conv_info_t;

/*structure used to track responses to requests using sequence number*/
typedef struct gtpv2_msg_hash_entry {
    bool is_request;    /*true/false*/
    uint32_t req_frame;      /*frame with request */
    nstime_t req_time;      /*req time */
    uint32_t rep_frame;      /*frame with reply */
    int seq_nr;            /*sequence number*/
    unsigned msgtype;          /*messagetype*/
} gtpv2_msg_hash_t;

static unsigned
gtpv2_sn_hash(const void *k)
{
    const gtpv2_msg_hash_t *key = (const gtpv2_msg_hash_t *)k;

    return key->seq_nr;
}

static int
gtpv2_sn_equal_matched(const void *k1, const void *k2)
{
    const gtpv2_msg_hash_t *key1 = (const gtpv2_msg_hash_t *)k1;
    const gtpv2_msg_hash_t *key2 = (const gtpv2_msg_hash_t *)k2;
    double diff;
    nstime_t delta;

    if (key1->req_frame && key2->req_frame && (key1->req_frame != key2->req_frame)) {
        return 0;
    }

    if (key1->rep_frame && key2->rep_frame && (key1->rep_frame != key2->rep_frame)) {
        return 0;
    }

    if (pref_pair_matching_max_interval_ms) {
        nstime_delta(&delta, &key1->req_time, &key2->req_time);
        diff = fabs(nstime_to_msec(&delta));

        return key1->seq_nr == key2->seq_nr && diff < pref_pair_matching_max_interval_ms;
    }

    return key1->seq_nr == key2->seq_nr;
}

static int
gtpv2_sn_equal_unmatched(const void *k1, const void *k2)
{
    const gtpv2_msg_hash_t *key1 = (const gtpv2_msg_hash_t *)k1;
    const gtpv2_msg_hash_t *key2 = (const gtpv2_msg_hash_t *)k2;
    double diff;
    nstime_t delta;

    if (pref_pair_matching_max_interval_ms) {
        nstime_delta(&delta, &key1->req_time, &key2->req_time);
        diff = fabs(nstime_to_msec(&delta));

        return key1->seq_nr == key2->seq_nr && diff < pref_pair_matching_max_interval_ms;
    }

    return key1->seq_nr == key2->seq_nr;
}

static GHashTable *gtpv2_stat_msg_idx_hash;

static void
gtpv2_stat_init(struct register_srt* srt _U_, GArray*srt_array)
{
    if (gtpv2_stat_msg_idx_hash != NULL) {
        g_hash_table_destroy(gtpv2_stat_msg_idx_hash);
    }
    gtpv2_stat_msg_idx_hash = g_hash_table_new(g_direct_hash, g_direct_equal);

    init_srt_table("GTPv2 Requests", NULL, srt_array, 0, NULL, NULL, NULL);
}

static tap_packet_status
gtpv2_stat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv, tap_flags_t flags _U_)
{
    unsigned i = 0;
    srt_stat_table *gtpv2_srt_table;
    srt_data_t *srt_data = (srt_data_t*)pss;
    const gtpv2_msg_hash_t *gcrp = (const gtpv2_msg_hash_t *)prv;
    int idx = 0;

    /* We are only interested in matched reply packets. */
    if (gcrp->is_request) {
        return TAP_PACKET_DONT_REDRAW;
    }
    if (!gcrp->req_frame) {
        return TAP_PACKET_DONT_REDRAW;
    }

    gtpv2_srt_table = g_array_index(srt_data->srt_array, srt_stat_table*, i);

    /* XXX: It would be nice if srt_table handled hashing so that the
     * real procedure number could be displayed in the table without
     * having to add empty rows for unused message types and responses
     * (requests and responses have different message types, and we
     * only use the request value.)
     */
    idx = GPOINTER_TO_UINT(g_hash_table_lookup(gtpv2_stat_msg_idx_hash, GUINT_TO_POINTER(gcrp->msgtype)));

    /* Store the row value incremented by 1 to distinguish 0 from NULL */
    if (idx == 0) {
        idx = g_hash_table_size(gtpv2_stat_msg_idx_hash);
        g_hash_table_insert(gtpv2_stat_msg_idx_hash, GUINT_TO_POINTER(gcrp->msgtype), GUINT_TO_POINTER(idx + 1));
        init_srt_table_row(gtpv2_srt_table, idx, val_to_str_ext_const(gcrp->msgtype, &gtpv2_message_type_vals_ext, "Unknown"));
    } else {
        idx -= 1;
    }

    add_srt_table_data(gtpv2_srt_table, idx, &gcrp->req_time, pinfo);

    return TAP_PACKET_REDRAW;
}

/* Make this a common function ???*/
static void
value_in_tenth_of_percent_fmt(char* s, uint32_t v)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v / 10, v);
}

/* Add Info element on IE types with multiple instances in same group */
typedef struct _gtpv2_information_element_instance {
    uint8_t      message_type;  /* Message type */
    uint8_t      parent_ie;     /* Parent group IE for which our IE is in. 0 if on message level */
    uint8_t      type;          /* This IE type */
    uint8_t      instance;      /* Which Instance */
    const char *info_element;  /* Information element for the IE type */
} gtpv2_information_element_instance_t;

/* IE types which defines with multiple instances in ch7.2 Tunnel Management Messages and ch7.3 Mobility Management Messages */
static const gtpv2_information_element_instance_t gtpv2_information_element_instance_vals[] = {
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_F_TEID, 0, "Sender F-TEID for Control Plane" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_F_TEID, 1, "PGW S5/S8 Address for Control Plane or PMIP" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_BEARER_CTX, 0, "Bearer Contexts to be Created" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_BEARER_CTX, 1, "Bearer Contexts to be Removed" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_FQ_CSID, 0, "MME-FQ-CSID" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_FQ_CSID, 1, "SGW-FQ-CSID" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_FQ_CSID, 2, "ePDG-FQ-CSID" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_FQ_CSID, 3, "TWAN-FQ-CSID" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_LDN, 0, "MME/S4-SGSN LDN" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_LDN, 1, "SGW LDN" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_LDN, 2, "ePDG LDN" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_LDN, 3, "TWAN LDN" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IP_ADDRESS, 0, "UE Local IP Address" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IP_ADDRESS, 1, "H(e)NB Local IP Address" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IP_ADDRESS, 2, "MME/S4-SGSN Identifier" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IP_ADDRESS, 3, "ePDG IP Address" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_PORT_NR, 0, "UE UDP Port" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_PORT_NR, 1, "H(e)NB Local UDP Port" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_PORT_NR, 2, "UE TCP Port" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "MME/S4-SGSN Overload Control Info" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 2, "TWAN/ePDG Overload Control Info" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_TWAN_IDENTIFIER, 0, "TWAN Identifier" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_TWAN_IDENTIFIER, 1, "WLAN Location Info" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_TWAN_ID_TS, 0, "WLAN Location Timestamp" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_ULI, 0, "User Location Info" },
    {  GTPV2_CREATE_SESSION_REQUEST, 0, GTPV2_IE_ULI, 1, "User Location Info for SGW" },

    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_F_TEID, 0, "Sender F-TEID for Control Plane" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_F_TEID, 1, "PGW S5/S8 Address for Control Plane or PMIP" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_BEARER_CTX, 0, "Bearer Contexts to be Created" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_BEARER_CTX, 1, "Bearer Contexts to be Removed" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_FQ_CSID, 0, "PGW-FQ-CSID" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_FQ_CSID, 1, "SGW-FQ-CSID" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_LDN, 0, "SGW LDN" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_LDN, 1, "PGW LDN" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_LOAD_CONTROL_INF, 0, "PGW node level Load Control Info" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_LOAD_CONTROL_INF, 1, "PGW APN level Load Control Info" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_LOAD_CONTROL_INF, 2, "SGW node level Load Control Info" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "PGW Overload Control Info" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_FQDN, 0, "Charging Gateway Name" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_FQDN, 1, "PGW Node Name" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IE_FQDN, 1, "Alternative PGW-C/SMF FQDN" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IP_ADDRESS, 0, "Charging Gateway Address" },
    {  GTPV2_CREATE_SESSION_RESPONSE, 0, GTPV2_IP_ADDRESS, 1, "Alternative PGW-C/SMF Address" },
    {  GTPV2_CREATE_SESSION_RESPONSE, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 0, "PGW Set FQDN" },
    {  GTPV2_CREATE_SESSION_RESPONSE, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 1, "Alternative PGW-C/SMF FQDN" },
    {  GTPV2_CREATE_SESSION_RESPONSE, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 0, "Alternative PGW-C/SMF Address" },

    {  GTPV2_CREATE_BEARER_REQUEST, 0, GTPV2_IE_FQ_CSID, 0, "PGW-FQ-CSID" },
    {  GTPV2_CREATE_BEARER_REQUEST, 0, GTPV2_IE_FQ_CSID, 1, "SGW-FQ-CSID" },
    {  GTPV2_CREATE_BEARER_REQUEST, 0, GTPV2_IE_LOAD_CONTROL_INF, 0, "PGW node level Load Control Info" },
    {  GTPV2_CREATE_BEARER_REQUEST, 0, GTPV2_IE_LOAD_CONTROL_INF, 1, "PGW APN level Load Control Info" },
    {  GTPV2_CREATE_BEARER_REQUEST, 0, GTPV2_IE_LOAD_CONTROL_INF, 2, "SGW node level Load Control Info" },
    {  GTPV2_CREATE_BEARER_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "PGW Overload Control Info" },
    {  GTPV2_CREATE_BEARER_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_CREATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 0, "PGW Set FQDN" },
    {  GTPV2_CREATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 1, "Alternative PGW-C/SMF FQDN" },
    {  GTPV2_CREATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 0, "Alternative PGW-C/SMF Address" },
    {  GTPV2_CREATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 1, "New PGW-C/SMF Address" },
    {  GTPV2_CREATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 2, "New PGW Control Plane IP Address" },
    {  GTPV2_CREATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 3, "New SGW-C Address" },
    {  GTPV2_CREATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_GROUP_ID, 0, "Group Id" },
    {  GTPV2_CREATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_GROUP_ID, 1, "New Group Id" },

    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 0, "MME-FQ-CSID" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 1, "SGW-FQ-CSID" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 2, "ePDG-FQ-CSID" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 3, "TWAN-FQ-CSID" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "MME/S4-SGSN Overload Control Info" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 2, "TWAN/ePDG Overload Control Info" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_TWAN_IDENTIFIER, 0, "TWAN Identifier" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_TWAN_IDENTIFIER, 1, "WLAN Location Info" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_TWAN_ID_TS, 1, "WLAN Location Timestamp" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_PORT_NR, 0, "UE UDP Port" },
    {  GTPV2_CREATE_BEARER_RESPONSE, 0, GTPV2_IE_PORT_NR, 1, "UE TCP Por" },

    {  GTPV2_BEARER_RESOURCE_COMMAND, 0, GTPV2_EBI, 0, "Linked EPS Bearer ID (LBI)" },
    {  GTPV2_BEARER_RESOURCE_COMMAND, 0, GTPV2_EBI, 1, "EPS Bearer ID" },
    {  GTPV2_BEARER_RESOURCE_COMMAND, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "MME/S4-SGSN Overload Control Info" },
    {  GTPV2_BEARER_RESOURCE_COMMAND, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },

    {  GTPV2_BEARER_RESOURCE_FAILURE_INDICATION, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "PGW Overload Control Info" },
    {  GTPV2_BEARER_RESOURCE_FAILURE_INDICATION, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },

    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_BEARER_CTX, 0, "Bearer Contexts to be Modified" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_BEARER_CTX, 1, "Bearer Contexts to be Removed" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_FQ_CSID, 0, "MME-FQ-CSID" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_FQ_CSID, 1, "SGW-FQ-CSID" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IP_ADDRESS, 0, "H(e)NB Local IP Address" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IP_ADDRESS, 1, "UE Local IP Address" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IP_ADDRESS, 2, "MME/S4-SGSN Identifier" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_PORT_NR, 0, "H(e)NB Local UDP Port" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_PORT_NR, 1, "UE UDP Port" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "MME/S4-SGSN Overload Control Info" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 2, "ePDG Overload Control Info" },
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_ULI, 0, "User Location Info" },                    /* redundant */
    {  GTPV2_MODIFY_BEARER_REQUEST, 0, GTPV2_IE_ULI, 1, "User Location Info for SGW" },            /* redundant ? */

    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_BEARER_CTX, 0, "Bearer Contexts to be Modified" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_BEARER_CTX, 1, "Bearer Contexts to be Removed" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 0, "PGW-FQ-CSID" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 1, "SGW-FQ-CSID" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_LDN, 0, "SGW LDN" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_LDN, 1, "PGW LDN" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_LOAD_CONTROL_INF, 0, "PGW node level Load Control Info" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_LOAD_CONTROL_INF, 1, "PGW APN level Load Control Info" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_LOAD_CONTROL_INF, 2, "SGW node level Load Control Info" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "PGW Overload Control Info" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 0, "PGW Set FQDN" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 1, "Alternative PGW-C/SMF FQDN" },
    {  GTPV2_MODIFY_BEARER_RESPONSE, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 0, "Alternative PGW-C/SMF Address" },

    {  GTPV2_DELETE_SESSION_REQUEST, 0, GTPV2_EBI, 0, "Linked EPS Bearer ID (LBI)" },
    {  GTPV2_DELETE_SESSION_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "MME/S4-SGSN Overload Control Info" },
    {  GTPV2_DELETE_SESSION_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_DELETE_SESSION_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 2, "TWAN/ePDG Overload Control Info" },
    {  GTPV2_DELETE_SESSION_REQUEST, 0, GTPV2_IE_TWAN_IDENTIFIER, 0, "TWAN Identifier" },
    {  GTPV2_DELETE_SESSION_REQUEST, 0, GTPV2_IE_TWAN_IDENTIFIER, 1, "WLAN Location Info" },
    {  GTPV2_DELETE_SESSION_REQUEST, 0, GTPV2_IE_TWAN_ID_TS, 1, "WLAN Location Timestamp" },
    {  GTPV2_DELETE_SESSION_REQUEST, 0, GTPV2_IE_PORT_NR, 0, "UE UDP Port" },
    {  GTPV2_DELETE_SESSION_REQUEST, 0, GTPV2_IE_PORT_NR, 1, "UE TCP Por" },

    {  GTPV2_DELETE_BEARER_REQUEST, 0, GTPV2_EBI, 0, "Linked EPS Bearer ID (LBI)" },
    {  GTPV2_DELETE_BEARER_REQUEST, 0, GTPV2_EBI, 1, "EPS Bearer ID" },
    {  GTPV2_DELETE_BEARER_REQUEST, 0, GTPV2_IE_FQ_CSID, 0, "PGW-FQ-CSID" },
    {  GTPV2_DELETE_BEARER_REQUEST, 0, GTPV2_IE_FQ_CSID, 1, "SGW-FQ-CSID" },
    {  GTPV2_DELETE_BEARER_REQUEST, 0, GTPV2_IE_LOAD_CONTROL_INF, 0, "PGW node level Load Control Info" },
    {  GTPV2_DELETE_BEARER_REQUEST, 0, GTPV2_IE_LOAD_CONTROL_INF, 1, "PGW APN level Load Control Info" },
    {  GTPV2_DELETE_BEARER_REQUEST, 0, GTPV2_IE_LOAD_CONTROL_INF, 2, "SGW node level Load Control Info" },
    {  GTPV2_DELETE_BEARER_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "PGW Overload Control Info" },
    {  GTPV2_DELETE_BEARER_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_DELETE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 0, "PGW Set FQDN" },
    {  GTPV2_DELETE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 1, "Alternative PGW-C/SMF FQDN" },
    {  GTPV2_DELETE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 0, "Alternative PGW-C/SMF Address" },
    {  GTPV2_DELETE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 1, "New PGW-C/SMF Address" },
    {  GTPV2_DELETE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 2, "New PGW Control Plane IP Address" },
    {  GTPV2_DELETE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 3, "New SGW-C Address" },
    {  GTPV2_DELETE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_GROUP_ID, 0, "Group Id" },
    {  GTPV2_DELETE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_GROUP_ID, 1, "New Group Id" },

    {  GTPV2_DELETE_SESSION_RESPONSE, 0, GTPV2_IE_LOAD_CONTROL_INF, 0, "PGW node level Load Control Info" },
    {  GTPV2_DELETE_SESSION_RESPONSE, 0, GTPV2_IE_LOAD_CONTROL_INF, 1, "PGW APN level Load Control Info" },
    {  GTPV2_DELETE_SESSION_RESPONSE, 0, GTPV2_IE_LOAD_CONTROL_INF, 2, "SGW node level Load Control Info" },
    {  GTPV2_DELETE_SESSION_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "PGW Overload Control Info" },
    {  GTPV2_DELETE_SESSION_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },

    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_EBI, 0, "Linked EPS Bearer ID (LBI)" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 0, "MME-FQ-CSID" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 1, "SGW-FQ-CSID" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 2, "ePDG-FQ-CSID" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 3, "TWAN-FQ-CSID" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "MME/S4-SGSN Overload Control Info" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 2, "TWAN/ePDG Overload Control Info" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_TWAN_IDENTIFIER, 0, "TWAN Identifier" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_TWAN_IDENTIFIER, 1, "WLAN Location Info" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_TWAN_ID_TS, 1, "WLAN Location Timestamp" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_PORT_NR, 0, "UE UDP Port" },
    {  GTPV2_DELETE_BEARER_RESPONSE, 0, GTPV2_IE_PORT_NR, 1, "UE TCP Por" },

    {  GTPV2_MODIFY_BEARER_COMMAND, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "MME/S4-SGSN Overload Control Info" },
    {  GTPV2_MODIFY_BEARER_COMMAND, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_MODIFY_BEARER_COMMAND, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 2, "TWAN/ePDG Overload Control Info" },

    {  GTPV2_MODIFY_BEARER_FAILURE_INDICATION, 0, GTPV2_IE_LOAD_CONTROL_INF, 0, "PGW node level Load Control Info" },
    {  GTPV2_MODIFY_BEARER_FAILURE_INDICATION, 0, GTPV2_IE_LOAD_CONTROL_INF, 1, "SGW node level Load Control Info" },

    {  GTPV2_UPDATE_BEARER_REQUEST, 0, GTPV2_IE_FQ_CSID, 0, "PGW-FQ-CSID" },
    {  GTPV2_UPDATE_BEARER_REQUEST, 0, GTPV2_IE_FQ_CSID, 1, "SGW-FQ-CSID" },
    {  GTPV2_UPDATE_BEARER_REQUEST, 0, GTPV2_IE_LOAD_CONTROL_INF, 0, "PGW node level Load Control Info" },
    {  GTPV2_UPDATE_BEARER_REQUEST, 0, GTPV2_IE_LOAD_CONTROL_INF, 1, "PGW APN level Load Control Info" },
    {  GTPV2_UPDATE_BEARER_REQUEST, 0, GTPV2_IE_LOAD_CONTROL_INF, 2, "SGW node level Load Control Info" },
    {  GTPV2_UPDATE_BEARER_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "PGW Overload Control Info" },
    {  GTPV2_UPDATE_BEARER_REQUEST, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_UPDATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 0, "PGW Set FQDN" },
    {  GTPV2_UPDATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 1, "Alternative PGW-C/SMF FQDN" },
    {  GTPV2_UPDATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 0, "Alternative PGW-C/SMF Address" },
    {  GTPV2_UPDATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 1, "New PGW-C/SMF Address" },
    {  GTPV2_UPDATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 2, "New PGW Control Plane IP Address" },
    {  GTPV2_UPDATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 3, "New SGW-C Address" },
    {  GTPV2_UPDATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_GROUP_ID, 0, "Group Id" },
    {  GTPV2_UPDATE_BEARER_REQUEST, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_GROUP_ID, 1, "New Group Id" },

    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 0, "MME-FQ-CSID" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 1, "SGW-FQ-CSID" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 2, "ePDG-FQ-CSID" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_FQ_CSID, 3, "TWAN-FQ-CSID" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "MME/S4-SGSN Overload Control Info" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 2, "TWAN/ePDG Overload Control Info" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_TWAN_IDENTIFIER, 0, "TWAN Identifier" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_TWAN_IDENTIFIER, 1, "WLAN Location Info" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_TWAN_ID_TS, 1, "WLAN Location Timestamp" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_PORT_NR, 0, "UE UDP Port" },
    {  GTPV2_UPDATE_BEARER_RESPONSE, 0, GTPV2_IE_PORT_NR, 1, "UE TCP Por" },

    {  GTPV2_DELETE_BEARER_COMMAND, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 0, "MME/S4-SGSN Overload Control Info" },
    {  GTPV2_DELETE_BEARER_COMMAND, 0, GTPV2_IE_OVERLOAD_CONTROL_INF, 1, "SGW Overload Control Info" },

    {  GTPV2_DELETE_BEARER_FAILURE_INDICATION, 0, GTPV2_IE_LOAD_CONTROL_INF, 0, "PGW node level Load Control Info" },
    {  GTPV2_DELETE_BEARER_FAILURE_INDICATION, 0, GTPV2_IE_LOAD_CONTROL_INF, 1, "SGW node level Load Control Info" },

    {  GTPV2_MODIFY_ACESSS_BEARER_REQUEST, 0, GTPV2_IE_BEARER_CTX, 0, "Bearer Contexts to be Modified" },
    {  GTPV2_MODIFY_ACESSS_BEARER_REQUEST, 0, GTPV2_IE_BEARER_CTX, 1, "Bearer Contexts to be Removed" },

    {  GTPV2_MODIFY_ACCESS_BEARER_RESPONSE, 0, GTPV2_IE_BEARER_CTX, 0, "Bearer Contexts to be Modified" },
    {  GTPV2_MODIFY_ACCESS_BEARER_RESPONSE, 0, GTPV2_IE_BEARER_CTX, 1, "Bearer Contexts to be Removed" },

    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_F_CONTAINER, 0, "E-UTRAN Transparent Container" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_F_CONTAINER, 1, "UTRAN Transparent Container" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_F_CONTAINER, 2, "BSS Container" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IP_ADDRESS, 0, "HRPD access node S101 IP Address" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IP_ADDRESS, 1, "1xIWS S102 IP Address" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_CAUSE, 0, "S1-AP Cause" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_CAUSE, 1, "RANAP Cause" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_CAUSE, 2, "BSSGP Cause" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_RFSP_INDEX, 0, "Subscribed RFSP Index" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_RFSP_INDEX, 1, "RFSP Index in Use" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_FQDN, 0, "SGW FQDN" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_FQDN, 1, "SGSN FQDN" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_FQDN, 2, "MME FQDN" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_ADDITIONAL_RRM_POLICY_INDEX, 0, "Subscribed Additional RRM Policy Index" },
    {  GTPV2_FORWARD_RELOCATION_REQ, 0, GTPV2_IE_ADDITIONAL_RRM_POLICY_INDEX, 1, "Additional RRM Policy Index in Use" },
    {  GTPV2_FORWARD_RELOCATION_REQ, GTPV2_IE_PDN_CONNECTION, GTPV2_IE_FQDN, 0, "PGW FQDN" },
    {  GTPV2_FORWARD_RELOCATION_REQ, GTPV2_IE_PDN_CONNECTION, GTPV2_IE_FQDN, 1, "Local Home Network ID" },
    {  GTPV2_FORWARD_RELOCATION_REQ, GTPV2_IE_V2X_CONTEXT, GTPV2_IE_SERVICES_AUTHORIZED, 0, "LTE V2X Service Authorized" },
    {  GTPV2_FORWARD_RELOCATION_REQ, GTPV2_IE_V2X_CONTEXT, GTPV2_IE_SERVICES_AUTHORIZED, 1, "NR V2X Service Authorized" },
    {  GTPV2_FORWARD_RELOCATION_REQ, GTPV2_IE_V2X_CONTEXT, GTPV2_IE_BIT_RATE, 0, "LTE UE Sidelink Aggregate Maximum Bit Rate" },
    {  GTPV2_FORWARD_RELOCATION_REQ, GTPV2_IE_V2X_CONTEXT, GTPV2_IE_BIT_RATE, 1, "NR UE Sidelink Aggregate Maximum Bit Rate" },
    {  GTPV2_FORWARD_RELOCATION_REQ, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 0, "PGW Set FQDN" },
    {  GTPV2_FORWARD_RELOCATION_REQ, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 1, "Alternative PGW-C/SMF FQDN" },
    {  GTPV2_FORWARD_RELOCATION_REQ, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 0, "Alternative PGW-C/SMF Address" },
    {  GTPV2_FORWARD_RELOCATION_REQ, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 1, "New PGW-C/SMF Address" },

    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_BEARER_CTX, 0, "List of Set-up Bearers" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_BEARER_CTX, 1, "List of Set-up RABs" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_BEARER_CTX, 2, "List of Set-up PFCs" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_BEARER_CTX, 2, "List of Set-up Bearers for SCEF PDN Connections" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_CAUSE, 0, "S1-AP Cause" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_CAUSE, 1, "RANAP Cause" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_CAUSE, 2, "BSSGP Cause" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_F_CONTAINER, 0, "E-UTRAN Transparent Container" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_F_CONTAINER, 1, "UTRAN Transparent Container" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_F_CONTAINER, 2, "BSS Container" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_FQDN, 0, "SGSN Node Name" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_FQDN, 1, "MME Node Name" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_NODE_IDENTIFIER, 0, "SGSN Identifier" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_NODE_IDENTIFIER, 1, "MME Identifier" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_NODE_IDENTIFIER, 2, "SGSN Identifier for MT-SMS" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_NODE_IDENTIFIER, 3, "MME Identifier for MT-SMS" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_NODE_NUMBER, 0, "SGSN Number" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_NODE_NUMBER, 1, "MME Number for MT-SMS" },
    {  GTPV2_FORWARD_RELOCATION_RESP, 0, GTPV2_IE_NODE_NUMBER, 2, "MSC Number" },

    {  GTPV2_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE, 0, GTPV2_IE_SECONDARY_RAT_USAGE_DATA_REPORT, 0, "Secondary RAT Usage Data Report" },
    {  GTPV2_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE, 0, GTPV2_IE_SECONDARY_RAT_USAGE_DATA_REPORT, 1, "Secondary RAT Usage Data Report from NG-RAN" },

    {  GTPV2_CONTEXT_REQUEST, 0, GTPV2_IE_FQDN, 0, "SGSN Node Name" },
    {  GTPV2_CONTEXT_REQUEST, 0, GTPV2_IE_FQDN, 1, "MME Node Name" },
    {  GTPV2_CONTEXT_REQUEST, 0, GTPV2_IE_NODE_IDENTIFIER, 0, "SGSN Identifier" },
    {  GTPV2_CONTEXT_REQUEST, 0, GTPV2_IE_NODE_IDENTIFIER, 1, "MME Identifier" },

    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IP_ADDRESS, 0, "HRPD access node S101 IP Address" },
    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IP_ADDRESS, 1, "1xIWS S102 IP Address" },
    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IE_RFSP_INDEX, 0, "Subscribed RFSP Index" },
    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IE_RFSP_INDEX, 1, "RFSP Index in Use" },
    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IE_FQDN, 0, "SGW Node Name" },
    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IE_FQDN, 1, "SGSN Node Name" },
    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IE_FQDN, 2, "MME Node Name" },
    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IE_INTEGER_NUMBER, 0, "UE Usage Type" },
    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IE_INTEGER_NUMBER, 1, "Remaining Running Service Gap Timer" },
    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IE_ADDITIONAL_RRM_POLICY_INDEX, 0, "Subscribed Additional RRM Policy Index" },
    {  GTPV2_CONTEXT_RESPONSE, 0, GTPV2_IE_ADDITIONAL_RRM_POLICY_INDEX, 1, "Additional RRM Policy Index in Use" },
    {  GTPV2_CONTEXT_RESPONSE, GTPV2_IE_PDN_CONNECTION, GTPV2_IE_FQDN, 0, "PGW FQDN" },
    {  GTPV2_CONTEXT_RESPONSE, GTPV2_IE_PDN_CONNECTION, GTPV2_IE_FQDN, 1, "Local Home Network ID" },
    {  GTPV2_CONTEXT_RESPONSE, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 0, "PGW Set FQDN" },
    {  GTPV2_CONTEXT_RESPONSE, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IE_PGW_FQDN, 1, "Alternative PGW-C/SMF FQDN" },
    {  GTPV2_CONTEXT_RESPONSE, GTPV2_IE_PGW_CHANGE_INFO, GTPV2_IP_ADDRESS, 0, "Alternative PGW-C/SMF Address" },

    {  GTPV2_CONTEXT_ACKNOWLEDGE, 0, GTPV2_IE_NODE_NUMBER, 0, "SGSN Number" },
    {  GTPV2_CONTEXT_ACKNOWLEDGE, 0, GTPV2_IE_NODE_NUMBER, 1, "MME Number for MT-SMS" },
    {  GTPV2_CONTEXT_ACKNOWLEDGE, 0, GTPV2_IE_NODE_IDENTIFIER, 0, "SGSN Identifier for MT-SMS" },
    {  GTPV2_CONTEXT_ACKNOWLEDGE, 0, GTPV2_IE_NODE_IDENTIFIER, 1, "MME Identifier for MT-SMS" },

    {  GTPV2_CONFIGURATION_TRANSFER_TUNNEL, 0, GTPV2_IE_TARGET_ID, 0, "Target eNodeB ID / en-gNB ID / gnB ID" },
    {  GTPV2_CONFIGURATION_TRANSFER_TUNNEL, 0, GTPV2_IE_TARGET_ID, 1, "Connected Target eNodeB ID" },

    {  0, 0, 0, 0, NULL },
};

#define NUM_GTPV2_IE_INFO_ELEM_INSTANCES array_length(gtpv2_information_element_instance_vals)

/* Code to dissect IE's */

static void
dissect_gtpv2_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}

/*
 * 8.3 International Mobile Subscriber Identity (IMSI)
 *
 * IMSI is defined in 3GPP TS 23.003
 * Editor's note: IMSI coding will be defined in 3GPP TS 24.301
 * Editor's note: In the first release of GTPv2 spec (TS 29.274v8.0.0) n = 8.
 * That is, the overall length of the IE is 11 octets.
 */

static void
dissect_gtpv2_imsi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args)
{
    int          offset = 0;
    const char *imsi_str;

    /* Fetch the BCD encoded digits from tvb low half byte, formating the digits according to
     * a default digit set of 0-9 returning "?" for overdecadic digits a pointer to the wmem
     * allocated string will be returned.
     */
    imsi_str =  dissect_e212_imsi(tvb, pinfo, tree,  offset, length, false);
    proto_item_append_text(item, "%s", imsi_str);

    if (g_gtp_session) {
        args->imsi = imsi_str;
    }
}

/*
 * 8.4 Cause
 */

/* Table 8.4-1: Cause values */
static const value_string gtpv2_cause_vals[] = {
    {0, "Reserved"},
    /* Request / Initial message */
    {  1, "Reserved"},
    {  2, "Local Detach"},
    {  3, "Complete Detach"},
    {  4, "RAT changed from 3GPP to Non-3GPP"},
    {  5, "ISR deactivation"},
    {  6, "Error Indication received from RNC/eNodeB/S4-SGSN"},
    {  7, "IMSI Detach Only"},
    {  8, "Reactivation Requested"},
    {  9, "PDN reconnection to this APN disallowed"},
    { 10, "Access changed from Non-3GPP to 3GPP"},
    { 11, "PDN connection inactivity timer expires"},
    { 12, "PGW not responding"},
    { 13, "Network Failure"},
    { 14, "QoS parameter mismatch"},
    { 15, "EPS to 5GS Mobility"},
    /* Acceptance in a Response / triggered message */
    { 16, "Request accepted"},
    { 17, "Request accepted partially"},
    { 18, "New PDN type due to network preference"},
    { 19, "New PDN type due to single address bearer only"},
    /* 20-63 Spare. This value range shall be used by Cause values in an acceptance response/triggered message */
    { 20, "Spare"},
    { 21, "Spare"},
    { 22, "Spare"},
    { 23, "Spare"},
    { 24, "Spare"},
    { 25, "Spare"},
    { 26, "Spare"},
    { 27, "Spare"},
    { 28, "Spare"},
    { 29, "Spare"},
    { 30, "Spare"},
    { 31, "Spare"},
    { 32, "Spare"},
    { 33, "Spare"},
    { 34, "Spare"},
    { 35, "Spare"},
    { 36, "Spare"},
    { 37, "Spare"},
    { 38, "Spare"},
    { 39, "Spare"},
    { 40, "Spare"},
    { 41, "Spare"},
    { 42, "Spare"},
    { 43, "Spare"},
    { 44, "Spare"},
    { 45, "Spare"},
    { 46, "Spare"},
    { 47, "Spare"},
    { 48, "Spare"},
    { 49, "Spare"},
    { 50, "Spare"},
    { 51, "Spare"},
    { 52, "Spare"},
    { 53, "Spare"},
    { 54, "Spare"},
    { 55, "Spare"},
    { 56, "Spare"},
    { 57, "Spare"},
    { 58, "Spare"},
    { 59, "Spare"},
    { 60, "Spare"},
    { 61, "Spare"},
    { 62, "Spare"},
    { 63, "Spare"},
    /* Rejection in a Response / triggered message */
    { 64, "Context Not Found"},
    { 65, "Invalid Message Format"},
    { 66, "Version not supported by next peer"},
    { 67, "Invalid length"},
    { 68, "Service not supported"},
    { 69, "Mandatory IE incorrect"},
    { 70, "Mandatory IE missing"},
    { 71, "Shall not be used"},
    { 72, "System failure"},
    { 73, "No resources available"},
    { 74, "Semantic error in the TFT operation"},
    { 75, "Syntactic error in the TFT operation"},
    { 76, "Semantic errors in packet filter(s)"},
    { 77, "Syntactic errors in packet filter(s)"},
    { 78, "Missing or unknown APN"},
    { 79, "Shall not be used"},
    { 80, "GRE key not found"},
    { 81, "Relocation failure"},
    { 82, "Denied in RAT"},
    { 83, "Preferred PDN type not supported"},
    { 84, "All dynamic addresses are occupied"},
    { 85, "UE context without TFT already activated"},
    { 86, "Protocol type not supported"},
    { 87, "UE not responding"},
    { 88, "UE refuses"},
    { 89, "Service denied"},
    { 90, "Unable to page UE"},
    { 91, "No memory available"},
    { 92, "User authentication failed"},
    { 93, "APN access denied - no subscription"},
    { 94, "Request rejected(reason not specified)"},
    { 95, "P-TMSI Signature mismatch"},
    { 96, "IMSI/IMEI not known"},
    { 97, "Semantic error in the TAD operation"},
    { 98, "Syntactic error in the TAD operation"},
    { 99, "Shall not be used"},
    {100, "Remote peer not responding"},
    {101, "Collision with network initiated request"},
    {102, "Unable to page UE due to Suspension"},
    {103, "Conditional IE missing"},
    {104, "APN Restriction type Incompatible with currently active PDN connection"},
    {105, "Invalid overall length of the triggered response message and a piggybacked initial message"},
    {106, "Data forwarding not supported"},
    {107, "Invalid reply from remote peer"},
    {108, "Fallback to GTPv1"},
    {109, "Invalid peer"},
    {110, "Temporarily rejected due to handover/TAU/RAU procedure in progress"},
    {111, "Modifications not limited to S1-U bearers"},
    {112, "Request rejected for a PMIPv6 reason "},
    {113, "APN Congestion"},
    {114, "Bearer handling not supported"},
    {115, "UE already re-attached"},
    {116, "Multiple PDN connections for a given APN not allowed"},
    {117, "Target access restricted for the subscriber"},
    {118, "Shall not be used. See NOTE 2 and NOTE 3."},
    {119, "MME/SGSN refuses due to VPLMN Policy"},
    {120, "GTP-C Entity Congestion"},
    {121, "Late Overlapping Request"},
    {122, "Timed out Request"},
    {123, "UE is temporarily not reachable due to power saving"},
    {124, "Relocation failure due to NAS message redirection"},
    {125, "UE not authorised by OCS or external AAA Server"},
    {126, "Multiple accesses to a PDN connection not allowed"},
    {127, "Request rejected due to UE capability"},
    {128, "S1-U Path Failure" },
    {129, "5GC not allowed" },
    {130, "PGW mismatch with network slice subscribed by the UE" },
    {131, "Rejection due to paging restriction" },

    /* 132-239 Spare. For future use in a triggered/response message  */
    /* 240-255 Spare. For future use in an initial/request message */
    {0, NULL}
};
value_string_ext gtpv2_cause_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_cause_vals);

/* Table 8.4-1: CS (Cause Source) */
static const true_false_string gtpv2_cause_cs = {
    "Originated by remote node",
    "Originated by node sending the message",
};

static void
dissect_gtpv2_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args)
{
    int    offset = 0;
    uint8_t tmp;

    /* Cause value octet 5 */
    tmp = tvb_get_uint8(tvb, offset);
    if (g_gtp_session) {
        args->last_cause = tmp;
    }
    proto_tree_add_item(tree, hf_gtpv2_cause, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Add Cause to ie_tree */
    proto_item_append_text(item, "%s (%u)", val_to_str_ext_const(tmp, &gtpv2_cause_vals_ext, "Unknown"), tmp);
    offset += 1;

    /* Octet 6 Spare PCE BCE CS */
    static int* const oct6_flags[] = {
        &hf_gtpv2_spare_b7_b3,
        &hf_gtpv2_cause_pce,
        &hf_gtpv2_cause_bce,
        &hf_gtpv2_cause_cs,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct6_flags, ENC_NA);
    offset += 1;

    /* If n = 2, a = 0 and the Cause IE shall be 6 octets long.
     * Therefore, octets "a(n+1) to a(n+4)" will not be present.
     * If n = 6, a = 1 and the Cause IE will be 10 octets long.
     */
    if ( length == 2 ) {
        return;
    }
    /*
     * If the rejection is due to a mandatory IE or a verifiable conditional IE is faulty
     * or missing, the offending IE shall be included within an additional field "a(n+1)
     * to a(n+4)". Only Type and Instance fields of the offending IE that caused the
     * rejection have a meaning. The length in the Octet 8-9 and spare bits in the Octet 10
     * shall be set to "0". In this case, the value of "n" shall be "6".
     * Otherwise, the value of "n" is equal to "2".
     */

    /* Type of the offending IE */
    proto_tree_add_item(tree, hf_gtpv2_cause_off_ie_t, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Length */
    proto_tree_add_item(tree, hf_gtpv2_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* a(n+4) Spare Instance */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_half_octet, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_instance, tvb, offset, 1, ENC_BIG_ENDIAN);

}

/*
 * 8.5 Recovery (Restart Counter)
 */
static void
dissect_gtpv2_recovery(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int    offset = 0;
    uint8_t recovery;

    recovery = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_rec, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%u", recovery);

}


/*Start SRVCC Messages*/

/* 6.2 STN-SR */
static void
dissect_gtpv2_stn_sr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_item *stn_sr_item;
    proto_tree *sub_tree;
    tvbuff_t   *new_tvb;
    int         offset = 0;

    stn_sr_item = proto_tree_add_item(tree, hf_gtpv2_stn_sr, tvb, offset, length, ENC_NA);
    new_tvb = tvb_new_subset_length(tvb, offset, length);
    sub_tree = proto_item_add_subtree(stn_sr_item, ett_gtpv2_stn_sr);

    /* Octet 5
     * contains the Nature of Address and Numbering Plan Indicator (NANPI) of the "AddressString" ASN.1 type (see 3GPP
     * TS 29.002 [11]). Octets 6 to (n+4) contain the actual STN-SR (digits of an address encoded as a TBCD-STRING as in
     * the "AddressString" ASN.1 type). For an odd number of STN-SR digits, bits 8 to 5 of the last octet are encoded with the
     * filler "1111".
     */
    dissect_gsm_map_msisdn(new_tvb, pinfo, sub_tree);
}

/* 6.3 Source to Target Transparent Container */

static void
dissect_gtpv2_src_tgt_trans_con(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_len_trans_con, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /*ra_type_flag = 0;*/

    /* Transparent Container
     * When target network is GERAN, this container carries the Old BSS to New BSS
     * Information IE defined in 3GPP TS 48.008 [8]. When target network is UTRAN, this container carries the Source RNC
     * to Target RNC Transparent Container IE defined in 3GPP TS 25.413 [9]. The Transparent container field includes the
     * IE value part as it is specified in the respective specification.
     */
    proto_tree_add_item(tree, hf_gtpv2_transparent_container, tvb, offset, length-1, ENC_NA);
    /*
    * bssmap_old_bss_to_new_bss_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo);
    * dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU
    */
    if ((message_type == GTPV2_SRVCC_PS_TO_CS_REQUEST) && (pref_decode_srvcc_p2c_trans_cont == PREF_DECODE_SRVCC_P2C_TRANS_CONT_TARGET_UTRAN)) {
        tvbuff_t   *new_tvb;
        proto_tree *sub_tree;

        sub_tree = proto_tree_add_subtree(tree, tvb, offset, length-1, ett_gtpv2_utran_con, NULL, "Source RNC to Target RNC Transparent Container");
        new_tvb = tvb_new_subset_remaining(tvb, offset);
        dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU(new_tvb, pinfo, sub_tree, NULL);
    }

}

/* 6.4 Target to Source Transparent Container */
static void
dissect_gtpv2_tgt_src_trans_con(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_len_trans_con, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Transparent Container */
    proto_tree_add_item(tree, hf_gtpv2_transparent_container, tvb, offset, length-1, ENC_NA);

    /* It's too hard to figure out the content...
    6.4 Target to Source Transparent Container

    The Target to Source Transparent Container contains information that shall be transferred transparently by CN entities
    from the target RAN to the source RAN.

    When the target network is GERAN, the Transparent container field contains the value part of the Layer 3 Information
    IE defined in 3GPP TS 48.008 [8], i.e., octets 3 to n, excluding octet 1 (Element ID) and octet 2 (Length).

    When the target network is UTRAN, this container carries the Target RNC to Source RNC Transparent Container IE
    defined in 3GPP TS 25.413 [9]. The Transparent container field contains a transparent copy of the corresponding
    ASN.1/PER IE (see subclauses 8.2.2 and 8.48 in 3GPP TS 29.274 [3]).

    When the target network is E-UTRAN, the container carries the Target eNB To Source eNB Transparent Container IE
    defined in 3GPP TS 36.413 [14]. The Transparent container field contains a transparent copy of the corresponding
    ASN.1/PER IE (see subclauses 8.2.2 and 8.48 in 3GPP TS 29.274 [3]).

    The receiver of this Information Element shall ignore the length of the transparent container encoded in octet 5 and shall
    derive the actual length of the container from the length encoded in octets 2 to 3 minus 1.

    For backward compatibility, the sender of this Information Element shall set the octet 5 to the actual length of the
    transparent container if the size of the container is smaller or equal to 255 octets, and to the value "255" otherwise.

    */
    if ((message_type == GTPV2_SRVCC_PS_TO_CS_RESPONSE) && (pref_decode_srvcc_p2c_trans_cont == PREF_DECODE_SRVCC_P2C_TRANS_CONT_TARGET_UTRAN)) {
        tvbuff_t   *new_tvb;
        proto_tree *sub_tree;

        sub_tree = proto_tree_add_subtree(tree, tvb, offset, length-1, ett_gtpv2_utran_con, NULL, "Target RNC to Source RNC Transparent Container");
        new_tvb = tvb_new_subset_remaining(tvb, offset);
        dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU(new_tvb, pinfo, sub_tree, NULL);
    }

}

/* 6.5 MM Context for E-UTRAN SRVCC */
static void
dissect_gtpv2_mm_con_eutran_srvcc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    uint8_t     elm_len;
    proto_tree *ms_tree, *fi;

    proto_tree_add_item(tree, hf_gtpv2_eksi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_gtpv2_cksrvcc, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_gtpv2_iksrvcc, tvb, offset, 16, ENC_NA);
    offset += 16;

  /* For each of the Mobile Station Classmark 2, Mobile Station Classmark 3 and Supported Codec List parameters, if they are not available,
     then the associated length field shall be set to zero, and the particular parameter field shall not be present.
     */
  /* Length of Mobile Station Classmark2  */
    elm_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (elm_len) {
        fi = proto_tree_add_item(tree, hf_gtpv2_mobile_station_classmark2, tvb, offset, elm_len, ENC_NA);
        ms_tree = proto_item_add_subtree(fi, ett_gtpv2_ms_mark);
        de_ms_cm_2(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);
        offset += elm_len;
    }

  /* Length of Mobile Station Classmark3  */
    elm_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (elm_len) {
        fi = proto_tree_add_item(tree, hf_gtpv2_mobile_station_classmark3, tvb, offset, elm_len, ENC_NA);
        ms_tree = proto_item_add_subtree(fi, ett_gtpv2_ms_mark);
        de_ms_cm_3(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);
        offset += elm_len;
    }

   /*Length of Supported Codec List  */
    elm_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_supp_codec_list, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (elm_len) {
        fi = proto_tree_add_item(tree, hf_gtpv2_supported_codec_list, tvb, offset, elm_len, ENC_NA);
        ms_tree = proto_item_add_subtree(fi, ett_gtpv2_supp_codec_list);
        de_sup_codec_list(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);
    }
}

/* 6.6 MM Context for UTRAN SRVCC */
static void
dissect_gtpv2_mm_con_utran_srvcc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    uint8_t     elm_len;
    proto_tree *ms_tree, *fi;

    proto_tree_add_item(tree, hf_gtpv2_ksi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_gtpv2_utran_srvcc_ck_cs, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_gtpv2_utran_srvcc_ik_cs, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_gtpv2_utran_srvcc_kc, tvb, offset, 8, ENC_NA);
    offset += 8;
    proto_tree_add_item(tree, hf_gtpv2_cksn, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

   /* For each of the Mobile Station Classmark 2, Mobile Station Classmark 3 and Supported Codec List parameters, if they are not available,
      then the associated length field shall be set to zero, and the particular parameter field shall not be present.
   */

    /*Length of Mobile Station Classmark2  */
    elm_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (elm_len) {
        fi = proto_tree_add_item(tree, hf_gtpv2_mobile_station_classmark2, tvb, offset, elm_len, ENC_NA);
        ms_tree = proto_item_add_subtree(fi, ett_gtpv2_ms_mark);
        de_ms_cm_2(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);
        offset += elm_len;
    }

    /*Length of Mobile Station Classmark3  */
    elm_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (elm_len) {
        fi = proto_tree_add_item(tree, hf_gtpv2_mobile_station_classmark3, tvb, offset, elm_len, ENC_NA);
        ms_tree = proto_item_add_subtree(fi, ett_gtpv2_ms_mark);
        de_ms_cm_3(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);
        offset += elm_len;
    }

    /*Length of Supported Codec List  */
    elm_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_supp_codec_list, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (elm_len) {
        fi = proto_tree_add_item(tree, hf_gtpv2_supported_codec_list, tvb, offset, elm_len, ENC_NA);
        ms_tree = proto_item_add_subtree(fi, ett_gtpv2_supp_codec_list);
        de_sup_codec_list(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);
    }

}

/* 6.7 SRVCC Cause */
static const value_string gtpv2_srvcc_cause_vals[] = {
    {0, "Reserved"},
    {1, "Unspecified"},
    {2, "Handover/Relocation cancelled by source system "},
    {3, "Handover /Relocation Failure with Target system"},
    {4, "Handover/Relocation Target not allowed"},
    {5, "Unknown Target ID"},
    {6, "Target Cell not available"},
    {7, "No Radio Resources Available in Target Cell"},
    {8, "Failure in Radio Interface Procedure"},
    {9, "Permanent session leg establishment error"},
    {10, "Temporary session leg establishment error"},

    {0, NULL}
};
static value_string_ext gtpv2_srvcc_cause_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_srvcc_cause_vals);

static void
dissect_gtpv2_srvcc_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int    offset = 0;
    uint8_t srvcc_cause;

    srvcc_cause = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_srvcc_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s (%u)", val_to_str_ext_const(srvcc_cause, &gtpv2_srvcc_cause_vals_ext, "Unknown"), srvcc_cause);

}

/*
 * 3GPP TS 29.280 version 10.3.0
 * 6.8 Target RNC ID
 */
static void
dissect_gtpv2_tgt_rnc_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    uint16_t    rnc_id;
    proto_tree *subtree;
    uint32_t    mcc;
    uint32_t    mnc;
    uint32_t    lac;
    uint32_t    curr_offset;

    /*ra_type_flag = 1;*/ /*Flag to be set to differentiate GERAN and UTRAN*/
    curr_offset = offset;

    mcc  = (tvb_get_uint8(tvb, curr_offset)   & 0x0f) << 8;
    mcc |= (tvb_get_uint8(tvb, curr_offset)   & 0xf0);
    mcc |= (tvb_get_uint8(tvb, curr_offset+1) & 0x0f);
    mnc  = (tvb_get_uint8(tvb, curr_offset+2) & 0x0f) << 8;
    mnc |= (tvb_get_uint8(tvb, curr_offset+2) & 0xf0);
    mnc |= (tvb_get_uint8(tvb, curr_offset+1) & 0xf0) >> 4;
    if ((mnc & 0x000f) == 0x000f)
        mnc = mnc >> 4;

    lac = tvb_get_ntohs(tvb, curr_offset + 3);
    rnc_id = tvb_get_ntohs(tvb,  curr_offset + 5);

    subtree = proto_tree_add_subtree_format(tree,
                                   tvb, curr_offset, 6, ett_gtpv2_rai, NULL,
                                   "Routing area identification: %x-%x-%u-%u",
                                   mcc, mnc, lac, rnc_id);

    dissect_e212_mcc_mnc(tvb, pinfo, subtree, offset, E212_RAI, true);
    curr_offset+=3;

    proto_tree_add_item(subtree, hf_gtpv2_lac,    tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset+=2;
    proto_tree_add_item(subtree, hf_gtpv2_rnc_id, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    /*curr_offset+=2;*/

    /* no length check possible */


}

/*
 * 3GPP TS 29.280
 * 6.9 Target Global Cell ID
 * The encoding of this IE is defined in 3GPP TS 29.002
 *  GlobalCellId ::= OCTET STRING (SIZE (5..7))
 *      -- Refers to Cell Global Identification defined in TS 3GPP TS 23.003 [17].
 *      -- The internal structure is defined as follows:
 *      -- octet 1 bits 4321    Mobile Country Code 1st digit
 *      --         bits 8765    Mobile Country Code 2nd digit
 *      -- octet 2 bits 4321    Mobile Country Code 3rd digit
 *      --         bits 8765    Mobile Network Code 3rd digit
 *      --                      or filler (1111) for 2 digit MNCs
 *      -- octet 3 bits 4321    Mobile Network Code 1st digit
 *      --         bits 8765    Mobile Network Code 2nd digit
 *      -- octets 4 and 5       Location Area Code according to TS 3GPP TS 24.008 [35]
 *      -- octets 6 and 7       Cell Identity (CI) according to TS 3GPP TS 24.008 [35]
 */
static void
dissect_gtpv2_tgt_global_cell_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    uint8_t     tgt_cell_id;
    proto_tree *subtree;
    uint32_t    mcc;
    uint32_t    mnc;
    uint32_t    lac;
    uint32_t    curr_offset;

    curr_offset = offset;

    mcc  = (tvb_get_uint8(tvb, curr_offset)   & 0x0f) << 8;
    mcc |= (tvb_get_uint8(tvb, curr_offset)   & 0xf0);
    mcc |= (tvb_get_uint8(tvb, curr_offset+1) & 0x0f);
    mnc  = (tvb_get_uint8(tvb, curr_offset+2) & 0x0f) << 8;
    mnc |= (tvb_get_uint8(tvb, curr_offset+2) & 0xf0);
    mnc |= (tvb_get_uint8(tvb, curr_offset+1) & 0xf0) >> 4;
    if ((mnc & 0x000f) == 0x000f)
        mnc = mnc >> 4;

    lac = tvb_get_ntohs(tvb, curr_offset + 3);
    tgt_cell_id = tvb_get_uint8(tvb,  curr_offset + 5);

    subtree = proto_tree_add_subtree_format(tree,
                                   tvb, curr_offset, 6, ett_gtpv2_rai, NULL,
                                   "Routing area identification: %x-%x-%u-%u",
                                   mcc, mnc, lac, tgt_cell_id);

    dissect_e212_mcc_mnc(tvb, pinfo, subtree, offset, E212_RAI, true);

    proto_tree_add_item(subtree, hf_gtpv2_lac,           tvb, curr_offset + 3, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gtpv2_tgt_g_cell_id, tvb, curr_offset + 5, 2, ENC_BIG_ENDIAN);

    proto_item_append_text(item, "%x-%x-%u-%u", mcc, mnc, lac, tgt_cell_id);
    /* no length check possible */

}

/* 6.10 Tunnel Endpoint Identifier for Control Plane (TEID-C) */
static void
dissect_gtpv2_teid_c(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_teid_c, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if (length > 4)
        proto_tree_add_item(tree, hf_gtpv2_teid_c_spare, tvb, offset, length-4, ENC_NA);

    proto_item_append_text(item, "%u", tvb_get_ntohl(tvb, offset-4));
}

/* 6.11 Sv Flags */
static void
dissect_gtpv2_sv_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    static int* const sv_flags[] = {
        &hf_gtpv2_sv_sti,
        &hf_gtpv2_sv_ics,
        &hf_gtpv2_sv_emind,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, sv_flags, ENC_NA);
    offset += 1;
    if (length > 1)
        proto_tree_add_item(tree, hf_gtpv2_teid_c_spare, tvb, offset, length-1, ENC_NA);
}

/* 6.12 Service Area Identifier */

static void
dissect_gtpv2_sai(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    /* 5 MCC digit 2 MCC digit 1
     * 6 MNC digit 3 MCC digit 3
     * 7 MNC digit 2 MNC digit 1
     */
    dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_SAI, true);
    offset += 3;

    /* The Location Area Code (LAC) consists of 2 octets. Bit 8 of Octet 8 is the most significant bit and bit 1 of Octet 9 the
     * least significant bit. The coding of the location area code is the responsibility of each administration. Coding using full
     * hexadecimal representation shall be used.
     */
    proto_tree_add_item(tree, hf_gtpv2_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* The Service Area Code (SAC) consists of 2 octets. Bit 8 of Octet 10 is the most significant bit and bit 1 of Octet 11 the
     * least significant bit. The SAC is defined by the operator. See 3GPP TS 23.003 [4] subclause 12.5 for more information
     */
    proto_tree_add_item(tree, hf_gtpv2_sac, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/* 6.13 MM Context for CS to PS SRVCC */
static void
dissect_gtpv2_mm_ctx_for_cs_to_ps_srvcc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    /* Octet 5 KSI"PS */
    proto_tree_add_item(tree, hf_gtpv2_ksi_ps, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* octet 6 - 21 CK'PS */
    proto_tree_add_item(tree, hf_gtpv2_ck_ps, tvb, offset, 16, ENC_NA);
    offset+=16;

    /* octet 22 - 37 IK'PS */
    proto_tree_add_item(tree, hf_gtpv2_ik_ps, tvb, offset, 16, ENC_NA);
    offset += 16;

    /* octet 38 to 45 kc'PS */
    proto_tree_add_item(tree, hf_gtpv2_kc_ps, tvb, offset, 8, ENC_NA);
    offset += 8;

    /* Octet 46 CKSN"PS */
    proto_tree_add_item(tree, hf_gtpv2_cksn_ps, tvb, offset, 1, ENC_BIG_ENDIAN);
    /*offset++;*/

}
/*End SRVCC Messages*/


/*
 * 8.6 Access Point Name (APN)
 * The encoding the APN field follows 3GPP TS 23.003 [2] subclause 9.1.
 * The content of the APN field shall be the full APN with both the APN Network Identifier
 * and APN Operator Identifier being present as specified in 3GPP TS 23.003 [2]
 * subclauses 9.1.1 and 9.1.2, 3GPP TS 23.060 [35] Annex A and 3GPP TS 23.401 [3] subclauses 4.3.8.1.
 */
void
dissect_gtpv2_apn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    const uint8_t *apn    = NULL;

    proto_tree_add_item_ret_string(tree, hf_gtpv2_apn, tvb, 0, length, ENC_APN_STR | ENC_NA, pinfo->pool, &apn);
    if (apn) {
        proto_item_append_text(item, "%s", apn);
    }

}

/*
 * 8.7 Aggregate Maximum Bit Rate (AMBR)
 */

void
dissect_gtpv2_ambr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_ambr_up, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_gtpv2_ambr_down, tvb, offset, 4, ENC_BIG_ENDIAN);
}

/*
 * 8.8 EPS Bearer ID (EBI)
 */
static void
dissect_gtpv2_ebi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{

    int    offset = 0;
    uint8_t ebi;

    /* Spare (all bits set to 0) B8 - B5*/
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* EPS Bearer ID (EBI) B4 - B1 */
    ebi = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%u", ebi);

}
/*
 * 8.9 IP Address
 */
static void
dissect_gtpv2_ip_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int               offset = 0;

    if (length == 4)
    {
        proto_tree_add_item(tree, hf_gtpv2_ip_address_ipv4, tvb, offset, length, ENC_BIG_ENDIAN);
        proto_item_append_text(item, "IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
    }
    else if (length == 16)
    {
        proto_tree_add_item(tree, hf_gtpv2_ip_address_ipv6, tvb, offset, length, ENC_NA);
        proto_item_append_text(item, "IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
    }
}
/*
 * 8.10 Mobile Equipment Identity (MEI)
 * The ME Identity field contains either the IMEI or the IMEISV
 * as defined in clause 6.2 of 3GPP TS 23.003 [2]. It is encoded
 * as specified in clause 7.7.53 of 3GPP TS 29.060 [4], beginning
 * with octet 4 of Figure 7.7.53.1. The IMEI(SV) digits are encoded
 * using BCD coding where IMEI is 15 BCD digits and IMEISV is 16 BCD
 * digits. For IMEI, bits 5 to 8 of the last octet shall be filled
 * with an end mark coded as '1111'.
 */

void
dissect_gtpv2_mei(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int          offset = 0;
    char         *mei_str;

    /* Fetch the BCD encoded digits from tvb low half byte, formating the digits according to
     * a default digit set of 0-9 returning "?" for overdecadic digits a pointer to the EP
     * allocated string will be returned.
     */
    proto_tree_add_item_ret_display_string(tree, hf_gtpv2_mei, tvb, offset, length, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN, pinfo->pool, &mei_str);
    proto_item_append_text(item, "%s", mei_str);
}

/*
 * 8.11 MSISDN
 *
 * MSISDN is defined in 3GPP TS 23.003
 * Editor's note: MSISDN coding will be defined in TS 24.301.
 */
static void
dissect_gtpv2_msisdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    const char *digit_str;

    /* Octets 5 to (n+4) represent the MSISDN value is in international number format
     * as described in ITU-T Rec E.164 [25] and 3GPP TS 29.002 [41].
     * MSISDN value contains only the actual MSISDN number (does not contain the "nature of
     * address indicator" octet, which indicates "international number"
     * as in 3GPP TS 29.002 [41]) and is encoded as TBCD digits, i.e.
     * digits from 0 through 9 are encoded "0000" to "1001".
     * When there is an odd number of digits, bits 8 to 5 of the last octet are encoded with
     * the filler "1111".
     */
    /* Fetch the BCD encoded digits from tvb low half byte, formating the digits according to
     * a default digit set of 0-9 returning "?" for overdecadic digits a pointer to the EP
     * allocated string will be returned.
     */
    digit_str = dissect_e164_msisdn(tvb, pinfo, tree, 0, length, E164_ENC_BCD);
    proto_item_append_text(item, "%s", digit_str);
}

/*
 * 8.12 Indication
 */
void
dissect_gtpv2_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    static int* const oct5_flags[] = {
        &hf_gtpv2_daf,
        &hf_gtpv2_dtf,
        &hf_gtpv2_hi,
        &hf_gtpv2_dfi,
        &hf_gtpv2_oi,
        &hf_gtpv2_isrsi,
        &hf_gtpv2_israi,
        &hf_gtpv2_sgwci,
        NULL
    };

    /* Octet 5 DAF DTF HI DFI OI ISRSI ISRAI SGWCI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct5_flags, ENC_NA);
    if (length == 1) {
        proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_len_invalid, tvb, 0, length, "Older version?, should be 2 octets in 8.0.0");
        return;
    }

    offset += 1;

    static int* const oct6_flags[] = {
    &hf_gtpv2_sqci,
    &hf_gtpv2_uimsi,
    &hf_gtpv2_cfsi,
    &hf_gtpv2_crsi,
    &hf_gtpv2_ps,
    &hf_gtpv2_pt,
    &hf_gtpv2_si,
    &hf_gtpv2_msv,
    NULL
    };

    /* Octet 6 SQCI UIMSI CFSI CRSI P PT SI MSV
     * 3GPP TS 29.274 version 9.4.0 Release 9
     */

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct6_flags, ENC_NA);
    offset += 1;

    if (length == 2) {
        return;
    }
    /* Only present in version 9 and higher */
    static int* const oct7_flags[] = {
        &hf_gtpv2_retloc,
        &hf_gtpv2_pbic,
        &hf_gtpv2_srni,
        &hf_gtpv2_s6af,
        &hf_gtpv2_s4af,
        &hf_gtpv2_mbmdt,
        &hf_gtpv2_israu,
        &hf_gtpv2_ccrsi,
        NULL
    };

    /* Octet 7 RetLoc PBIC SRNI S6AF S4AF MBMDT ISRAU CCRSI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct7_flags, ENC_NA);
    offset += 1;

    if (length == 3) {
        return;
    }
    static int* const oct8_flags[] = {
        &hf_gtpv2_cprai,
        &hf_gtpv2_arrl,
        &hf_gtpv2_ppof,
        &hf_gtpv2_ppon_ppei,
        &hf_gtpv2_ppsi,
        &hf_gtpv2_csfbi,
        &hf_gtpv2_clii,
        &hf_gtpv2_cpsr,
        NULL
    };

    /* Octet 8 CPRAI ARRL PPOF PPON/PPEI PPSI CSFBI CLII CPSR */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct8_flags, ENC_NA);
    offset += 1;

    if (length == 4) {
        return;
    }

    static int* const oct9_flags[] = {
        &hf_gtpv2_nsi,
        &hf_gtpv2_uasi,
        &hf_gtpv2_dtci,
        &hf_gtpv2_bdwi,
        &hf_gtpv2_psci,
        &hf_gtpv2_pcri,
        &hf_gtpv2_aosi,
        &hf_gtpv2_aopi,
        NULL
    };

    /* Octet 9 NSI UASI DTCI BDWI PSCI PCRI AOSI AOPI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct9_flags, ENC_NA);
    offset += 1;

    if (length == 5) {
        return;
    }

    static int* const oct10_flags[] = {
        &hf_gtpv2_roaai,
        &hf_gtpv2_epcosi,
        &hf_gtpv2_cpopci,
        &hf_gtpv2_pmtsmi,
        &hf_gtpv2_s11tf,
        &hf_gtpv2_pnsi,
        &hf_gtpv2_unaccsi,
        &hf_gtpv2_wpmsi,
        NULL
    };
    /* Octet 10 ROAAI EPCOSI CPOPCI PMTSMI S11TF PNSI UNACCSI WPMSI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct10_flags, ENC_NA);
    offset += 1;

    if (length == 6){
        return;
    }

    static int* const oct11_flags[] = {
        &hf_gtpv2_5gsnn26,
        &hf_gtpv2_reprefi,
        &hf_gtpv2_5gsiwk,
        &hf_gtpv2_eevrsi,
        &hf_gtpv2_ltemui,
        &hf_gtpv2_ltempi,
        &hf_gtpv2_enbcrsi,
        &hf_gtpv2_tspcmi,
        NULL
    };
    /*Octet 11 5GSNN26 REPREFI 5GSIWK EEVRSI LTEMUI LTEMPI ENBCRSI TSPCMI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct11_flags, ENC_NA);
    offset += 1;

    if (length == 7){
        return;
    }

    static int* const oct12_flags[] = {
        &hf_gtpv2_csrmfi,
        &hf_gtpv2_mtedtn,
        &hf_gtpv2_mtedta,
        &hf_gtpv2_n5gnmi,
        &hf_gtpv2_5gcnrs,
        &hf_gtpv2_5gcnri,
        &hf_gtpv2_5srhoi,
        &hf_gtpv2_ethpdn,
        NULL
    };
    /* Octet 12 CSRMFI MTEDTN MTEDTA N5GNMI 5GCNRS 5GCNRI 5SRHOI ETHPDN */

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct12_flags, ENC_NA);
    offset += 1;

    if (length == 8) {
        return;
    }

    static int* const oct13_flags[] = {
        &hf_gtpv2_nspusi,
        &hf_gtpv2_pgwrnsi,
        &hf_gtpv2_rppcsi,
        &hf_gtpv2_pgwchi,
        &hf_gtpv2_sissme,
        &hf_gtpv2_nsenbi,
        &hf_gtpv2_idfupf,
        &hf_gtpv2_emci,
        NULL
    };

    /* Octet 13 NSOUSI PGWRNSI RPPCSI PGWCHI SISSME NSENBI IDFUPF EMCI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct13_flags, ENC_NA);
    offset += 1;

    if (length == 9) {
        return;
    }

    static int* const oct14_flags[] = {
        &hf_gtpv2_spare_b7_b4,
        &hf_gtpv2_lapcosi,
        &hf_gtpv2_ltemsai,
        &hf_gtpv2_srtpi,
        &hf_gtpv2_upipsi,
        NULL
    };

    /* Octet 13 Spare LAPCOSI LTEMSAI SRTPI UPIPSI */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct14_flags, ENC_NA);
    offset += 1;

    if (length == 10) {
        return;
    }

    proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");


}

/*
 * 8.13 Protocol Configuration Options (PCO)
 * Protocol Configuration Options (PCO) is transferred via GTP tunnels. The sending entity copies the value part of the
 * PCO into the Value field of the PCO IE. The detailed coding of the PCO field from octets 5 to (n+4) shall be specified
 * as per clause 10.5.6.3 of 3GPP TS 24.008 [5], starting with octet 3.
 * Dissected in packet-gsm_a_gm.c
 */
static void
dissect_gtpv2_pco(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    switch (message_type) {
    case GTPV2_CREATE_SESSION_REQUEST:
    case GTPV2_DELETE_SESSION_REQUEST:
    case GTPV2_BEARER_RESOURCE_COMMAND:
    case GTPV2_CREATE_BEARER_RESPONSE:
    case GTPV2_UPDATE_BEARER_RESPONSE:
    case GTPV2_DELETE_BEARER_RESPONSE:
        /* PCO options as MS to network direction */
        pinfo->link_dir = P2P_DIR_UL;
        break;
    case GTPV2_CREATE_SESSION_RESPONSE:
    case GTPV2_MODIFY_BEARER_RESPONSE:
    case GTPV2_DELETE_SESSION_RESPONSE:
    case GTPV2_CREATE_BEARER_REQUEST:
    case GTPV2_UPDATE_BEARER_REQUEST:
    case GTPV2_DELETE_BEARER_REQUEST:
        /* PCO options as Network to MS direction: */
        pinfo->link_dir = P2P_DIR_DL;
        break;
    default:
        break;
    }
    de_sm_pco(tvb, tree, pinfo, 0, length, NULL, 0);
}

/*
 * 8.14 PDN Address Allocation (PAA)
 */

static const value_string gtpv2_pdn_type_vals[] = {
    {1, "IPv4"},
    {2, "IPv6"},
    {3, "IPv4/IPv6"},
    {4, "Non-IP"},
    {5, "Ethernet"},
    {0, NULL}
};
value_string_ext gtpv2_pdn_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_pdn_type_vals);

void
dissect_gtpv2_paa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int    offset = 0;
    uint8_t pdn_type;

    pdn_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_pdn_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    switch (pdn_type)
    {
    case 1:
        /* IPv4 */
        if (length != 5) {
            proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_len_invalid, tvb, 0, length,
                                         "Wrong length indicated. Expected 5, got %u", length);
            return;
        }
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, "IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        break;
    case 2:
        /* IPv6*/
        /* If PDN type value indicates IPv6, octet 6 contains the IPv6 Prefix Length.
         * Octets 7 through 22 contain an IPv6 Prefix and Interface Identifier.
         * Bit 8 of octet 7 represents the most significant bit of the IPv6 Prefix
         * and Interface Identifier and bit 1 of octet 22 the least significant bit.
         */
        if (length != 18) {
            proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_len_invalid, tvb, 0, length,
                                         "Wrong length indicated. Expected 18, got %u", length);
            return;
        }
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, "IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        break;
    case 3:
        /* IPv4/IPv6 */
        /* If PDN type value indicates IPv4v6, octet 6 contains the IPv6 Prefix Length.
         * Octets 7 through 22 contain an IPv6 Prefix and Interface Identifier.
         * Bit 8 of octet 7 represents the most significant bit of the IPv6 Prefix
         * and Interface Identifier and bit 1 of octet 22 the least significant bit.
         * Octets 23 through 26 contain an IPv4 address. Bit 8 of octet 23 represents
         * the most significant bit of the IPv4 address and bit 1 of octet 26 the least
         * significant bit.
         */
        if (length != 22) {
            proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_len_invalid, tvb, 0, length,
                                         "Wrong length indicated. Expected 22, got %u", length);
            return;
        }
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, "IPv6 %s, ", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        offset += 16;
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, "IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        break;
    case 4: /* Non IP */
    case 5: /* Ethernet */
        /* If PDN type value indicates Non-IP or Ethernet, octets from 6 to 'n+4'
           shall not be present. */
        if (length != 1) {
            proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_len_invalid, tvb, 0, length,
                                         "Wrong length indicated. Expected 1, got %u", length);
            return;
        }
    default:
        break;
    }
}
/*
 * 8.15 Bearer Quality of Service (Bearer QoS)
 */

void
dissect_gtpv2_bearer_qos(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    static int* const bearer_qos_oct1_flags[] = {
        &hf_gtpv2_bearer_qos_pci,
        &hf_gtpv2_bearer_qos_pl,
        &hf_gtpv2_bearer_qos_pvi,
        NULL
    };
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, bearer_qos_oct1_flags, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_label_qci, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_mbr_up,    tvb, offset, 5, ENC_BIG_ENDIAN);
    offset += 5;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_mbr_down,  tvb, offset, 5, ENC_BIG_ENDIAN);
    offset += 5;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_gbr_up,    tvb, offset, 5, ENC_BIG_ENDIAN);
    offset += 5;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_gbr_down,  tvb, offset, 5, ENC_BIG_ENDIAN);
}

/*
 * 8.16 Flow Quality of Service (Flow QoS)
 */

static void
dissect_gtpv2_flow_qos(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_label_qci, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_mbr_up,    tvb, offset, 5, ENC_BIG_ENDIAN);
    offset += 5;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_mbr_down,  tvb, offset, 5, ENC_BIG_ENDIAN);
    offset += 5;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_gbr_up,    tvb, offset, 5, ENC_BIG_ENDIAN);
    offset += 5;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_gbr_down,  tvb, offset, 5, ENC_BIG_ENDIAN);
}

/*
 * 8.17 RAT Type
 */
static const value_string gtpv2_rat_type_vals[] = {
    {0, "Reserved"},
    {1, "UTRAN"},
    {2, "GERAN"},
    {3, "WLAN"},
    {4, "GAN"},
    {5, "HSPA Evolution"},
    {6, "EUTRAN"},
    {7, "Virtual"},
    {8, "EUTRAN-NB-IoT"},
    {9, "LTE-M"},
    {10, "NR"},
    {11, "WB-E-UTRAN(LEO)"},
    {12, "WB-E-UTRAN(MEO)"},
    {13, "WB-E-UTRAN(GEO)"},
    {14, "WB-E-UTRAN(OTHERSAT)"},
    {15, "EUTRAN-NB-IoT(LEO)"},
    {16, "EUTRAN-NB-IoT(MEO)"},
    {17, "EUTRAN-NB-IoT(GEO)"},
    {18, "EUTRAN-NB-IoT(OTHERSAT)"},
    {19, "LTE-M(LEO)"},
    {20, "LTE-M(MEO)"},
    {21, "LTE-M(GEO)"},
    {22, "LTE-M(OTHERSAT)"},
    {0, NULL}
};
value_string_ext gtpv2_rat_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_rat_type_vals);


static void
dissect_gtpv2_rat_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    uint8_t rat_type;

    rat_type = tvb_get_uint8(tvb, 0);
    proto_tree_add_item(tree, hf_gtpv2_rat_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s (%u)", val_to_str_ext_const(rat_type, &gtpv2_rat_type_vals_ext, "Unknown"), rat_type);

}

/*
 * 8.18 Serving Network
 */
static void
dissect_gtpv2_serv_net(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    char *mcc_mnc_str;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, 0, E212_SERV_NET, true);
    proto_item_append_text(item, "%s", mcc_mnc_str);
}

/*
 * 8.19 EPS Bearer Level Traffic Flow Template (Bearer TFT)
 */

static void
dissect_gtpv2_bearer_tft(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    /* The detailed coding of Traffic Aggregate
     * Description is specified in 3GPP TS 24.008 [5] ,
     * clause 10.5.6.12, beginning with octet 3..
     * Use the decoding in packet-gsm_a_gm.c
     */
    de_sm_tflow_temp(tvb, tree, pinfo, 0, length, NULL, 0);

}
 /* 8.20 Traffic Aggregate Description (TAD)
 */
static void
dissect_gtpv2_tad(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    /* The detailed coding of Traffic Aggregate
     * Description is specified in 3GPP TS 24.008 [5] ,
     * clause 10.5.6.12, beginning with octet 3..
     * Use the decoding in packet-gsm_a_gm.c
     */
    de_sm_tflow_temp(tvb, tree, pinfo, 0, length, NULL, 0);
}

/*
 * 8.21 User Location Info (ULI)
 *
 * The flags ECGI, TAI, RAI, SAI and CGI in octed 5 indicate if the corresponding
 * fields are present in the IE or not. If one of these flags is set to "0",
 * the corresponding field is not present at all. The respective identities are defined in 3GPP
 * TS 23.003 [2].
 * Editor's Note: The definition of ECGI is missing in 3GPP TS 23.003 v8.1.0.
 * It can be found in 3GPP TS 36.413 v8.3.0, but it is expected that it will be moved
 * to 23.003 in a future version.
 */
char*
dissect_gtpv2_tai(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, bool is_5gs)
{
    char       *str = NULL;
    char       *mcc_mnc_str;
    uint32_t    tac;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, *offset, E212_TAI, true);
    *offset += 3;
    if (is_5gs) {
        proto_tree_add_item_ret_uint(tree, hf_gtpv2_5gs_tai_tac, tvb, *offset, 3, ENC_BIG_ENDIAN, &tac);
        *offset += 3;
    } else {
        proto_tree_add_item_ret_uint(tree, hf_gtpv2_tai_tac, tvb, *offset, 2, ENC_BIG_ENDIAN, &tac);
        *offset += 2;
    }
    str = wmem_strdup_printf(pinfo->pool, "%s, TAC 0x%x",
        mcc_mnc_str,
        tac);

    return str;
}

static char*
dissect_gtpv2_ecgi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset)
{
    char       *str = NULL;
    char       *mcc_mnc_str;
    uint8_t     octet;
    uint32_t    octet4;
    uint8_t     spare;
    uint32_t    ECGI;
    static int* const ECGI_flags[] = {
        &hf_gtpv2_enodebid,
        &hf_gtpv2_cellid,
        NULL
    };

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, *offset, E212_ECGI, true);
    *offset += 3;
    /* The bits 8 through 5, of octet e+3 (Fig 8.21.5-1 in TS 29.274 V8.2.0) are spare
        * and hence they would not make any difference to the hex string following it,
        * thus we directly read 4 bytes from the tvb
        */

    octet = tvb_get_uint8(tvb, *offset);
    spare = octet & 0xF0;
    octet4 = tvb_get_ntohl(tvb, *offset);
    ECGI = octet4 & 0x0FFFFFFF;
    proto_tree_add_uint(tree, hf_gtpv2_ecgi_eci_spare, tvb, *offset, 1, spare);
    /* The coding of the E-UTRAN cell identifier is the responsibility of each administration.
     * Coding using full hexadecimal representation shall be used.
     */
    proto_tree_add_bitmask(tree, tvb, *offset, hf_gtpv2_ecgi_eci, ett_gtpv2_eci, ECGI_flags, ENC_BIG_ENDIAN);
    *offset += 4;
    str = wmem_strdup_printf(pinfo->pool, "%s, ECGI 0x%x",
        mcc_mnc_str,
        ECGI);


    return str;
}

static char*
dissect_gtpv2_rai(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset)
{
    char       *str = NULL;
    char       *mcc_mnc_str;
    uint16_t    lac, rac;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, *offset, E212_RAI, true);
    *offset += 3;
    lac = tvb_get_ntohs(tvb, *offset);
    proto_tree_add_item(tree, hf_gtpv2_rai_lac, tvb, *offset, 2, ENC_BIG_ENDIAN);
    *offset += 2;
    /* 3GPP 29.274 8.21.3 RAI Field
     * "Only Octet c+5 contains the RAC. Octet c+6 is coded as all 1's (11111111)."
     * (We could, here and in GTP, check that the other octet is all 1's.)
     */
    rac = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_gtpv2_rai_rac, tvb, *offset, 1, ENC_BIG_ENDIAN);
    *offset += 2;
    str = wmem_strdup_printf(pinfo->pool, "%s, LAC 0x%x, RAC 0x%x",
        mcc_mnc_str,
        lac,
        rac);

    return str;
}

static char*
dissect_gtpv2_sai_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset)
{
    char       *str = NULL;
    char       *mcc_mnc_str;
    uint16_t    lac, sac;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, *offset, E212_SAI, true);
    *offset += 3;
    lac = tvb_get_ntohs(tvb, *offset);
    proto_tree_add_item(tree, hf_gtpv2_sai_lac, tvb, *offset, 2, ENC_BIG_ENDIAN);
    *offset += 2;
    sac = tvb_get_ntohs(tvb, *offset);
    proto_tree_add_item(tree, hf_gtpv2_sai_sac, tvb, *offset, 2, ENC_BIG_ENDIAN);
    *offset += 2;
    str = wmem_strdup_printf(pinfo->pool, "%s, LAC 0x%x, SAC 0x%x",
        mcc_mnc_str,
        lac,
        sac);

    return str;
}

static char*
dissect_gtpv2_cgi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset)
{
    char       *str = NULL;
    char       *mcc_mnc_str;
    uint16_t    lac, ci;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, *offset, E212_CGI, true);
    *offset += 3;
    lac = tvb_get_ntohs(tvb, *offset);
    proto_tree_add_item(tree, hf_gtpv2_uli_cgi_lac, tvb, *offset, 2, ENC_BIG_ENDIAN);
    *offset += 2;
    ci = tvb_get_ntohs(tvb, *offset);
    proto_tree_add_item(tree, hf_gtpv2_uli_cgi_ci, tvb, *offset, 2, ENC_BIG_ENDIAN);
    *offset += 2;
    str = wmem_strdup_printf(pinfo->pool, "%s, LAC 0x%x, CI 0x%x",
        mcc_mnc_str,
        lac,
        ci);

    return str;
}

static char*
dissect_gtpv2_macro_enodeb_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset)
{
    char       *str = NULL;
    char       *mcc_mnc_str;
    uint32_t    macro_enodeb_id;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, *offset, E212_NONE, true);
    *offset += 3;
    /* The Macro eNodeB ID consists of 20 bits.
     * Bit 4 of Octet 4 is the most significant bit and bit 1 of Octet 6 is the least significant bit.
     */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_macro_enodeb_id, tvb, *offset, 3, ENC_BIG_ENDIAN, &macro_enodeb_id);
    *offset += 3;

    str = wmem_strdup_printf(pinfo->pool, "%s, Macro eNodeB ID 0x%x",
        mcc_mnc_str,
        macro_enodeb_id);

    return str;
}

static const true_false_string gtpv2_smenb = {
    "Short Macro eNodeB ID",
    "Long Macro eNodeB ID",
};

static char*
dissect_gtpv2_ext_macro_enodeb_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, int hfindex)
{
    char       *str = NULL;
    char       *mcc_mnc_str;
    uint32_t    ext_macro_enodeb_id;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, *offset, E212_NONE, true);
    *offset += 3;
    /* The Extended Macro eNodeB ID consists of 21 bits. */
    proto_tree_add_item(tree, hf_gtpv2_smenb, tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hfindex, tvb, *offset, 3, ENC_BIG_ENDIAN, &ext_macro_enodeb_id);
    *offset += 3;

    str = wmem_strdup_printf(pinfo->pool, "%s, Extended Macro %seNodeB ID 0x%x",
        mcc_mnc_str,
        hfindex == hf_gtpv2_ext_macro_ng_enodeb_id ? "ng-" : "",
        ext_macro_enodeb_id);

    return str;
}


static char*
decode_gtpv2_uli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length, uint8_t instance _U_, unsigned flags)
{
    int         offset = 1;     /* flags are already dissected */
    proto_tree *part_tree;
    char       *mcc_mnc_str;
    char       *str = NULL;

    /* 8.21.1 CGI field  */
    if (flags & GTPv2_ULI_CGI_MASK)
    {

        proto_item_append_text(item, "CGI ");
        part_tree = proto_tree_add_subtree(tree, tvb, offset, 7,
                ett_gtpv2_uli_field, NULL, "Cell Global Identity (CGI)");

        str = dissect_gtpv2_cgi(tvb, pinfo, part_tree, &offset);

        if (offset == length)
            return str;
    }

    /* 8.21.2 SAI field  */
    if (flags & GTPv2_ULI_SAI_MASK)
    {
        proto_item_append_text(item, "SAI ");
        part_tree = proto_tree_add_subtree(tree, tvb, offset, 7,
                ett_gtpv2_uli_field, NULL, "Service Area Identity (SAI)");

        str = dissect_gtpv2_sai_common(tvb, pinfo, part_tree, &offset);

        if (offset == length)
            return str;
    }
    /* 8.21.3 RAI field  */
    if (flags & GTPv2_ULI_RAI_MASK)
    {
        proto_item_append_text(item, "RAI ");
        part_tree = proto_tree_add_subtree(tree, tvb, offset, 7,
                ett_gtpv2_uli_field, NULL, "Routeing Area Identity (RAI)");

        str = dissect_gtpv2_rai(tvb, pinfo, part_tree, &offset);

        if (offset == length)
            return str;
    }
    /* 8.21.4 TAI field  */
    if (flags & GTPv2_ULI_TAI_MASK)
    {
        proto_item_append_text(item, "TAI ");
        part_tree = proto_tree_add_subtree(tree, tvb, offset, 5,
            ett_gtpv2_uli_field, NULL, "Tracking Area Identity (TAI)");

        str = dissect_gtpv2_tai(tvb, pinfo, part_tree, &offset, false);

        if (offset == length)
            return str;
    }
    /* 8.21.5 ECGI field */
    if (flags & GTPv2_ULI_ECGI_MASK)
    {
        proto_item_append_text(item, "ECGI ");
        part_tree = proto_tree_add_subtree(tree, tvb, offset, 7,
            ett_gtpv2_uli_field, NULL, "E-UTRAN Cell Global Identifier (ECGI)");

        str = dissect_gtpv2_ecgi(tvb, pinfo, part_tree, &offset);

        if (offset == length)
            return str;

    }
    /* 8.21.6  LAI field */
    if (flags & GTPv2_ULI_LAI_MASK)
    {
        uint32_t lac;
        proto_item_append_text(item, "LAI ");
        part_tree = proto_tree_add_subtree(tree, tvb, offset, 5,
            ett_gtpv2_uli_field, NULL, "LAI (Location Area Identifier)");
        mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, part_tree, offset, E212_LAI, true);
        offset += 3;

        /* The Location Area Code (LAC) consists of 2 octets. Bit 8 of Octet f+3 is the most significant bit
         * and bit 1 of Octet f+4 the least significant bit. The coding of the location area code is the
         * responsibility of each administration. Coding using full hexadecimal representation shall be used.
         */
        proto_tree_add_item_ret_uint(part_tree, hf_gtpv2_uli_lai_lac, tvb, offset, 2, ENC_BIG_ENDIAN, &lac);
        offset += 2;
        str = wmem_strdup_printf(pinfo->pool, "%s, LAC 0x%x",
            mcc_mnc_str,
            lac);

    }
    /* 8.21.7  Macro eNodeB ID field */
    if (flags & GTPv2_ULI_MACRO_eNB_ID_MASK)
    {
        proto_item_append_text(item, "Macro eNodeB ID ");
        part_tree = proto_tree_add_subtree(tree, tvb, offset, 6,
            ett_gtpv2_uli_field, NULL, "Macro eNodeB ID");

        str = dissect_gtpv2_macro_enodeb_id(tvb, pinfo, part_tree, &offset);

        if (offset == length)
            return str;
    }

    /* 8.21.8  Extended Macro eNodeB ID field */
    if (flags & GTPv2_ULI_EXT_MACRO_eNB_ID_MASK)
    {
        proto_item_append_text(item, "Ext Macro eNodeB ID ");
        part_tree = proto_tree_add_subtree(tree, tvb, offset, 6,
            ett_gtpv2_uli_field, NULL, "Extended Macro eNodeB ID");

        str = dissect_gtpv2_ext_macro_enodeb_id(tvb, pinfo, part_tree, &offset, hf_gtpv2_ext_macro_enodeb_id);

        if (offset == length)
            return str;
    }

    return str;

}

void
dissect_gtpv2_uli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    uint64_t    flags;

    static int * const gtpv2_uli_flags[] = {
        &hf_gtpv2_uli_ext_macro_enb_id_flg,
        &hf_gtpv2_uli_macro_enb_id_flg,
        &hf_gtpv2_uli_lai_flg,
        &hf_gtpv2_uli_ecgi_flg,
        &hf_gtpv2_uli_tai_flg,
        &hf_gtpv2_uli_rai_flg,
        &hf_gtpv2_uli_sai_flg,
        &hf_gtpv2_uli_cgi_flg,
        NULL
    };

    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_gtpv2_uli_flags,
        ett_gtpv2_uli_flags, gtpv2_uli_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE| BMT_NO_INT, &flags);

    decode_gtpv2_uli(tvb, pinfo, tree, item, length, instance, (unsigned)flags);

    return;
}

/* Diameter 3GPP AVP Code: 22 3GPP-User-Location-Info */
/*
 * TS 29.061 v15.5.0
 * 16.4.7.2 Coding 3GPP Vendor-Specific RADIUS attributes
 */
static const value_string geographic_location_type_vals[] = {
    {0,   "CGI"},
    {1,   "SAI"},
    {2,   "RAI"},
    {128, "TAI"},
    {129, "ECGI"},
    {130, "TAI and ECGI"},
    {131, "eNodeB ID"},
    {132, "TAI and eNodeB ID"},
    {133, "extended eNodeB ID"},
    {134, "TAI and extended eNodeB ID"},
    {135, "NCGI"},
    {136, "5GS TAI"},
    {137, "5GS TAI and NCGI"},
    {138, "NG-RAN Node ID"},
    {139, "5GS TAI and NG-RAN Node ID"},
    /* 140-255    Spare for future use */
    {0, NULL}
};

static int
dissect_3gpp_uli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, char **avp_str)
{
    int   offset = 0;
    unsigned length;
    unsigned flags;
    uint32_t flags_3gpp;
    char *str_buf = NULL;
    length       = tvb_reported_length(tvb);

    if (!avp_str)
        avp_str = &str_buf;

    proto_tree_add_item_ret_uint(tree, hf_gtpv2_glt, tvb, offset, 1, ENC_BIG_ENDIAN, &flags_3gpp);
    offset++;

    switch (flags_3gpp)
    {
    case 0:
        /* CGI */
        flags = GTPv2_ULI_CGI_MASK;
        break;
    case 1:
        /* SAI */
        flags = GTPv2_ULI_SAI_MASK;
        break;
    case 2:
        /* RAI */
        flags = GTPv2_ULI_RAI_MASK;
        break;
    case 128:
        /* TAI */
        flags = GTPv2_ULI_TAI_MASK;
        break;
    case 129:
        /* ECGI */
        flags = GTPv2_ULI_ECGI_MASK;
        break;
    case 130:
        /* TAI and ECGI */
        flags = GTPv2_ULI_TAI_MASK + GTPv2_ULI_ECGI_MASK;
        break;
    case 131:
        /* eNodeB ID */
        flags = GTPv2_ULI_MACRO_eNB_ID_MASK;
        break;
    case 132:
        /* TAI and eNodeB ID */
        flags = GTPv2_ULI_TAI_MASK + GTPv2_ULI_MACRO_eNB_ID_MASK;
        break;
    case 133:
        /* extended eNodeB ID */
        flags = GTPv2_ULI_EXT_MACRO_eNB_ID_MASK;
        break;
    case 134:
        /* TAI and extended eNodeB ID */
        flags = GTPv2_ULI_TAI_MASK + GTPv2_ULI_EXT_MACRO_eNB_ID_MASK;
        break;
    case 135:
        /* NCGI */
        {
            char *mcc_mnc_str;
            uint64_t nr_cell_id;
            proto_tree *subtree;

            subtree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_gtpv2_uli_field, NULL,
                                             "NR Cell Global Identifier (NCGI)");
            mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, subtree, offset, E212_NRCGI, true);
            offset += 3;
            proto_tree_add_item_ret_uint64(subtree, hf_gtpv2_ncgi_nrci, tvb, offset, 5, ENC_BIG_ENDIAN, &nr_cell_id);
            *avp_str = wmem_strdup_printf(pinfo->pool,
                                          "%s, NR Cell Id 0x%" PRIx64,
                                          mcc_mnc_str, nr_cell_id);
        }
        return length;
    case 136:
        /* 5GS TAI */
        {
            proto_tree *subtree;

            subtree = proto_tree_add_subtree(tree, tvb, offset, 6, ett_gtpv2_uli_field, NULL,
                                             "Tracking Area Identity (TAI)");
            *avp_str = dissect_gtpv2_tai(tvb, pinfo, subtree, &offset, true);
        }
        return length;
    case 137:
        /* 5GS TAI and NCGI */
        {
            char *mcc_mnc_str;
            uint64_t nr_cell_id;
            proto_tree *subtree;

            subtree = proto_tree_add_subtree(tree, tvb, offset, 6, ett_gtpv2_uli_field, NULL,
                                             "Tracking Area Identity (TAI)");
            *avp_str = dissect_gtpv2_tai(tvb, pinfo, subtree, &offset, true);
            subtree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_gtpv2_uli_field, NULL,
                                             "NR Cell Global Identifier (NCGI)");
            mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, subtree, offset, E212_NRCGI, true);
            offset += 3;
            proto_tree_add_item_ret_uint64(subtree, hf_gtpv2_ncgi_nrci, tvb, offset, 5, ENC_BIG_ENDIAN, &nr_cell_id);
            *avp_str = wmem_strdup_printf(pinfo->pool,
                                          "%s, %s, NR Cell Id 0x%" PRIx64,
                                          *avp_str, mcc_mnc_str, nr_cell_id);
        }
        return length;
    default:
        proto_tree_add_item(tree, hf_gtpv2_geographic_location, tvb, offset, -1, ENC_NA);
        return length;
    }

    *avp_str = decode_gtpv2_uli(tvb, pinfo, tree, NULL, length, 0, flags);
    return length;
}

static const
char *dissect_radius_user_loc(proto_tree * tree, tvbuff_t * tvb, packet_info* pinfo)
{
    uint16_t length;

    length = dissect_3gpp_uli(tvb, pinfo, tree, NULL);
    return tvb_bytes_to_str(pinfo->pool, tvb, 0, length);

}

int
dissect_diameter_3gpp_uli(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    diam_sub_dis_t* diam_sub_dis = (diam_sub_dis_t*)data;

    if (diam_sub_dis) {
        return dissect_3gpp_uli(tvb, pinfo, tree, &diam_sub_dis->avp_str);
    } else {
        return dissect_3gpp_uli(tvb, pinfo, tree, NULL);
    }
}

/*
 * 8.22 Fully Qualified TEID (F-TEID)
 */
static const value_string gtpv2_f_teid_interface_type_vals[] = {
    { 0, "S1-U eNodeB GTP-U interface"},
    { 1, "S1-U SGW GTP-U interface"},
    { 2, "S12 RNC GTP-U interface"},
    { 3, "S12 SGW GTP-U interface"},
    { 4, "S5/S8 SGW GTP-U interface"},
    { 5, "S5/S8 PGW GTP-U interface"},
    { 6, "S5/S8 SGW GTP-C interface"},
    { 7, "S5/S8 PGW GTP-C interface"},
    { 8, "S5/S8 SGW PMIPv6 interface"}, /* (the 32 bit GRE key is encoded in 32 bit TEID field "
         "and since alternate CoA is not used the control plane and user plane addresses are the same for PMIPv6)"}, */
    { 9, "S5/S8 PGW PMIPv6 interface"}, /* (the 32 bit GRE key is encoded in 32 bit TEID field "
         "and the control plane and user plane addresses are the same for PMIPv6)"}, */
    {10, "S11 MME GTP-C interface"},
    {11, "S11/S4 SGW GTP-C interface"},
    {12, "S10 MME GTP-C interface"},
    {13, "S3 MME GTP-C interface"},
    {14, "S3 SGSN GTP-C interface"},
    {15, "S4 SGSN GTP-U interface"},
    {16, "S4 SGW GTP-U interface"},
    {17, "S4 SGSN GTP-C interface"},
    {18, "S16 SGSN GTP-C interface"},
    {19, "eNodeB/gNodeB GTP-U interface for DL data forwarding"},
    {20, "eNodeB GTP-U interface for UL data forwarding"},
    {21, "RNC GTP-U interface for data forwarding"},
    {22, "SGSN GTP-U interface for data forwarding"},
    {23, "SGW GTP-U interface for data forwarding"},
    {24, "Sm MBMS GW GTP-C interface"},
    {25, "Sn MBMS GW GTP-C interface"},
    {26, "Sm MME GTP-C interface"},
    {27, "Sn SGSN GTP-C interface"},
    {28, "SGW GTP-U interface for UL data forwarding"},
    {29, "Sn SGSN GTP-U interface"},
    {30, "S2b ePDG GTP-C interface"},
    {31, "S2b-U ePDG GTP-U interface"},
    {32, "S2b PGW GTP-C interface"},
    {33, "S2b-U PGW GTP-U interface"},
    {34, "S2a TWAN GTP-U interface"},
    {35, "S2a TWAN GTP-C interface"},
    {36, "S2a PGW GTP-C interface"},
    {37, "S2a PGW GTP-U interface"},
    {38, "S11 MME GTP-U interface"},
    {39, "S11 SGW GTP-U interface"},
    {40, "N26 AMF GTP-C interface"},
    {41, "N19mb UPF GTP-U interface"},
    {0, NULL}
};
static value_string_ext gtpv2_f_teid_interface_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_f_teid_interface_type_vals);

static const true_false_string gtpv2_f_teid_v4_vals = {
    "IPv4 address present",
    "IPv4 address not present",
};

static const true_false_string gtpv2_f_teid_v6_vals = {
    "IPv6 address present",
    "IPv6 address not present",
};

static void
dissect_gtpv2_f_teid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t *args)
{
    int    offset = 0;
    uint8_t flags;
    address *ipv4 = NULL, *ipv6 = NULL;
    uint32_t teid_cp, *teid, session;

    flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_f_teid_v4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_f_teid_v6, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* NOTE:  "Interface type" IE is defined with 5 bits only in the earlier releases of this specification,
     * thus pre-Rel-10 GTPv2-C nodes can ignore bit "6" which is marked as "Spare" in earlier releases,
     * allowing backward compatibility.
     */
    proto_tree_add_item(tree, hf_gtpv2_f_teid_interface_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_f_teid_gre_key, tvb, offset, 4, ENC_BIG_ENDIAN, &teid_cp);
    proto_item_append_text(item, "%s, TEID/GRE Key: 0x%s",
                           val_to_str_ext_const((flags & 0x3f), &gtpv2_f_teid_interface_type_vals_ext, "Unknown"),
                           tvb_bytes_to_str(pinfo->pool, tvb, offset, 4));

    offset += 4;
    if (flags & 0x80)
    {
        ipv4 = wmem_new0(pinfo->pool, address);
        proto_tree_add_item(tree, hf_gtpv2_f_teid_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, ", IPv4 %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        set_address_tvb(ipv4, AT_IPv4, 4, tvb, offset);
        offset += 4;
    }
    if (flags & 0x40)
    {
        ipv6 = wmem_new0(pinfo->pool, address);
        proto_tree_add_item(tree, hf_gtpv2_f_teid_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, ", IPv6 %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        set_address_tvb(ipv6, AT_IPv6, 16, tvb, offset);
    }

    if (g_gtp_session && args) {
        session = GPOINTER_TO_UINT(wmem_map_lookup(session_table, GUINT_TO_POINTER(pinfo->num)));
        if (!session) {
            /* We save the teid so that we could assignate its corresponding session ID later */
            args->last_teid = teid_cp;
            if (!teid_exists(teid_cp, args->teid_list)) {
                teid = wmem_new(pinfo->pool, uint32_t);
                *teid = teid_cp;
                wmem_list_prepend(args->teid_list, teid);
            }
            if (ipv4 != NULL && !ip_exists(*ipv4, args->ip_list)) {
                copy_address_wmem(pinfo->pool, &args->last_ip, ipv4);
                wmem_list_prepend(args->ip_list, ipv4);
            }
            if (ipv6 != NULL && !ip_exists(*ipv6, args->ip_list)) {
                copy_address_wmem(pinfo->pool, &args->last_ip, ipv6);
                wmem_list_prepend(args->ip_list, ipv6);
            }
        }
    }
}
/*
 * 8.23 TMSI
 */
static void
dissect_gtpv2_tmsi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_tmsi, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(item, hf_gtpv2_tmsi_bytes, tvb, 0, length, ENC_NA);
}
/*
 * 8.24 Global CN-Id
 * (TS 23.003)
 * 12.3 CN Identifier
 *
 * A CN node is uniquely identified within a PLMN by its CN Identifier (CN-Id). The CN-Id together with the PLMN
 * identifier globally identifies the CN node. The CN-Id together with the PLMN-Id is used as the CN node identifier in
 * RANAP signalling over the Iu interface.
 * Global CN-Id = PLMN-Id || CN-Id
 * The CN-Id is defined by the operator, and set in the nodes via O&M.
 * For the syntax description and the use of this identifier in RANAP signalling, see 3GPP TS 25.413 [17].
 */

static void
dissect_gtpv2_g_cn_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, E212_NONE, true);
    offset += 3;

    /* >CN-ID M INTEGER (0..4095) */
    proto_tree_add_item(tree, hf_gtpv2_cn_id, tvb, offset, 2, ENC_NA);
}
/*
 * 8.25 S103 PDN Data Forwarding Info (S103PDF)
 */
static void
dissect_gtpv2_s103pdf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    uint8_t     m, k, i;

    /* The HSGW Address and GRE Key identify a GRE Tunnel towards a HSGW over S103 interface for a specific PDN
     * connection of the UE. The EPS Bearer IDs specify the EPS Bearers which require data forwarding that belonging to this
     * PDN connection. The number of EPS bearer Ids included is specified by the value of EPS Bearer ID Number.
     */
    /* Octet 5 HSGW Address for forwarding Length = m */
    m = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_hsgw_addr_f_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* 6 to (m+5) HSGW Address for forwarding [4..16] */
    switch (m) {
    case 4:
        /* IPv4 */
        proto_tree_add_item(tree, hf_gtpv2_hsgw_addr_ipv4, tvb, offset, m, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 16:
        /* IPv6 */
        proto_tree_add_item(tree, hf_gtpv2_hsgw_addr_ipv6, tvb, offset, m, ENC_NA);
        offset += 16;
        break;
    default:
        /* Error */
        proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_len_invalid, tvb, 0, length,
                                     "Wrong length %u, should be 4 or 16", m);
        return;
    }

    /* (m+6)- to (m+9) GRE Key */
    proto_tree_add_item(tree, hf_gtpv2_gre_key, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* (m+10) EPS Bearer ID Number = k */
    k = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_eps_bearer_id_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* (m+11) to (m+10+k)
     * Spare EPS Bearer ID
     */
    for ( i = 0; i < k; i++ ) {
        proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

}
/*
 * 8.26 S1-U Data Forwarding (S1UDF)
 */
static void
dissect_gtpv2_s1udf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    uint8_t     m;

    /* 5 Spare EPS Bearer ID */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* 6 Serving GW Address Length = m */
    m = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_serving_gw_address_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* 7 to (m+6) Serving GW Address [4..16] */
    switch (m) {
    case 4:
        /* IPv4 */
        proto_tree_add_item(tree, hf_gtpv2_sgw_addr_ipv4, tvb, offset, m, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 16:
        /* IPv6 */
        proto_tree_add_item(tree, hf_gtpv2_sgw_addr_ipv6, tvb, offset, m, ENC_NA);
        offset += 16;
        break;
    default:
        /* Error */
        proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_len_invalid, tvb, 0, length,
                                     "Wrong length %u, should be 4 or 16", m);
        return;
    }

    /* (m+7) to (m+10)
     * Serving GW S1-U TEID
     */
    proto_tree_add_item(tree, hf_gtpv2_sgw_s1u_teid, tvb, offset, 4, ENC_BIG_ENDIAN);

}
/*
 * 8.27 Delay Value
 */

static void
dissect_gtpv2_delay_value(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_delay_value, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/*
 * 8.28 Bearer Context (grouped IE)
 */

static void
dissect_gtpv2_bearer_ctx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    tvbuff_t   *new_tvb;
    proto_tree *grouped_tree;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(item, ett_gtpv2_bearer_ctx);

    new_tvb = tvb_new_subset_length(tvb, offset, length);
    dissect_gtpv2_ie_common(new_tvb, pinfo, grouped_tree, 0, message_type, args, GTPV2_IE_BEARER_CTX);
}

/* 8.29 Charging ID */
static void
dissect_gtpv2_charging_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_charging_id, tvb, offset, length, ENC_BIG_ENDIAN);
}


 /* 8.30 Charging Characteristics
  * The charging characteristics information element is defined in 3GPP TS 32.251 [8]
  * and is a way of informing both the SGW and PGW of the rules for producing charging
  * information based on operator configured triggers. For the encoding of this
  * information element see 3GPP TS 32.298 [9].
  */
static void
dissect_gtpv2_char_char(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_charging_characteristic, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (length > 2) {
        offset += 2;
        /* These octet(s) is/are present only if explicitly specified */
        proto_tree_add_item(tree, hf_gtpv2_charging_characteristic_remaining_octets, tvb, offset, length-2, ENC_NA);
    }

}

/*
 * 8.30 Bearer Flag
 */
static void
dissect_gtpv2_bearer_flag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{

    int offset = 0;

    /* Octet 5 Spare VB PPC */
    proto_tree_add_item(tree, hf_gtpv2_bearer_flag_ppc, tvb, offset, length, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_bearer_flag_vb, tvb, offset, length, ENC_BIG_ENDIAN);

}
/*
 * 8.34 PDN Type
 */
void
dissect_gtpv2_pdn_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{

    int offset = 0;
    uint8_t pdn;

    if (length != 1) {
        proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_len_invalid, tvb, 0, length,
                                     "Wrong length indicated. Expected 1, got %u", length);
        return;
    }

    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset << 3, 5, ENC_BIG_ENDIAN);
    pdn = tvb_get_uint8(tvb, offset)& 0x7;
    proto_tree_add_item(tree, hf_gtpv2_pdn_type, tvb, offset, length, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s", val_to_str_ext_const(pdn, &gtpv2_pdn_type_vals_ext, "Unknown"));

}

/*
 * 8.31 Trace Information
 */
 /* List of NE Types */
static int* const trace_ne_types_flags_oct1[] = {
    &hf_gtpv2_tra_info_lne_sgw,
    &hf_gtpv2_tra_info_lne_mme,
    &hf_gtpv2_tra_info_lne_bm_sc,
    &hf_gtpv2_tra_info_lne_rnc,
    &hf_gtpv2_tra_info_lne_ggsn,
    &hf_gtpv2_tra_info_lne_sgsn,
    &hf_gtpv2_tra_info_lne_mgw,
    &hf_gtpv2_tra_info_lne_msc_s,
    NULL
};

static int* const trace_ne_types_flags_oct2[] = {
    &hf_gtpv2_tra_info_tra_info_ng_ran_node,
    &hf_gtpv2_tra_info_lne_upf,
    &hf_gtpv2_tra_info_lne_pcf,
    &hf_gtpv2_tra_info_lne_smf,
    &hf_gtpv2_tra_info_lne_amf,
    &hf_gtpv2_tra_info_lne_enb,
    &hf_gtpv2_tra_info_lne_pdn_gw,
    NULL
};

static void
dissect_gtpv2_tra_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree  *trigg_tree, *msc_server_tree, *mgw_tree, *sgsn_tree, *ggsn_tree;
    proto_tree  *bm_sc_tree, *sgw_mme_tree, *sgw_tree, *pgw_tree, *ne_types_tree;
    proto_tree  *interfaces_tree, *imsc_server_tree, *lmgw_tree, *lsgsn_tree, *lggsn_tree, *lrnc_tree;
    proto_tree  *lbm_sc_tree, *lmme_tree, *lsgw_tree, *lpdn_gw_tree, *lenb_tree;

    int         offset = 0;
#if 0
    uint8_t     *trace_id = NULL;
#endif
    uint16_t    tid;
    uint32_t    bit_offset;

    dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, E212_NONE, true);
    offset += 3;

    /* Append Trace ID to main tree */
    tid = tvb_get_ntohs(tvb, offset);
    proto_item_append_text(item, "Trace ID: %d  ", tid);

    /* Trace ID */
    /*--------------------------------------------------
     * trace_id = tvb_format_text(tvb, offset, 2);
     * proto_tree_add_string(tree, hf_gtpv2_tra_info, tvb, offset, length, trace_id);
     *--------------------------------------------------*/
    proto_tree_add_item(tree, hf_gtpv2_trace_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Triggering Events, put all into a new tree called triggering_tree */
    trigg_tree = proto_tree_add_subtree(tree, tvb, offset, 9, ett_gtpv2_tra_info_trigg, NULL, "Triggering Events");

    /* Create all subtrees */
    msc_server_tree = proto_tree_add_subtree(trigg_tree, tvb, offset, 2, ett_gtpv2_tra_info_trigg_msc_server, NULL, "MSC Server");

    mgw_tree = proto_tree_add_subtree(trigg_tree, tvb, offset + 2, 1, ett_gtpv2_tra_info_trigg_mgw, NULL, "MGW");

    sgsn_tree = proto_tree_add_subtree(trigg_tree, tvb, offset + 3, 2, ett_gtpv2_tra_info_trigg_sgsn, NULL, "SGSN");

    ggsn_tree = proto_tree_add_subtree(trigg_tree, tvb, offset + 5, 1, ett_gtpv2_tra_info_trigg_ggsn, NULL, "GGSN");

    bm_sc_tree = proto_tree_add_subtree(trigg_tree, tvb, offset + 6, 1, ett_gtpv2_tra_info_trigg_bm_sc, NULL, "BM-SC");

    sgw_mme_tree = proto_tree_add_subtree(trigg_tree, tvb, offset + 7, 1, ett_gtpv2_tra_info_trigg_sgw_mme, NULL, "SGW MME");

    sgw_tree = proto_tree_add_subtree(trigg_tree, tvb, offset + 8, 1, ett_gtpv2_tra_info_trigg_sgw, NULL, "SGW");

    pgw_tree = proto_tree_add_subtree(trigg_tree, tvb, offset + 8, 1, ett_gtpv2_tra_info_trigg_pgw, NULL, "PGW");

    /* MSC Server - 2 octets */
    static int* const tra_info_msc_flags[] = {
        &hf_gtpv2_tra_info_msc_ss,
        &hf_gtpv2_tra_info_msc_handovers,
        &hf_gtpv2_tra_info_msc_lu_imsi_ad,
        &hf_gtpv2_tra_info_msc_momt_sms,
        &hf_gtpv2_tra_info_msc_momt_calls,
        NULL
    };
    proto_tree_add_bitmask_list(msc_server_tree, tvb, offset, 1, tra_info_msc_flags, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(msc_server_tree, hf_gtpv2_spare_bits,          tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    offset += 1;
    bit_offset = offset << 3;
    proto_tree_add_bits_item(msc_server_tree, hf_gtpv2_spare_bits,          tvb, bit_offset, 8, ENC_BIG_ENDIAN);
    offset += 1;

    /* MGW - 1 octet */
    proto_tree_add_item(mgw_tree, hf_gtpv2_tra_info_mgw_context,            tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(mgw_tree, hf_gtpv2_spare_bits,                 tvb, bit_offset, 7, ENC_BIG_ENDIAN);
    offset += 1;
    /* SGSN - 2 octets */
    static int* const tra_info_sgsn_flags[] = {
        &hf_gtpv2_tra_info_sgsn_mbms,
        &hf_gtpv2_tra_info_sgsn_rau_gprs_ad,
        &hf_gtpv2_tra_info_sgsn_momt_sms,
        &hf_gtpv2_tra_info_sgsn_pdp_context,
        NULL
    };
    proto_tree_add_bitmask_list(sgsn_tree, tvb, offset, 1, tra_info_sgsn_flags, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(sgsn_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(sgsn_tree, hf_gtpv2_tra_info_sgsn_reserved,         tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* GGSN - 1 octet */
    proto_tree_add_item(ggsn_tree, hf_gtpv2_tra_info_ggsn_pdp,              tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ggsn_tree, hf_gtpv2_tra_info_ggsn_mbms,             tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(ggsn_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 6, ENC_BIG_ENDIAN);
    offset += 1;
    /* BM-SC - 1 octet */
    proto_tree_add_item(bm_sc_tree, hf_gtpv2_tra_info_bm_sc,                tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(bm_sc_tree, hf_gtpv2_spare_bits,               tvb, bit_offset, 7, ENC_BIG_ENDIAN);
    offset += 1;
    /* MME/SGW - 1 octet */
    static int* const tra_info_mme_flags[] = {
        &hf_gtpv2_tra_info_mme_sgw_ho,
        &hf_gtpv2_tra_info_mme_sgw_bearer_act_mod_del,
        &hf_gtpv2_tra_info_mme_sgw_ue_init_pdn_disc,
        &hf_gtpv2_tra_info_mme_sgw_iataud,
        &hf_gtpv2_tra_info_mme_sgw_sr,
        &hf_gtpv2_tra_info_mme_sgw_ss,
        NULL
    };
    proto_tree_add_bitmask_list(sgw_mme_tree, tvb, offset, 1, tra_info_mme_flags, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(sgw_mme_tree, hf_gtpv2_spare_bits,                     tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    offset += 1;
    /* PGW/SGW - 1 octet */
    static int* const tra_info_sgw_pdn_flags[] = {
        &hf_gtpv2_tra_info_sgw_bearer_act_mod_del,
        &hf_gtpv2_tra_info_sgw_pdn_con_term,
        &hf_gtpv2_tra_info_sgw_pdn_con_creat,
        NULL
    };
    proto_tree_add_bitmask_list(sgw_mme_tree, tvb, offset, 1, tra_info_sgw_pdn_flags, ENC_BIG_ENDIAN);
    bit_offset = (offset << 3) + 4;
    proto_tree_add_bits_item(sgw_tree, hf_gtpv2_spare_bits,                 tvb, bit_offset, 1, ENC_BIG_ENDIAN);

    static int* const tra_info_pgw_flags[] = {
        &hf_gtpv2_tra_info_sgw_bearer_act_mod_del,
        &hf_gtpv2_tra_info_pgw_pdn_con_term,
        &hf_gtpv2_tra_info_pgw_pdn_con_creat,
        NULL
    };
    proto_tree_add_bitmask_list(pgw_tree, tvb, offset, 1, tra_info_pgw_flags, ENC_BIG_ENDIAN);

    bit_offset = offset << 3;
    proto_tree_add_bits_item(pgw_tree, hf_gtpv2_spare_bits,                 tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Create NE Types subtree */
    ne_types_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_gtpv2_tra_info_ne_types, NULL, "List of NE Types");

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, trace_ne_types_flags_oct1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, trace_ne_types_flags_oct2, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(ne_types_tree, hf_gtpv2_spare_bits,        tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Trace Depth Length */
    proto_tree_add_item(tree, hf_gtpv2_tra_info_tdl,                    tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Set up subtree interfaces and put all interfaces under it */
    interfaces_tree = proto_tree_add_subtree(tree, tvb, offset, 12, ett_gtpv2_tra_info_interfaces, NULL, "List of Interfaces");

    /* Create all subtrees */
    imsc_server_tree = proto_tree_add_subtree(interfaces_tree, tvb, offset, 2, ett_gtpv2_tra_info_interfaces_imsc_server, NULL, "MSC Server");

    lmgw_tree = proto_tree_add_subtree(interfaces_tree, tvb, offset + 2, 1, ett_gtpv2_tra_info_interfaces_lmgw, NULL, "MGW");

    lsgsn_tree = proto_tree_add_subtree(interfaces_tree, tvb, offset + 3, 2, ett_gtpv2_tra_info_interfaces_lsgsn, NULL, "SGSN");

    lggsn_tree = proto_tree_add_subtree(interfaces_tree, tvb, offset + 5, 1, ett_gtpv2_tra_info_interfaces_lggsn, NULL, "GGSN");

    lrnc_tree = proto_tree_add_subtree(interfaces_tree, tvb, offset + 6, 1, ett_gtpv2_tra_info_interfaces_lrnc, NULL, "RNC");

    lbm_sc_tree = proto_tree_add_subtree(interfaces_tree, tvb, offset + 7, 1, ett_gtpv2_tra_info_interfaces_lbm_sc, NULL, "BM-SC");

    lmme_tree = proto_tree_add_subtree(interfaces_tree, tvb, offset + 8, 1, ett_gtpv2_tra_info_interfaces_lmme, NULL, "MME");

    lsgw_tree = proto_tree_add_subtree(interfaces_tree, tvb, offset + 9, 1,ett_gtpv2_tra_info_interfaces_lsgw, NULL, "SGW");

    lpdn_gw_tree = proto_tree_add_subtree(interfaces_tree, tvb, offset + 10, 1, ett_gtpv2_tra_info_interfaces_lpdn_gw, NULL, "PDN GW");

    lenb_tree = proto_tree_add_subtree(interfaces_tree, tvb, offset + 11, 1, ett_gtpv2_tra_info_interfaces_lpdn_lenb, NULL, "eNB");

    /* MSC Server - 2 octets */
    static int* const tra_info_lmsc_flags[] = {
        &hf_gtpv2_tra_info_lmsc_cap,
        &hf_gtpv2_tra_info_lmsc_map_f,
        &hf_gtpv2_tra_info_lmsc_map_e,
        &hf_gtpv2_tra_info_lmsc_map_b,
        &hf_gtpv2_tra_info_lmsc_map_g,
        &hf_gtpv2_tra_info_lmsc_mc,
        &hf_gtpv2_tra_info_lmsc_lu,
        &hf_gtpv2_tra_info_lmsc_a,
        NULL
    };
    proto_tree_add_bitmask_list(imsc_server_tree, tvb, offset, 1, tra_info_lmsc_flags, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_map_d,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_map_c,     tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(imsc_server_tree, hf_gtpv2_spare_bits,         tvb, bit_offset, 6, ENC_BIG_ENDIAN);
    offset += 1;
    /* MGW - 1 octet */
    static int* const tra_info_lmgw_flags[] = {
        &hf_gtpv2_tra_info_lmgw_lu_up,
        &hf_gtpv2_tra_info_lmgw_nb_up,
        &hf_gtpv2_tra_info_lmgw_mc,
        NULL
    };
    proto_tree_add_bitmask_list(lmgw_tree, tvb, offset, 1, tra_info_lmgw_flags, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(lmgw_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 5, ENC_BIG_ENDIAN);
    offset += 1;
    /* SGSN - 2 octets */
    static int* const tra_info_lsgsn_flags[] = {
        &hf_gtpv2_tra_info_lsgsn_ge,
        &hf_gtpv2_tra_info_lsgsn_gs,
        &hf_gtpv2_tra_info_lsgsn_map_gf,
        &hf_gtpv2_tra_info_lsgsn_map_gd,
        &hf_gtpv2_tra_info_lsgsn_map_gr,
        &hf_gtpv2_tra_info_lsgsn_gn,
        &hf_gtpv2_tra_info_lsgsn_lu,
        &hf_gtpv2_tra_info_lsgsn_gb,
        NULL
    };
    proto_tree_add_bitmask_list(lsgsn_tree, tvb, offset, 1, tra_info_lsgsn_flags, ENC_BIG_ENDIAN);
    offset += 1;
    bit_offset = offset << 3;
    proto_tree_add_bits_item(lsgsn_tree, hf_gtpv2_spare_bits,               tvb, bit_offset, 8, ENC_BIG_ENDIAN);
    offset += 1;

    /* GGSN - 1 octet */
    static int* const tra_info_lggsn_flags[] = {
        &hf_gtpv2_tra_info_lggsn_gmb,
        & hf_gtpv2_tra_info_lggsn_gi,
        & hf_gtpv2_tra_info_lggsn_gn,
        NULL
    };
    proto_tree_add_bitmask_list(lggsn_tree, tvb, offset, 1, tra_info_lggsn_flags, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(lggsn_tree, hf_gtpv2_spare_bits,               tvb, bit_offset, 5, ENC_BIG_ENDIAN);
    offset += 1;
    /* RNC - 1 octet */
    static int* const tra_info_lrnc_flags[] = {
        &hf_gtpv2_tra_info_lrnc_uu,
        &hf_gtpv2_tra_info_lrnc_lub,
        &hf_gtpv2_tra_info_lrnc_lur,
        &hf_gtpv2_tra_info_lrnc_lu,
        NULL
    };
    proto_tree_add_bitmask_list(lrnc_tree, tvb, offset, 1, tra_info_lrnc_flags, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(lrnc_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    offset += 1;
    /* BM_SC - 1 octet */
    proto_tree_add_item(lbm_sc_tree, hf_gtpv2_tra_info_lbm_sc_gmb,          tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(lbm_sc_tree, hf_gtpv2_spare_bits,              tvb, bit_offset, 7, ENC_BIG_ENDIAN);
    offset += 1;
    /* MME - 1 octet */
    static int* const tra_info_lmme_flags[] = {
        &hf_gtpv2_tra_info_lmme_s11,
        &hf_gtpv2_tra_info_lmme_s10,
        &hf_gtpv2_tra_info_lmme_s6a,
        &hf_gtpv2_tra_info_lmme_s3,
        &hf_gtpv2_tra_info_lmme_s1_mme,
        NULL
    };
    proto_tree_add_bitmask_list(lmme_tree, tvb, offset, 1, tra_info_lmme_flags, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(lmme_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    offset += 1;
    /* SGW - 1 octet */
    static int* const tra_info_lsgw_flags[] = {
        &hf_gtpv2_tra_info_lsgw_s11,
        &hf_gtpv2_tra_info_lsgw_s8b,
        &hf_gtpv2_tra_info_lsgw_s5,
        &hf_gtpv2_tra_info_lsgw_s4,
        NULL
    };
    proto_tree_add_bitmask_list(lsgw_tree, tvb, offset, 1, tra_info_lsgw_flags, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(lsgw_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    offset += 1;
    /* PDN GW - 1 octet */
    static int* const tra_info_lpdn_gw_flags[] = {
        &hf_gtpv2_tra_info_lpdn_gw_sgi,
        &hf_gtpv2_tra_info_lpdn_gw_s8b,
        &hf_gtpv2_tra_info_lpdn_gw_gx,
        &hf_gtpv2_tra_info_lpdn_gw_s6c,
        &hf_gtpv2_tra_info_lpdn_gw_s5,
        &hf_gtpv2_tra_info_lpdn_gw_s2c,
        &hf_gtpv2_tra_info_lpdn_gw_s2b,
        &hf_gtpv2_tra_info_lpdn_gw_s2a,
        NULL
    };
    proto_tree_add_bitmask_list(lpdn_gw_tree, tvb, offset, 1, tra_info_lpdn_gw_flags, ENC_BIG_ENDIAN);
    offset += 1;
    /* eNB - 1 octet */
    static int* const tra_info_lenb_flags[] = {
        &hf_gtpv2_tra_info_lenb_uu,
        &hf_gtpv2_tra_info_lenb_x2,
        &hf_gtpv2_tra_info_lenb_s1_mme,
        NULL
    };
    proto_tree_add_bitmask_list(lenb_tree, tvb, offset, 1, tra_info_lenb_flags, ENC_BIG_ENDIAN);
    bit_offset = offset << 3;
    proto_tree_add_bits_item(lenb_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 5, ENC_BIG_ENDIAN);

    /*--------------------------------------------------
     * offset += 1;
     *--------------------------------------------------*/

    /* IP Address of Trace Collection Entity */
    while ( (offset + 4) <= length ) {
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_ipv4_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 3;
    }
}

/*
 * 8.33 Paging Cause
 * 8.33 Void (TS 129 274 V9.4.0 (2010-10))
 */

/* 8.35 Procedure Transaction ID (PTI) */
static void
dissect_gtpv2_pti(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_pti, tvb, 0, 1, ENC_BIG_ENDIAN);
}
/*
 * 8.36 DRX Parameter
 */
static void
dissect_gtpv2_drx_param(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    /* 36.413 : 9.2.1.17   Paging Cause, void */
    proto_tree_add_item(tree, hf_gtpv2_drx_parameter, tvb, offset, length, ENC_NA);
}

/*
 * 8.37 UE Network Capability
 * UE Network Capability is coded as depicted in Figure 8.37-1. Actual coding of the UE Network Capability field is
 * defined in 3GPP TS 24.301
 */
static void
dissect_gtpv2_ue_net_capability(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    de_emm_ue_net_cap(tvb, tree, pinfo, 0, length, NULL, 0);

}
/*
 * 8.38 MM Context
 */
static const value_string gtpv2_mm_context_security_mode[] = {
    {0, "GSM Key and Triplets"},
    {1, "UMTS Key, Used Cipher and Quintuplets"},
    {2, "GSM Key, Used Cipher and Quintuplets"},
    {3, "UMTS Key and Quintuplets"},
    {4, "EPS Security Context, Quadruplets and Quintuplets" },
    {5, "UMTS Key, Quadruplets and Quintuplets"},
    {0, NULL                                                                                                    }
};

static const true_false_string gtpv2_nhi_vals = {
    "NH (Next Hop) and NCC (Next Hop Chaining Count) are both present",
    "NH (Next Hop) and NCC (Next Hop Chaining Count) not present",
};

/* Table 8.38-2: Used NAS Cipher Values */

static const value_string gtpv2_mm_context_unc_vals[] = {
    {0, "No ciphering"},
    {1, "128-EEA1"},
    {2, "128-EEA2"},
    {3, "128-EEA3"},
    {4, "EEA4"  },
    {5, "EEA5"},
    {6, "EEA6"},
    {7, "EEA7"},
    {0, NULL}
};

/* Table 8.38-3: Used Cipher Values */
static const value_string gtpv2_mm_context_used_cipher_vals[] = {
    {0, "No ciphering"},
    {1, "GEA/1"},
    {2, "GEA/2"},
    {3, "GEA/3"},
    {4, "GEA/4" },
    {5, "GEA/5"},
    {6, "GEA/6"},
    {7, "GEA/7"},
    {0, NULL}
};

/* Table 8.38-4: Used NAS integrity protection algorithm Values */
static const value_string gtpv2_mm_context_unipa_vals[] = {
    {0, "No integrity protection"},
    {1, "128-EIA1"},
    {2, "128-EIA2"},
    {3, "128-EIA3"},
    {4, "EIA4"  },
    {5, "EIA5"},
    {6, "EIA6"},
    {7, "EIA7"},
    {0, NULL}
};

/* Table 8.38-6: EPS NAS Security Context Type Values */
static const value_string gtpv2_mm_context_eps_nas_security_context_type_vals[] = {
    {0, "Reporting EPS NAS Security Context Type is not supported"},
    {1, "Native EPS NAS Security Context Type"},
    {2, "Mapped EPS NAS Security Context Type"},
    {0, NULL}
};

/* Helper functions */

/* Figure 8.38-7: Authentication Triplet */
static int
dissect_gtpv2_authentication_triplets(tvbuff_t *tvb, proto_tree *tree, int offset, uint8_t num_triplet)
{
    proto_tree *auth_tri_tree;
    int         i;

    for (i = 0; i < num_triplet; i++) {
        auth_tri_tree = proto_tree_add_subtree_format(tree, tvb, offset, 0,
                ett_gtpv2_mm_context_auth_tri, NULL, "Authentication Triplet %u", i);
        /*
        * Figure 8.38-8: Authentication Quintuplet
        * 1 to 16 RAND
        * 17 to 20 SRES
        * 21 to 28 Kc
        */
        proto_tree_add_item(auth_tri_tree, hf_gtpv2_mm_context_rand, tvb, offset, 16, ENC_NA);
        offset += 16;
        proto_tree_add_item(auth_tri_tree, hf_gtpv2_mm_context_sres, tvb, offset, 4, ENC_NA);
        offset += 4;
        proto_tree_add_item(auth_tri_tree, hf_gtpv2_mm_context_kc, tvb, offset, 8, ENC_NA);
        offset += 8;

    }

    return offset;
}

static int
dissect_gtpv2_authentication_quintuplets(tvbuff_t *tvb, proto_tree *tree, int offset, uint8_t nr_qui)
{
    proto_tree *auth_qui_tree;
    int         i;
    uint32_t     tmp;

    for (i = 0; i < nr_qui; i++) {
        auth_qui_tree = proto_tree_add_subtree_format(tree, tvb, offset, 0,
            ett_gtpv2_mm_context_auth_qui, NULL, "Authentication Quintuplet %u", i);
        /*
        * Figure 8.38-8: Authentication Quintuplet
        * 1 to 16 RAND
        * 17 XRES Length
        * 18 to m XRES
        * (m+1) to (m+16) CK
        * (m+17) to (m+32) IK
        * m+33 AUTN Length
        * (m+34) to n AUTN
        */
        proto_tree_add_item(auth_qui_tree, hf_gtpv2_mm_context_rand, tvb, offset, 16, ENC_NA);
        offset += 16;
        proto_tree_add_item_ret_uint(auth_qui_tree, hf_gtpv2_mm_context_xres_len, tvb, offset, 1, ENC_NA, &tmp);
        offset += 1;
        proto_tree_add_item(auth_qui_tree, hf_gtpv2_mm_context_xres, tvb, offset, tmp, ENC_NA);
        offset += tmp;
        proto_tree_add_item(auth_qui_tree, hf_gtpv2_ck, tvb, offset, 16, ENC_NA);
        offset += 16;
        proto_tree_add_item(auth_qui_tree, hf_gtpv2_ik, tvb, offset, 16, ENC_NA);
        offset += 16;
        proto_tree_add_item_ret_uint(auth_qui_tree, hf_gtpv2_mm_context_autn_len, tvb, offset, 1, ENC_NA, &tmp);
        offset += 1;
        proto_tree_add_item(auth_qui_tree, hf_gtpv2_mm_context_autn, tvb, offset, tmp, ENC_NA);
        offset += tmp;
    }

    return offset;

}

static int
dissect_gtpv2_authentication_quadruplets(tvbuff_t *tvb, proto_tree *tree, int offset, uint8_t nr_qui)
{
    proto_tree *auth_qua_tree;
    uint32_t    tmp;
    int         i;

    for (i = 0; i < nr_qui; i++) {
        auth_qua_tree = proto_tree_add_subtree_format(tree, tvb, offset, 0,
            ett_gtpv2_mm_context_auth_qua, NULL, "Authentication Quadruplet %u",i+1);

        proto_tree_add_item(auth_qua_tree, hf_gtpv2_mm_context_rand, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item_ret_uint(auth_qua_tree, hf_gtpv2_mm_context_xres_len, tvb, offset, 1, ENC_NA, &tmp);
        offset++;

        proto_tree_add_item(auth_qua_tree, hf_gtpv2_mm_context_xres, tvb, offset, tmp, ENC_NA);
        offset += tmp;

        proto_tree_add_item_ret_uint(auth_qua_tree, hf_gtpv2_mm_context_autn_len, tvb, offset, 1, ENC_NA, &tmp);
        offset++;

        proto_tree_add_item(auth_qua_tree, hf_gtpv2_mm_context_autn, tvb, offset, tmp, ENC_NA);
        offset += tmp;

        proto_tree_add_item(tree, hf_gtpv2_mm_context_kasme, tvb, offset, 32, ENC_NA);

        offset += 32;
    }
    return offset;
}

static const value_string gtpv2_mm_context_higher_br_16mb_flg_vals[] = {
    {0, "Not allowed"},
    {1, "Allowed"},
    {0, NULL}
};

static int
dissect_gtpv2_mm_context_common_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint8_t samb_ri, uint8_t uamb_ri)
{
    proto_tree *net_cap_tree, *msnt_cap_tree;
    uint8_t     ue_net_cap_len, ms_net_cap_len, mei_len;

    /*
     * If SAMBRI (Subscribed UE AMBR Indicator), bit 1 of octet 6, is set to "1",
     * then the Uplink/downlink Subscribed UE AMBR parameter field is present,
     */
    if (samb_ri) {
        /* j to (j+3) Uplink Subscribed UE AMBR */
        proto_tree_add_item(tree, hf_gtpv2_uplink_subscribed_ue_ambr, tvb, offset, 4, ENC_BIG_ENDIAN);

        offset += 4;
        /* (j+4) to (j+7) Downlink Subscribed UE AMBR */
        proto_tree_add_item(tree, hf_gtpv2_downlink_subscribed_ue_ambr, tvb, offset, 4, ENC_BIG_ENDIAN);

        offset += 4;
    }
    /*
     * If UAMBRI (Used UE AMBR Indicator), bit 2 of octet 6, is set to "1",
     * then the Uplink/downlink Used UE AMBR parameter field is present
     */
    if (uamb_ri) {
        /* i to (i+3) Uplink Used UE AMBR  */
        proto_tree_add_item(tree, hf_gtpv2_uplink_used_ue_ambr, tvb, offset, 4, ENC_BIG_ENDIAN);

        offset += 4;
        /* (i+4) to (i+7) Downlink Used UE AMBR */
        proto_tree_add_item(tree, hf_gtpv2_downlink_used_ue_ambr, tvb, offset, 4, ENC_BIG_ENDIAN);

        offset += 4;
    }
    /* q Length of UE Network Capability */
    ue_net_cap_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_mm_context_ue_net_cap_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* (q+1) to k UE Network Capability */
    if (ue_net_cap_len) {
        /* The UE Network Capability coding is specified in clause 9.9.3.34 of 3GPP TS 24.301 [23].
         * If Length of UE Network Capability is zero, then the UE Network Capability parameter
         * shall not be present.
         */
        net_cap_tree = proto_tree_add_subtree(tree, tvb, offset, ue_net_cap_len,
            ett_gtpv2_mm_context_net_cap, NULL, "UE Network Capability");
        offset += de_emm_ue_net_cap(tvb, net_cap_tree, pinfo, offset, ue_net_cap_len, NULL, 0);
    }
    /* k+1 Length of MS Network Capability */
    ms_net_cap_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_mm_context_ms_net_cap_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* (k+2) to m MS Network Capability
     * The MS Network Capability coding is specified in clause 10.5.5.12 of 3GPP TS 24.008 [5].
     * If Length of MS Network Capability is zero, then the MS Network Capability parameter shall not be present.
     */
    if (ms_net_cap_len) {
        msnt_cap_tree = proto_tree_add_subtree(tree, tvb, offset, ms_net_cap_len,
            ett_gtpv2_ms_network_capability, NULL, "MS network capability");
        offset += de_gmm_ms_net_cap(tvb, msnt_cap_tree, pinfo, offset, ms_net_cap_len, NULL, 0);
    }
    /* m+1 Length of Mobile Equipment Identity (MEI) */
    mei_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_mm_context_mei_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* (m+2) to r Mobile Equipment Identity (MEI) */
    if (mei_len) {
        proto_tree_add_item(tree, hf_gtpv2_mei, tvb, offset, mei_len, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);
        offset += mei_len;
    }
    return offset;
}

static int
dissect_gtpv2_access_restriction_data(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree *accrstdata_tree;

    accrstdata_tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_gtpv2_access_rest_data, NULL, "Access restriction data");
    /* Spare HNNA ENA INA GANA GENA UNA */
    proto_tree_add_bits_item(accrstdata_tree, hf_gtpv2_spare_bits, tvb, (offset << 3), 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(accrstdata_tree, hf_gtpv2_hbna, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(accrstdata_tree, hf_gtpv2_hnna, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(accrstdata_tree, hf_gtpv2_ena,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(accrstdata_tree, hf_gtpv2_ina,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(accrstdata_tree, hf_gtpv2_gana, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(accrstdata_tree, hf_gtpv2_gena, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(accrstdata_tree, hf_gtpv2_una,  tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

/* Type = 103 (decimal)
 * Figure 8.38-1: GSM Key and Triplets
 */
static void
dissect_gtpv2_mm_context_gsm_t(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree *flag_tree;
    int         offset;
    uint8_t     oct, drxi, num_triplet, uamb_ri, samb_ri;

    offset = 0;
    flag_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_gtpv2_mm_context_flag, NULL, "MM Context flags");

    /* Octet 5 */
    /* Security Mode | Spare | DRXI | CKSN */
    drxi = (tvb_get_uint8(tvb, offset) & 0x08) >> 3;
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm,   tvb, offset,      1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, offset << 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset,      1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_cksn, tvb, offset,      1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 6 */
    /* Number of Triplet | Spare  | UAMB RI | SAMB RI */
    oct = tvb_get_uint8(tvb, offset);
    num_triplet = oct >> 5;
    uamb_ri = (oct & 0x02) >> 1;
    samb_ri = oct & 0x01;

    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_tri,       tvb, offset,            1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits,         tvb, (offset << 3) + 3, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_uamb_ri,      tvb, offset,            1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_mm_context_samb_ri, tvb, (offset << 3) + 7, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 7 Spare Used Cipher */
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits,         tvb, ((offset << 3)),   5, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_used_cipher,  tvb, offset,            1, ENC_BIG_ENDIAN);
    offset += 1;

    /* 8 to 15 Kc */
    proto_tree_add_item(tree, hf_gtpv2_mm_context_kc, tvb, offset, 8, ENC_NA);
    offset += 8;

    /* 16 to h Authentication Triplet [0..4] */
    if (num_triplet) {
        dissect_gtpv2_authentication_triplets(tvb, tree, offset, num_triplet);
    }

    /*
     * (h+1) to (h+2) DRX parameter
     */
    if (drxi) {
        proto_tree_add_item(tree, hf_gtpv2_mm_context_drx, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    /* Dissect octet j to r */
    offset = dissect_gtpv2_mm_context_common_data(tvb, pinfo, tree, offset, samb_ri, uamb_ri);

    proto_tree_add_expert_format(flag_tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");
}

/* Type = 104 (decimal)
 * Figure 8.38-2: UMTS Key, Used Cipher and Quintuplets
 */
static void
dissect_gtpv2_mm_context_utms_cq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree *flag_tree;
    int         offset;
    uint8_t     oct, drxi, nr_qui, uamb_ri, samb_ri, vdp_len, hbr_len;

    offset = 0;
    flag_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_gtpv2_mm_context_flag, NULL, "MM Context flags");

    /* Octet 5 */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);
    drxi = (tvb_get_uint8(tvb, offset) & 0x08) >> 3;
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, ((offset << 3) + 3), 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_cksn_ksi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 6 */
    oct = tvb_get_uint8(tvb, offset);
    nr_qui = oct >> 5;
    uamb_ri = (oct & 0x02) >> 1;
    samb_ri = oct & 0x01;
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, (offset << 3) + 3, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_uamb_ri, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_mm_context_samb_ri, tvb, (offset << 3) + 7, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 7 Spare Used Cipher */
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, ((offset << 3)), 5, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_used_cipher, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 8 to 23  CK */
    proto_tree_add_item(tree, hf_gtpv2_ck, tvb, offset, 16, ENC_NA);
    offset += 16;
    /* Octet 24 to 39 IK */
    proto_tree_add_item(tree, hf_gtpv2_ik, tvb, offset, 16, ENC_NA);
    offset += 16;

    /*
     * 40 to h Authentication Quintuplet [0..4]
     */
    if (nr_qui) {
        offset = dissect_gtpv2_authentication_quintuplets(tvb, tree, offset, nr_qui);
    }

    /*
     * (h+1) to (h+2) DRX parameter
     */
    if (drxi) {
        proto_tree_add_item(tree, hf_gtpv2_mm_context_drx, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }


    /* Dissect octet j to r */
    offset = dissect_gtpv2_mm_context_common_data(tvb, pinfo, tree, offset, samb_ri, uamb_ri);

    /* r+1 Spare HNNA ENA INA GANA GENA UNA
     * The Access restriction data is composed of UNA(UTRAN Not Allowed), GENA(GERAN Not Allowed),
     * GANA(GAN Not Allowed), INA(I-HSPA-Evolution Not Allowed), ENA(E-UTRAN Not Allowed) and
     * HNNA(HO-To-Non-3GPPAccess Not Allowed).
     */
    if (offset < (int)length) {
        offset = dissect_gtpv2_access_restriction_data(tvb, tree, offset);
    } else {
        return;
    }
    if (offset == (int)length) {
        return;
    }

    /* r+2 Length of Voice Domain Preference and UE's Usage Setting */
    vdp_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_mm_context_vdp_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* (r+3) to s Voice Domain Preference and UE's Usage Setting */
    if (vdp_len) {
        proto_tree_add_item(tree, hf_gtpv2_voice_domain_and_ue_usage_setting, tvb, offset, vdp_len, ENC_NA);
        offset += vdp_len;
    }

    /* s+1 Length of Higher bitrates than 16 Mbps flag */
    if (offset == (int)length) {
        hbr_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tree, hf_gtpv2_mm_context_higher_br_16mb_flg_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* s+2 Higher bitrates than 16 Mbps flag */
        if (hbr_len) {
            proto_tree_add_item(tree, hf_gtpv2_mm_context_higher_br_16mb_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += hbr_len;
        }
    } else {
        return;
    }

    proto_tree_add_expert_format(flag_tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");

}

/* Type = 105 (decimal)
 * Figure 8.38-3: GSM Key, Used Cipher and Quintuplets
 */
static void
dissect_gtpv2_mm_context_gsm_cq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree *flag_tree;
    int         offset;
    uint8_t     oct, drxi, nr_qui, uamb_ri, samb_ri, vdp_len, hbr_len;

    offset = 0;
    flag_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_gtpv2_mm_context_flag, NULL, "MM Context flags");

    /* Octet 5 */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);
    drxi = (tvb_get_uint8(tvb, offset) & 0x08) >> 3;
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, ((offset << 3) + 3), 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_cksn_ksi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 6 */
    oct = tvb_get_uint8(tvb, offset);
    nr_qui = oct >> 5;
    uamb_ri = (oct & 0x02) >> 1;
    samb_ri = oct & 0x01;
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, (offset << 3) + 3, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_uamb_ri, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_mm_context_samb_ri, tvb, (offset << 3) + 7, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 7 Spare Used Cipher */
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, ((offset << 3)), 5, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_used_cipher, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* 8 to 15 Kc */
    proto_tree_add_item(tree, hf_gtpv2_mm_context_kc, tvb, offset, 8, ENC_NA);
    offset += 8;

    /*
     * 40 to h Authentication Quintuplet [0..4]
     */
    if (nr_qui) {
        offset = dissect_gtpv2_authentication_quintuplets(tvb, tree, offset, nr_qui);
    }

    /*
     * (h+1) to (h+2) DRX parameter
     */
    if (drxi) {
        proto_tree_add_item(tree, hf_gtpv2_mm_context_drx, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }


    /* Dissect octet j to r */
    offset = dissect_gtpv2_mm_context_common_data(tvb, pinfo, tree, offset, samb_ri, uamb_ri);

    /* r+1 Spare HNNA ENA INA GANA GENA UNA
     * The Access restriction data is composed of UNA(UTRAN Not Allowed), GENA(GERAN Not Allowed),
     * GANA(GAN Not Allowed), INA(I-HSPA-Evolution Not Allowed), ENA(E-UTRAN Not Allowed) and
     * HNNA(HO-To-Non-3GPPAccess Not Allowed).
     */
    if (offset < (int)length) {
        offset = dissect_gtpv2_access_restriction_data(tvb, tree, offset);
    } else {
        return;
    }
    if (offset == (int)length) {
        return;
    }

    /* r+2 Length of Voice Domain Preference and UE's Usage Setting */
    vdp_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_mm_context_vdp_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* (r+3) to s Voice Domain Preference and UE's Usage Setting */
    if (vdp_len) {
        proto_tree_add_item(tree, hf_gtpv2_voice_domain_and_ue_usage_setting, tvb, offset, vdp_len, ENC_NA);
        offset += vdp_len;
    }

    /* s+1 Length of Higher bitrates than 16 Mbps flag */
    if (offset < (int)length) {
        hbr_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tree, hf_gtpv2_mm_context_higher_br_16mb_flg_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* s+2 Higher bitrates than 16 Mbps flag */
        if (hbr_len) {
            proto_tree_add_item(tree, hf_gtpv2_mm_context_higher_br_16mb_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += hbr_len;
        }
    } else {
        return;
    }

    proto_tree_add_expert_format(flag_tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");

}

/* Type = 106 (decimal)
 * Figure 8.38-4: UMTS Key and Quintuplets
 */
static void
dissect_gtpv2_mm_context_utms_q(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree *flag_tree;
    int         offset;
    uint8_t     oct, drxi, nr_qui, uamb_ri, samb_ri, vdp_len, hbr_len, ear_len;

    offset = 0;
    flag_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_gtpv2_mm_context_flag, NULL, "MM Context flags");

    /* Octet 5 */
    /* Security Mode Spare DRXI KSI */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, ((offset << 3) + 3), 1, ENC_BIG_ENDIAN);
    drxi = (tvb_get_uint8(tvb, offset) & 0x08) >> 3;
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_ksi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 6 */
    /* Number of Quintuplets Spare UAMB RI SAMB RI */
    oct = tvb_get_uint8(tvb, offset);
    nr_qui = oct >> 5;
    uamb_ri = (oct & 0x02) >> 1;
    samb_ri = oct & 0x01;

    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, (offset << 3) + 3, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_uamb_ri, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_mm_context_samb_ri, tvb, (offset << 3) + 7, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 7 Spare */
    proto_tree_add_item(flag_tree, hf_gtpv2_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 8 to 23  CK */
    proto_tree_add_item(tree, hf_gtpv2_ck, tvb, offset, 16, ENC_NA);
    offset += 16;
    /* Octet 24 to 39 IK */
    proto_tree_add_item(tree, hf_gtpv2_ik, tvb, offset, 16, ENC_NA);
    offset += 16;

    /*
     * 40 to h Authentication Quintuplet [0..4]
     */
    if (nr_qui) {
        offset = dissect_gtpv2_authentication_quintuplets(tvb, tree, offset, nr_qui);
    }

    /*
     * (h+1) to (h+2) DRX parameter
     */
    if (drxi) {
        proto_tree_add_item(tree, hf_gtpv2_mm_context_drx, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }


    /* Dissect octet j to r */
    offset = dissect_gtpv2_mm_context_common_data(tvb, pinfo, tree, offset, samb_ri, uamb_ri);

    /* r+1 Spare HNNA ENA INA GANA GENA UNA
     * The Access restriction data is composed of UNA(UTRAN Not Allowed), GENA(GERAN Not Allowed),
     * GANA(GAN Not Allowed), INA(I-HSPA-Evolution Not Allowed), ENA(E-UTRAN Not Allowed) and
     * HNNA(HO-To-Non-3GPPAccess Not Allowed).
     */
    if (offset < (int)length) {
        offset = dissect_gtpv2_access_restriction_data(tvb, tree, offset);
    } else {
        return;
    }
    if (offset == (int)length) {
        return;
    }

    /* r+2 Length of Voice Domain Preference and UE's Usage Setting */
    vdp_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_mm_context_vdp_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* (r+3) to s Voice Domain Preference and UE's Usage Setting */
    if (vdp_len) {
        proto_tree_add_item(tree, hf_gtpv2_voice_domain_and_ue_usage_setting, tvb, offset, vdp_len, ENC_NA);
        offset += vdp_len;
    }

    /* s+1 Length of Higher bitrates than 16 Mbps flag */
    if (offset < (int)length) {
        hbr_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tree, hf_gtpv2_mm_context_higher_br_16mb_flg_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* s+2 Higher bitrates than 16 Mbps flag */
        if (hbr_len) {
            proto_tree_add_item(tree, hf_gtpv2_mm_context_higher_br_16mb_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += hbr_len;
        }
    } else {
        return;
    }

    /* s+3    IOV_updates counter */
    if (offset < (int)length) {
        proto_tree_add_item(tree, hf_gtpv2_mm_context_iov_updates_counter, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    } else {
        return;
    }
    /* s+4    Length of Extended Access Restriction Data */
    if (offset < (int)length) {
        ear_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tree, hf_gtpv2_mm_context_ear_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        static int * const ear_flags[] = {
            &hf_gtpv2_mm_context_nrsrna,
            NULL
        };
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, ear_flags, ENC_BIG_ENDIAN);
        offset += 1;
        if (ear_len > 1) {
            proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");
            offset += ear_len - 1;
        }
    } else {
        return;
    }

    if (offset == (int)length) {
        return;
    }
    /* ts+1) to (n+4) These octet(s) is/are present only if explicitly specified */
    proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");

}

/* 8.38 MM Context
 * Type = 107 (decimal)
 * Figure 8.38-5: EPS Security Context and Quadruplets
 */
static void
dissect_gtpv2_mm_context_eps_qq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_item *qua_item, *qui_item;
    proto_tree *flag_tree, *qua_tree, *qui_tree, *sc_tree;
    int         offset;
    uint8_t     tmp, nhi, drxi, nr_qua, nr_qui, uamb_ri, osci, samb_ri, vdp_len;
    uint32_t    dword, paging_len, ue_add_sec_cap_len, ex_access_res_data_len, ue_nr_sec_cap_len, apn_rte_ctrl_sts_len, ie_len;

    offset = 0;

    flag_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_gtpv2_mm_context_flag, NULL, "MM Context flags");

    /* Octet 5
     * Bits
     * 8      7     6     5     4      3      2      1
     * Security Mode    | NHI | DRXI | KSIASME
     */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* If NHI (Next Hop Indicator), bit 5 of octet 5, is set to "1",
     * then the optional parameters NH (Next Hop) and NCC (Next
     * Hop Chaining Count) are both present, otherwise their octets are not present.
     */
    tmp = tvb_get_uint8(tvb, offset);
    nhi = (tmp & 0x10) >> 4;
    drxi = (tmp & 0x08) >> 3;
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_ksi_a, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 6
     * Bits
     * 8      7     6     5     4      3      2      1
     * Number of        | Number of       | UAMB  | OSCI
     * Quintuplets      | Quadruplet      |  RI   |
     */
    tmp = tvb_get_uint8(tvb, offset);
    nr_qui = (tmp & 0xe0) >> 5;
    nr_qua = tmp & 0x1c;
    nr_qua >>= 2;
    uamb_ri = (tmp & 0x2) >> 1;
    osci = tmp & 1;

    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qua, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* UAMB RI */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_uamb_ri, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* OSCI */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_osci, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 7 SAMB RI Used NAS integrity protection algorithm Used NAS Cipher*/
    /* SAMB RI */
    samb_ri = tvb_get_uint8(tvb, offset) >> 7;
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_mm_context_samb_ri, tvb, offset << 3, 1, ENC_BIG_ENDIAN);
    /* Used NAS integrity protection algorithm */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_unipa, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Used NAS Cipher */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_unc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 8-10 NAS Downlink Count*/
    proto_tree_add_item(tree, hf_gtpv2_mm_context_nas_dl_cnt, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Octet 11-13 NAS Uplink Count */
    proto_tree_add_item(tree, hf_gtpv2_mm_context_nas_ul_cnt, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Octet 14-45 */
    proto_tree_add_item(tree, hf_gtpv2_mm_context_kasme, tvb, offset, 32, ENC_NA);
    offset += 32;

    qua_item = proto_tree_add_uint(tree, hf_gtpv2_authentication_quadruplets, tvb, offset, 0, nr_qua);
    if ( nr_qua ){
        qua_tree = proto_item_add_subtree(qua_item, ett_gtpv2_qua);
        offset = dissect_gtpv2_authentication_quadruplets(tvb, qua_tree, offset, nr_qua);
    }else {
        proto_item_set_generated(qua_item);
    }

    qui_item = proto_tree_add_uint(tree, hf_gtpv2_authentication_quintuplets, tvb, offset, 0, nr_qui);
    if (nr_qui) {
        qui_tree = proto_item_add_subtree(qui_item, ett_gtpv2_qui);
        offset = dissect_gtpv2_authentication_quintuplets(tvb, qui_tree, offset, nr_qui);
    }else{
        proto_item_set_generated(qui_item);
    }

    /* (h+1) to (h+2) DRX parameter */
    if (drxi) {
        proto_tree_add_item(tree, hf_gtpv2_mm_context_drx, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    /* Octet p to p+31 & Octet p+32 */
    if ( nhi )
    {
        proto_tree_add_item(tree, hf_gtpv2_mm_context_nh, tvb, offset, 32, ENC_NA);
        offset += 32;

        proto_tree_add_item(tree, hf_gtpv2_mm_context_ncc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }


    /* Dissect octet j to r */
    offset = dissect_gtpv2_mm_context_common_data(tvb, pinfo, tree, offset, samb_ri, uamb_ri);

    /* r+1 Spare HBNA HNNA ENA INA GANA GENA UNA */
    if (offset < (int)length) {
        offset = dissect_gtpv2_access_restriction_data(tvb, tree, offset);
    } else {
        return;
    }

    if (offset == (int)length) {
        return;
    }

    /* the fields for the Old EPS Security Context (i.e. octets from s to s+64)
     * may be present only in S10 Forward Relocation Request message according to
     * the Rules on Concurrent Running of Security Procedures, which are specified in 3GPP TS 33.401 [12].
     * The octets for Old EPS Security Context shall be present if the OSCI (Old Security Context Indicator),
     * bit 1 of octet 6) is set to "1"; otherwise they shall not be present.
     */
    if (osci == 1) {
        /* s */
        /* If NHI_old (Next Hop Indicator for old EPS Security Context), bit 1 of octet s, is set to "1",
         * then the parameters old NH (Next Hop) and old NCC (Next Hop Chaining Count) shall be present;
         * otherwise the octets for old NH parameter shall not be present and the value of old NCC parameter
         * shall be ignored by the receiver
         */
        /* NHI_old Spare old KSIASME old NCC*/
        proto_tree_add_item_ret_uint(tree, hf_gtpv2_mm_contex_nhi_old, tvb, offset, 1, ENC_BIG_ENDIAN, &dword);
        proto_tree_add_item(tree, hf_gtpv2_mm_context_old_ksiasme, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gtpv2_mm_context_old_ncc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* (s+1) to (s+32) old KASME */
        proto_tree_add_item(tree, hf_gtpv2_mm_context_old_kasme, tvb, offset, 32, ENC_NA);
        offset += 32;
        /* (s+33) to (s+64) old NH */
        if (dword) {
            proto_tree_add_item(tree, hf_gtpv2_mm_context_old_nh, tvb, offset, 32, ENC_NA);
            offset += 32;
        }
    }

    if (offset == (int)length) {
        return;
    }

    /* w Length of Voice Domain Preference and UE's Usage Setting */
    vdp_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_mm_context_vdp_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* (r+3) to s Voice Domain Preference and UE's Usage Setting */
    if (vdp_len) {
        proto_tree_add_item(tree, hf_gtpv2_voice_domain_and_ue_usage_setting, tvb, offset, vdp_len, ENC_NA);
        offset += vdp_len;
    }

    if (offset == (int)length) {
        return;
    }

    /* (t+1) to (t+2) Length of UE Radio Capability for Paging information*/
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_mm_context_paging_len, tvb, offset, 2, ENC_BIG_ENDIAN, &paging_len);
    offset += 2;

    if (paging_len > 0) {
        proto_tree_add_item(tree, hf_gtpv2_ue_radio_capability_for_paging_information, tvb, offset, paging_len, ENC_NA);
        offset +=paging_len;
    }

    if (offset == (int)length) {
        return;
    }

    /*(u+1) Length of Extended Access Restriction Data */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_mm_context_ex_access_res_data_len, tvb, offset, 1, ENC_BIG_ENDIAN, &ex_access_res_data_len);
    offset += 1;

    /*(u+2) to v
     *8      7     6     5     4      3      2      1
     *            spare               |    USSRNA | NRSRNA
     */
    if(ex_access_res_data_len > 0){
        static int* const ear_flags[] = {
            &hf_gtpv2_spare_b7_b5,
            &hf_gtpv2_mm_context_nruna,
            &hf_gtpv2_mm_context_nrusrna,
            &hf_gtpv2_mm_context_nrna,
            &hf_gtpv2_mm_context_ussrna,
            &hf_gtpv2_mm_context_nrsrna,
            NULL
        };
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, ear_flags, ENC_BIG_ENDIAN);

        offset += 1;
        if (ex_access_res_data_len > 1) {
            proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, ex_access_res_data_len - 1, "The rest of the IE not dissected yet");
            offset += ex_access_res_data_len - 1;
        }
    }

    if (offset == (int)length) {
        return;
    }

    /*
    * The UE additional security capability coding is specified in clause 9.9.3.53 of 3GPP TS 24.301 [23].
    * If Length of UE additional security capability is zero, then the field UE additional security capability in octets "(v+2) to x" shall not be present.
    */
    /*(v+1) Length of UE additional security capability*/
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_mm_context_ue_add_sec_cap_len, tvb, offset, 1, ENC_BIG_ENDIAN, &ue_add_sec_cap_len);
    offset += 1;

    /*(v+2) to x UE additional security capability*/
    if(ue_add_sec_cap_len > 0){
        sc_tree = proto_tree_add_subtree(tree, tvb, offset, ue_add_sec_cap_len, ett_gtpv2_mm_context_sc, NULL, "UE additional Security Capability");
        offset += de_emm_ue_add_sec_cap(tvb, sc_tree, NULL, offset, ue_add_sec_cap_len, NULL, 0);
    }

    if (offset == (int)length) {
        return;
    }

    /* x+1 Length of UE NR security capability */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_mm_context_ue_nr_sec_cap_len, tvb, offset, 1, ENC_BIG_ENDIAN, &ue_nr_sec_cap_len);
    offset += 1;
    /* The UE NR security capability coding is specified in clause 9.8.3.57 of 3GPP TS 24.501.
     * If Length of UE NR security capability is zero, then the field UE NR security capability in octets
     "(x+2) to y" shall not be present.
     */
    if (ue_nr_sec_cap_len) {
        /* (x+2) to y UE NR security capability */
        /* The UE NR security capability coding is specified in clause 9.8.3.57 of 3GPP TS 24.501 */
        sc_tree = proto_tree_add_subtree(tree, tvb, offset, ue_nr_sec_cap_len, ett_gtpv2_ue_nr_sec_cap_len, NULL, "UE NR security capability");
        proto_tree_add_expert_format(sc_tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, ue_nr_sec_cap_len, "The rest of the IE not dissected yet");
        offset += ue_nr_sec_cap_len;
    }

    if (offset == (int)length) {
        return;
    }

    /* (y+1) to (y+2) Length of APN Rate Control Statuses */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_mm_context_apn_rte_ctrl_sts_len, tvb, offset, 2, ENC_BIG_ENDIAN, &apn_rte_ctrl_sts_len);
    offset += 2;
    if (apn_rte_ctrl_sts_len) {
        /* (y+3) to l APN Rate Control Status [1..z] */
        sc_tree = proto_tree_add_subtree(tree, tvb, offset, apn_rte_ctrl_sts_len, ett_gtpv2_apn_rte_ctrl_sts_len, NULL, "APN Rate Control Status");
        proto_tree_add_expert_format(sc_tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, apn_rte_ctrl_sts_len, "The rest of the IE not dissected yet");
        offset += apn_rte_ctrl_sts_len;
    }
    if (offset == (int)length) {
        return;
    }

    /* (l+1)  Length of Core Network Restrictions */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_mm_context_cnr_len, tvb, offset, 1, ENC_BIG_ENDIAN, &ie_len);
    offset += 1;
    if (ie_len) {
        /* (l+2) to (l+5)    Core Network Restrictions */
        /* The Core Network Restrictions coding is specified in clause 7.2.230 of 3GPP TS 29.272 [70].
           If Length of Core Network Restrictions is zero, then the field of Core Network Restrictions
           in octets "(l+2) to (l+5)" shall not be present.
         */
        tvbuff_t *new_tvb = tvb_new_subset_length(tvb, offset, ie_len);
        dissect_diameter_3gpp_core_network_restrictions(new_tvb, pinfo, tree, NULL);
        offset += ie_len;
    }

    if (offset == (int)length) {
        return;
    }

    /* (l+6)  Length of UE Radio Capability ID */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_mm_context_ue_radio_cap_len, tvb, offset, 1, ENC_BIG_ENDIAN, &ie_len);
    offset += 1;
    if (ie_len) {
        /* (l+7) to z UE Radio Capability ID
         * The UE Radio Capability ID is specified in the clause 9.9.3.60 of 3GPP TS24.301
         */
        de_nas_5gs_mm_ue_radio_cap_id(tvb, tree, pinfo, offset, ie_len, NULL, 0);
        offset += ie_len;
    }

    if (offset == (int)length) {
        return;
    }

    /*(a) ENSCT */
    proto_tree_add_item(tree, hf_gtpv2_mm_context_ensct, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset < (int)length){
        proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, length - offset, "The rest of the IE not dissected yet");
    }
}

/*
 * Type = 108 (decimal)
 * Figure 8.38-6: UMTS Key, Quadruplets and Quintuplets
 */
static void
dissect_gtpv2_mm_context_utms_qq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree *flag_tree;
    uint32_t    offset;
    uint8_t     tmp, drxi, nr_qua, nr_qui, uamb_ri, samb_ri, vdp_length;

    offset = 0;
    flag_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_gtpv2_mm_context_flag, NULL, "MM Context flags");

    /* Octet 5
     * Security Mode Spare DRXI KSIASME
     */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, ((offset << 3) + 3), 1, ENC_BIG_ENDIAN);
    drxi = (tvb_get_uint8(tvb, offset) & 0x08) >> 3;
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_ksi_a, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 6
     * Bits
     * 8      7     6     5     4      3      2      1
     * Number of        | Number of       | UAMB  | SAMB
     * Quintuplets      | Quadruplet      |  RI   |  RI
     */
    tmp = tvb_get_uint8(tvb, offset);
    nr_qui = (tmp & 0xe0) >> 5;
    nr_qua = tmp & 0x1c;
    nr_qua >>= 2;
    uamb_ri = (tmp & 0x2) >> 1;
    samb_ri = tmp & 0x01;

    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qua, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_uamb_ri, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_mm_context_samb_ri, tvb, (offset << 3) + 7, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 7 Spare */
    proto_tree_add_item(flag_tree, hf_gtpv2_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 8 to 23  CK */
    proto_tree_add_item(tree, hf_gtpv2_ck, tvb, offset, 16, ENC_NA);
    offset += 16;
    /* Octet 24 to 39 IK */
    proto_tree_add_item(tree, hf_gtpv2_ik, tvb, offset, 16, ENC_NA);
    offset += 16;

    if ( nr_qua ) {
        offset = dissect_gtpv2_authentication_quadruplets(tvb, tree, offset, nr_qua);
    }

    if (nr_qui) {
        offset = dissect_gtpv2_authentication_quintuplets(tvb, tree, offset, nr_qui);
    }

    /* (h+1) to (h+2) DRX parameter */
    if (drxi) {
        proto_tree_add_item(tree, hf_gtpv2_mm_context_drx, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    /* Dissect octet j to r */
    offset = dissect_gtpv2_mm_context_common_data(tvb, pinfo, tree, offset, samb_ri, uamb_ri);

    if (offset >= (uint32_t)length) {
        return;
    }
    /* r+1 Spare HBNA HNNA ENA INA GANA GENA UNA */
    offset = dissect_gtpv2_access_restriction_data(tvb, tree, offset);

    if (offset >= (uint32_t)length) {
        return;
    }

    /* The Voice Domain Preference and UE's Usage Setting coding is specified in clause 10.5.5.28 of 3GPP TS 24.008 [5]. If
     * Length of Voice Domain Preference and UE's Usage Setting is zero, then the Voice Domain Preference and UE's Usage
     * Setting parameter shall not be present.
     */
    /* r+2 */
    vdp_length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_vdp_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if(vdp_length !=0){
        offset += de_gmm_voice_domain_pref(tvb, tree, pinfo, offset, vdp_length, NULL, 0);
    }

    if (offset < (uint32_t)length) {
        proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");
    }

}

/*
  * 8.39 PDN Connection (grouped IE)
 */
static void
dissect_gtpv2_PDN_conn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    proto_tree *grouped_tree;
    tvbuff_t   *new_tvb;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(item, ett_gtpv2_PDN_conn);
    new_tvb = tvb_new_subset_length(tvb, offset, length);

    dissect_gtpv2_ie_common(new_tvb, pinfo, grouped_tree, offset, message_type, args, GTPV2_IE_PDN_CONNECTION);
}
/*
 * 8.40 PDU Numbers
 */
static void
dissect_gtpv2_pdn_numbers(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_item *nsapi_ti;
    proto_tree *nsapi_tree;
    uint8_t     nsapi;
    int         offset = 0;

    nsapi = (tvb_get_uint8(tvb, offset) & 0x08);
    nsapi_ti = proto_tree_add_item(tree, hf_gtpv2_nsapi08, tvb, offset, 1, ENC_BIG_ENDIAN);
    nsapi_tree = proto_item_add_subtree(nsapi_ti, ett_gtpv2_pdn_numbers_nsapi);
    proto_tree_add_bits_item(nsapi_tree, hf_gtpv2_spare_bits, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(nsapi_tree, hf_gtpv2_pdn_numbers_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "NSAPI: %u", nsapi);
    offset += 1;

    proto_tree_add_item(tree, hf_gtpv2_dl_gtp_u_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_gtpv2_ul_gtp_u_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_gtpv2_send_n_pdu_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_gtpv2_receive_n_pdu_number, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/*
 * 8.41 Packet TMSI (P-TMSI)
 */
static void
dissect_gtpv2_p_tmsi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    proto_item* ti;

    /* The TMSI consists of 4 octets. It can be coded using a full hexadecimal representation. */
    proto_tree_add_item(tree, hf_gtpv2_p_tmsi, tvb, offset, 4, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(tree, hf_3gpp_tmsi, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_set_hidden(ti);
    proto_item_append_text(item, "%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, 4));
}

/*
 * 8.42 P-TMSI Signature
 */
static void
dissect_gtpv2_p_tmsi_sig(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    /* The P-TMSI Signature consists of 3 octets and may be allocated by the SGSN. */
    proto_tree_add_item(tree, hf_gtpv2_p_tmsi_sig, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s", tvb_bytes_to_str(pinfo->pool, tvb, offset, 3));

}

/*
 * 8.43 Hop Counter
 */
static void
dissect_gtpv2_hop_counter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int    offset = 0;
    uint8_t hop_counter;

    hop_counter = tvb_get_uint8(tvb, offset);

    proto_tree_add_item(tree, hf_gtpv2_hop_counter, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%d", hop_counter);
}

/*
 * 8.44 UE Time Zone
 */

static const value_string gtpv2_ue_time_zone_dst_vals[] = {
    {0, "No Adjustments for Daylight Saving Time"},
    {1, "+1 Hour Adjustments for Daylight Saving Time"},
    {2, "+2 Hour Adjustments for Daylight Saving Time"},
    {3, "Spare"},
    {0, NULL}
};
static void
dissect_gtpv2_ue_time_zone(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    /*
     * UE Time Zone is used to indicate the offset between universal time and local time in steps of 15 minutes of where the
     * UE currently resides. The "Time Zone" field uses the same format as the "Time Zone" IE in 3GPP TS 24.008 [5].
     * (packet-gsm_a_dtap.c)
     */
    de_time_zone(tvb, tree, pinfo, offset, 1, NULL, 0);
    offset += 1;
    proto_tree_add_item(item, hf_gtpv2_ue_time_zone_dst, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/*
 * 8.45 Trace Reference
 */
static void
dissect_gtpv2_trace_reference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int      offset = 0;
    uint32_t trace_id;
    char    *mcc_mnc_str;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, 0, E212_NONE, true);
    offset += 3;

    trace_id = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_trace_id, tvb, offset, 3, ENC_BIG_ENDIAN);

    proto_item_append_text(item, "%s,Trace ID %u", mcc_mnc_str, trace_id);
}
/*
 * 8.46 Complete Request Message
 */
static const value_string gtpv2_complete_req_msg_type_vals[] = {
    {0, "Complete Attach Request Message"  },
    {1, "Complete TAU Request Message"     },
    {0, NULL                               }
};
static void
dissect_complete_request_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    tvbuff_t  *new_tvb;
    int        offset;

    offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_complete_req_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    /* Add the Complete Request Message */
    new_tvb = tvb_new_subset_length(tvb, offset, length-1);
    call_dissector(nas_eps_handle, new_tvb, pinfo, tree);

}

/*
 * 8.47 GUTI
 */
static void
dissect_gtpv2_guti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    offset = 0;

    dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, E212_NONE, true);
    offset += 3;

    proto_tree_add_item(tree, hf_gtpv2_mme_grp_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_gtpv2_mme_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_gtpv2_m_tmsi, tvb, offset, 4, ENC_NA);
}

/*
 * 8.48 Fully Qualified Container (F-Container)
 */

static const value_string gtpv2_container_type_vals[] = {
    {1, "UTRAN transparent container"},
    {2, "BSS container"},
    {3, "E-UTRAN transparent container"},
    {4, "NBIFOM Container"},
    {5, "EN-DC Container"},
    {6, "Inter-System SON Container"},
    {0, NULL}
};


static void
dissect_gtpv2_F_container(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type, uint8_t instance _U_, session_args_t * args _U_)
{
    tvbuff_t   *new_tvb;
    proto_tree *sub_tree;
    int         offset = 0;
    uint32_t     container_type;
    uint8_t     container_flags, xid_len;

    /* Octets   8   7   6   5   4   3   2   1
     * 5            Spare     | Container Type
     */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_container_type, tvb, offset, 1, ENC_BIG_ENDIAN, &container_type);
    offset += 1;
    length--;
    if (length == 0) {
        expert_add_info(pinfo, item, &ei_gtpv2_ie_len_invalid);
        return;
    }
    if (   (message_type == GTPV2_FORWARD_RELOCATION_REQ)
        || (message_type == GTPV2_CONTEXT_RESPONSE)
        || (message_type == GTPV2_RAN_INFORMATION_RELAY)) {
        switch (container_type) {
        case 1:
            /* UTRAN transparent container (1)
             * Contains the "Source to Target
             * Transparent Container", if the message is used for PS
             * handover to UTRAN Iu mode procedures, SRNS relocation
             * procedure and E-UTRAN to UTRAN inter RAT handover
             * procedure.
             */
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_gtpv2_utran_con, NULL, "UTRAN transparent container");
            new_tvb = tvb_new_subset_length(tvb, offset, length);
            dissect_ranap_Source_ToTarget_TransparentContainer_PDU(new_tvb, pinfo, sub_tree, NULL);
            return;
        case 2:
            /* BSS container */
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_gtpv2_bss_con, NULL, "BSS container");
            /* The flags PFI, RP, SAPI and PHX in octet 6 indicate the corresponding type of parameter */
            proto_tree_add_item(sub_tree, hf_gtpv2_bss_container_phx, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_sapi_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_rp_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_pfi_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
            container_flags = tvb_get_uint8(tvb, offset);
            offset += 1;
            if ((container_flags & 0x01) == 1) {
                /* Packet Flow ID present */
                proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_pfi, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            if (((container_flags & 0x04) == 4) || ((container_flags & 0x02) == 2)) {
                if ((container_flags & 0x04) == 4) {
                    /* SAPI present */
                    proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_sapi, tvb, offset, 1, ENC_BIG_ENDIAN);
                }
                if ((container_flags & 0x02) == 2) {
                    /* Radio Priority present */
                    proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_rp, tvb, offset, 1, ENC_BIG_ENDIAN);
                }
                offset += 1;
            }
            if ((container_flags & 0x08) == 8) {
                /* XiD parameters length is present in Octet c.
                 * XiD parameters are present in Octet d to n.
                 */
                xid_len = tvb_get_uint8(tvb, offset);
                proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_xid_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_xid, tvb, offset, xid_len, ENC_NA);
            }
            return;
        case 3:
            /* E-UTRAN transparent container
            * This IE shall be included to contain the "Source to Target
            * Transparent Container", if the message is used for
            * UTRAN/GERAN to E-UTRAN inter RAT handover
            * procedure, E-UTRAN intra RAT handover procedure and
            * 3G SGSN to MME combined hard handover and SRNS
            * relocation procedure. The Container Type shall be set to 3.
            */
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_gtpv2_eutran_con, NULL, "E-UTRAN transparent container");
            new_tvb = tvb_new_subset_length(tvb, offset, length);
            dissect_s1ap_SourceeNB_ToTargeteNB_TransparentContainer_PDU(new_tvb, pinfo, sub_tree, NULL);
            return;
        default:
            break;
        }
    }
    if (message_type == GTPV2_FORWARD_CTX_NOTIFICATION) {
        switch (container_type) {
        case 3:
            /* E-UTRAN transparent container */
            new_tvb = tvb_new_subset_length(tvb, offset, length);
            dissect_s1ap_ENB_StatusTransfer_TransparentContainer_PDU(new_tvb, pinfo, tree, NULL);
            return;
        default:
            break;
        }
    }
    if (message_type == GTPV2_FORWARD_RELOCATION_RESP) {

    /* 7.3.2 Forward Relocation Response */
        switch (container_type) {
        case 3:
            /* E-UTRAN transparent container
             * This IE shall be included to contain the "Target to Source Transparent Container"
             * during a handover to E-UTRAN, 5GS to EPS handover and EPS to 5GS handover.
             * If the Cause IE contains the value "Request accepted". The Container Type shall be set to 3.
             */
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_gtpv2_eutran_con, NULL, "E-UTRAN transparent container");
            new_tvb = tvb_new_subset_length(tvb, offset, length);
            dissect_s1ap_TargeteNB_ToSourceeNB_TransparentContainer_PDU(new_tvb, pinfo, sub_tree, NULL);
            return;
        default:
            break;
        }
    }
    if (message_type == GTPV2_CONFIGURATION_TRANSFER_TUNNEL) {
    /* 7.3.18 Configuration Transfer Tunnel */
        switch (container_type) {
        case 3:
            /* SON Configuration Transfer
             * This IE shall be included to contain the "SON Configuration Transfer" as specified in 3GPP TS 36.413 [10].
             * The Container Type shall be set to 3.
             */
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_gtpv2_son_con, NULL, "SON Configuration Transfer");
            new_tvb = tvb_new_subset_length(tvb, offset, length);
            dissect_s1ap_SONConfigurationTransfer_PDU(new_tvb, pinfo, sub_tree, NULL);
            return;
        case 5:
            /* EN-DC SON Configuration Transfer
             * This IE shall be included to contain the "EN-DC SON Configuration Transfer" as specified in 3GPP TS 36.413 [10].
             * The Container Type shall be set to 5.
             */
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_gtpv2_endc_son_con, NULL, "EN-DC SON Configuration Transfer");
            new_tvb = tvb_new_subset_length(tvb, offset, length);
            dissect_s1ap_EN_DCSONConfigurationTransfer_PDU(new_tvb, pinfo, sub_tree, NULL);
            return;
        case 6:
            /* Inter-System SON Container
             * This IE shall be included to contain the "Inter-System SON Container" as specified in 3GPP TS 36.413 [10].
             * The Container Type shall be set to 6.
             */
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_gtpv2_intersys_son_con, NULL, "Inter-System SON Container");
            new_tvb = tvb_new_subset_length(tvb, offset, length);
            dissect_s1ap_IntersystemSONConfigurationTransfer_PDU(new_tvb, pinfo, sub_tree, NULL);
            return;
        default:
            break;
        }
    }
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, length);

}

/*
 * 8.49 Fully Qualified Cause (F-Cause)
 */

static const value_string gtpv2_cause_type_vals[] = {
    {0,  "Radio Network Layer"},
    {1,  "Transport Layer"},
    {2,  "NAS"},
    {3,  "Protocol"},
    {4,  "Miscellaneous"},
    {5,  "<spare>"},
    {6,  "<spare>"},
    {7,  "<spare>"},
    {8,  "<spare>"},
    {9,  "<spare>"},
    {10, "<spare>"},
    {11, "<spare>"},
    {12, "<spare>"},
    {13, "<spare>"},
    {14, "<spare>"},
    {15, "<spare>"},
    {0, NULL}
};
static value_string_ext gtpv2_cause_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_cause_type_vals);

static void
dissect_gtpv2_s1ap_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, uint8_t cause_type)
{

    switch (cause_type) {
    case 0:
        /* CauseRadioNetwork */
        proto_tree_add_item(tree, hf_gtpv2_CauseRadioNetwork, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 1:
        /* CauseTransport */
        proto_tree_add_item(tree, hf_gtpv2_CauseTransport, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 2:
        /* CauseNas */
        proto_tree_add_item(tree, hf_gtpv2_CauseNas, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 3:
        /* CauseProtocol */
        proto_tree_add_item(tree, hf_gtpv2_CauseProtocol, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 4:
        /* CauseMisc */
        proto_tree_add_item(tree, hf_gtpv2_CauseMisc, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    default:
        break;
    }

    return;

}
static void
dissect_gtpv2_F_cause(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type, uint8_t instance, session_args_t * args _U_)
{
    int    offset = 0;
    uint8_t cause_type;

    /* The value of Instance field of the F-Cause IE in a GTPv2 message shall indicate
     * whether the F-Cause field contains RANAP Cause, BSSGP Cause or RAN Cause.
     * If the F-Cause field contains RAN Cause, the Cause Type field shall contain
     * the RAN cause subcategory as specified in 3GPP TS 36.413 [10] and it shall be
     * encoded as in Table 8.49-1.
     * If the F-Cause field contains BSSGP Cause or RANAP Cause,
     * the Cause Type field shall be ignored by the receiver.
     */
    if (message_type == GTPV2_FORWARD_RELOCATION_REQ) {
        switch (instance) {
        case 0:
            proto_item_append_text(item, "[RAN Cause]");
            proto_tree_add_item(tree, hf_gtpv2_cause_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            cause_type = tvb_get_uint8(tvb, offset);
            offset += 1;
            dissect_gtpv2_s1ap_cause(tvb, pinfo, tree, offset, cause_type);
            return;
        case 1:
            proto_item_append_text(item, "[RANAP Cause]");
            break;
        case 2:
            proto_item_append_text(item, "[BSSGP Cause]");
            break;
        default:
            break;
        }
    }
    else if (message_type == GTPV2_FORWARD_RELOCATION_RESP) {
        /* Table 7.3.2-1: Information Elements in a Forward Relocation Response */
        switch (instance) {
        case 0:
            /* Instance 0 S1-AP Cause */
            proto_item_append_text(item, "[S1-AP Cause]");
            proto_tree_add_item(tree, hf_gtpv2_cause_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            cause_type = tvb_get_uint8(tvb, offset);
            offset++;
            dissect_gtpv2_s1ap_cause(tvb, pinfo, tree, offset, cause_type);
            return;
        case 1:
            /* Instance 1 RANAP Cause */
            proto_item_append_text(item, "[RANAP Cause]");
            break;
        case 2:
            /* Instance 2 BSSGP Cause */
            proto_item_append_text(item, "[BSSGP Cause]");
            break;
        default:
            break;
        }

    }/* GTPV2_FORWARD_RELOCATION_RESP */

    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, length-offset);

}

/*
 * 8.50 PLMN ID
 */
/*
 * The Selected PLMN ID IE contains the core network operator selected for tne UE
 * in a shared network. Octets 5-7 shall be encoded as the content part of the
 *  "Selected PLMN Identity" parameter in 3GPP TS 36.413 [10].
 * -The Selected PLMN identity consists of 3 digits from MCC followed by
 * either -a filler digit plus 2 digits from MNC (in case of 2 digit MNC) or
 * -3 digits from MNC (in case of a 3 digit MNC).
 *
 *         8  7  6  5  4  3  2  1
 *         +--+--+--+--+--+--+--+--+
 * Octet 5 |MCC digit 2|MCC digit 1|
 *         +--+--+--+--+--+--+--+--+
 * Octet 6 |MNC digit 1|MCC digit 3|
 *         +--+--+--+--+--+--+--+--+
 * Octet 7 |MNC digit 3|MNC digit 2|
 *         +--+--+--+--+--+--+--+--+
 */
static void
dissect_gtpv2_plmn_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    char *mcc_mnc_str;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, 0, E212_NONE, false);
    proto_item_append_text(item, "%s", mcc_mnc_str);
}

/*
 * 8.51 Target Identification
 */

static const value_string gtpv2_target_type_vals[] = {
    {0,  "RNC ID"},
    {1,  "Macro eNodeB ID"},
    {2,  "Cell Identifier"},
    {3,  "Home eNodeB ID"},
    {4,  "Extended Macro eNodeB ID"},
    {5,  "gNodeB ID"},
    {6,  "Macro ng-eNodeB ID"},
    {7,  "Extended ng-eNodeB ID"},
    {8,  "en-gNB ID"},
    {0, NULL}
};
static value_string_ext gtpv2_target_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_target_type_vals);

static char*
dissect_gtpv2_home_enodeb_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset)
{
    char       *str = NULL;
    char       *mcc_mnc_str;
    uint32_t    home_enodeb_id;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, *offset, E212_NONE, true);
    *offset += 3;

    /* Octet 10 to 12 Home eNodeB ID
        * The Home eNodeB ID consists of 28 bits. See 3GPP TS 36.413 [10].
        * Bit 4 of Octet 9 is the most significant bit and bit 1 of Octet 12 is the least significant bit.
        * The coding of the Home eNodeB ID is the responsibility of each administration.
        * Coding using full hexadecimal representation shall be used.
        */
    home_enodeb_id = tvb_get_ntohl(tvb, *offset) & 0x0fffffff;
    proto_tree_add_item(tree, hf_gtpv2_home_enodeb_id, tvb, *offset, 4 , ENC_BIG_ENDIAN);
    *offset += 4;

    str = wmem_strdup_printf(pinfo->pool, "%s, Home eNodeB ID 0x%x",
        mcc_mnc_str,
        home_enodeb_id);

    return str;
}

static char*
dissect_gtpv2_gnodeb_id(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int* offset)
{
    char* str = NULL;
    char* mcc_mnc_str;
    uint32_t    gnodeb_id;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, *offset, E212_NONE, true);
    *offset += 3;

    /* The gNodeB ID Length field, in bits 1 to 6 of octet 9,
     * indicates the length of the gNodeB ID in number of bits
     */

    proto_tree_add_item(tree, hf_gtpv2_gnodeb_id_len, tvb, *offset, 1, ENC_BIG_ENDIAN);
    *offset += 1;

    proto_tree_add_item_ret_uint(tree, hf_gtpv2_gnodeb_id, tvb, *offset, 4, ENC_BIG_ENDIAN, &gnodeb_id);
    *offset += 4;

    str = wmem_strdup_printf(pinfo->pool, "%s, gNodeB ID 0x%x",
        mcc_mnc_str,
        gnodeb_id);

    return str;
}

static char*
dissect_gtpv2_macro_ng_enodeb_id(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int* offset)
{
    char       *str = NULL;
    char       *mcc_mnc_str;
    uint32_t    ng_enodeb_id;

    mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, *offset, E212_NONE, true);
    *offset += 3;

    proto_tree_add_item_ret_uint(tree, hf_gtpv2_macro_ng_enodeb_id, tvb, *offset, 3, ENC_BIG_ENDIAN, &ng_enodeb_id);
    *offset += 3;

    str = wmem_strdup_printf(pinfo->pool, "%s, Macro ng-eNodeB ID 0x%x",
        mcc_mnc_str,
        ng_enodeb_id);

    return str;
}

static void
dissect_gtpv2_target_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    tvbuff_t *new_tvb;
    int       offset = 0;
    uint8_t   target_type, oct;

    proto_tree_add_item(tree, hf_gtpv2_target_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    target_type = tvb_get_uint8(tvb, offset);
    offset += 1;
    switch (target_type) {
    case 0:
        /* 8.51.2 RNC ID*/
        new_tvb = tvb_new_subset_remaining(tvb, offset);
        dissect_e212_mcc_mnc(new_tvb, pinfo, tree, 0, E212_NONE, true);
        offset += 3;
        /* LAC */
        proto_tree_add_item(tree, hf_gtpv2_lac,    tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* RAC (see NOTE 3) */
        proto_tree_add_item(tree, hf_gtpv2_rac, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* RNC ID
         * In this case the Target ID field shall be encoded as the Target
         * RNC-ID part of the "Target ID" parameter in 3GPP TS 25.413 [33]. Therefore, the "Choice Target ID" that indicates
         * "Target RNC-ID" (numerical value of 0x20) shall not be included (value in octet 5 specifies the target type).
         */
        proto_tree_add_item(tree, hf_gtpv2_rnc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        /* If the optional Extended RNC-ID is not included, then the length variable 'n' = 8 and the overall length of the IE is 11
         * octets. Otherwise, 'n' = 10 and the overall length of the IE is 13 octets
         */
        if(length == 11){
            proto_tree_add_item(tree, hf_gtpv2_ext_rnc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
        return;
    case 1:
        /* Macro eNodeB ID*/
        dissect_gtpv2_macro_enodeb_id(tvb, pinfo, tree, &offset);

        /* Tracking Area Code (TAC) */
        proto_tree_add_item(tree, hf_gtpv2_tai_tac, tvb, offset, 2, ENC_BIG_ENDIAN);

        return;

    case 2:
        /* Cell Identifier */
        /* Target ID field shall be same as the Octets 3 to 10 of the Cell Identifier IEI
         * in 3GPP TS 48.018 [34].
         */
        new_tvb = tvb_new_subset_remaining(tvb, offset);
        de_bssgp_cell_id(new_tvb, tree, pinfo, 0, 0/* not used */, NULL, 0);
        return;
    case 3:
        /* Home eNodeB ID */
        dissect_gtpv2_home_enodeb_id(tvb, pinfo, tree, &offset);

        /* Octet 13 to 14 Tracking Area Code (TAC) */
        proto_tree_add_item(tree, hf_gtpv2_tac, tvb, offset, 2 , ENC_BIG_ENDIAN);
        return;

    case 4:
        /* 8.51.5 Extended Macro eNodeB ID */
        dissect_gtpv2_ext_macro_enodeb_id(tvb, pinfo, tree, &offset, hf_gtpv2_ext_macro_enodeb_id);

        /* Octet 12 to 13 Tracking Area Code (TAC) */
        proto_tree_add_item(tree, hf_gtpv2_tac, tvb, offset, 2, ENC_BIG_ENDIAN);
        return;

    case 5:
        /* gNodeB ID */
        dissect_gtpv2_gnodeb_id(tvb, pinfo, tree, &offset);

        /* Octet 14 to 16 5GS Tracking Area Code (TAC) */
        proto_tree_add_item(tree, hf_gtpv2_5gs_tac, tvb, offset, 3, ENC_BIG_ENDIAN);
        return;

    case 6:
        /* Macro ng-eNodeB ID */
        dissect_gtpv2_macro_ng_enodeb_id(tvb, pinfo, tree, &offset);
        /* Octet 14 to 16 5GS Tracking Area Code (TAC) */
        proto_tree_add_item(tree, hf_gtpv2_5gs_tac, tvb, offset, 3, ENC_BIG_ENDIAN);
        return;

    case 7:
        /* Extended ng-eNodeB ID */
        dissect_gtpv2_ext_macro_enodeb_id(tvb, pinfo, tree, &offset, hf_gtpv2_ext_macro_ng_enodeb_id);
        /* Octet 12 to 14 5GS Tracking Area Code (TAC) */
        proto_tree_add_item(tree, hf_gtpv2_5gs_tac, tvb, offset, 3, ENC_BIG_ENDIAN);
        return;

    case 8:
        /* en-gNB ID */
        dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, offset, E212_NONE, true);
        offset += 3;
        /* Octet 9 5TAC ETAC en-gNB ID Length */
        oct = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tree, hf_gtpv2_5tac, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gtpv2_etac, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gtpv2_en_gnb_id_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* Octet 10 to 13 en-gNB ID */
        proto_tree_add_item(tree, hf_gtpv2_en_gnb_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if ((oct & 0x40) == 0x40) {
            /* ETAC*/
            /* p to (p+1 */
            proto_tree_add_item(tree, hf_gtpv2_tac, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

        }
        if ((oct & 0x80) == 0x80) {
            /* 5 TAC*/
            /* q to(q + 2) */
            proto_tree_add_item(tree, hf_gtpv2_5gs_tac, tvb, offset, 3, ENC_BIG_ENDIAN);
        }
        return;

    default:
        break;
    }
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, length-offset);

}

/*
 * 8.52 Void
 */
/*
 * 8.53 Packet Flow ID
 */
static void
dissect_gtpv2_pkt_flow_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    /* Octet 5 Spare EBI */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Packet Flow ID */
    proto_tree_add_item(tree, hf_gtpv2_packet_flow_id, tvb, offset, length - 1, ENC_NA);

}
/*
 * 8.54 RAB Context
 */
static void
dissect_gtpv2_rab_context(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int     offset = 0;

    /* 5 Spare NSAPI */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* 6 to 7 DL GTP-U Sequence Number */
    proto_tree_add_item(tree, hf_gtpv2_dl_gtp_u_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* 8 to 9 UL GTP-U Sequence Number */
    proto_tree_add_item(tree, hf_gtpv2_ul_gtp_u_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* 10 to 11 DL PDCP Sequence Number */
    proto_tree_add_item(tree, hf_gtpv2_dl_pdcp_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* 12 to 13 UL PDCP Sequence Number */
    proto_tree_add_item(tree, hf_gtpv2_ul_pdcp_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);

}

/*
 * 8.55 Source RNC PDCP context info
 */
static void
dissect_gtpv2_s_rnc_pdcp_ctx_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_rrc_container, tvb, 0, length, ENC_NA);
}

/*
 * 8.56 Port Number
 */
static void
dissect_port_nr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_port_number, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%u", tvb_get_ntohs(tvb, 0));
}
/*
 * 8.57 APN Restriction
 */

/* Table 8.57-1: Valid Combinations of APN Restriction */
static const value_string gtpv2_apn_restriction_vals[] = {
    {0, "No Existing Contexts or Restriction"},
    {1, "Public-1"},
    {2, "Public-2"},
    {3, "Private-1"},
    {4, "Private-2"},
    {0, NULL}
};
static value_string_ext gtpv2_apn_restriction_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_apn_restriction_vals);

static void
dissect_gtpv2_apn_rest(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    uint8_t type_value;
    int    offset = 0;

    /* APN restriction value octet 5 */
    type_value = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_apn_rest, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Add APN restriction to ie_tree */
    proto_item_append_text(item, "%s (%u)", val_to_str_ext_const(type_value, &gtpv2_apn_restriction_vals_ext, "Unknown"), type_value);
    offset += 1;

    if (length > offset)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-offset, ENC_NA);
}

/*
 * 8.58 Selection Mode
 */
static const value_string gtpv2_selec_mode_vals[] = {
    {0, "MS or network provided APN, subscribed verified"},
    {1, "MS provided APN, subscription not verified"},
    {2, "Network provided APN, subscription not verified"},
    {3, "Network provided APN, subscription not verified (Basically for Future use"},
    {0, NULL}
};

void
dissect_gtpv2_selec_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int    offset = 0;
    uint8_t ss_mode;

    ss_mode = tvb_get_uint8(tvb, offset) & 0x03;
    proto_tree_add_item(tree, hf_gtpv2_selec_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s", val_to_str_const(ss_mode, gtpv2_selec_mode_vals, "Unknown"));
}


/*
 * 8.59 Source Identification
 */
#if 0
static const value_string gtpv2_source_ident_types[] = {
    {0, "Cell ID"},
    {1, "RNC ID"},
    {2, "eNodeB ID(Reserved, used in earlier v of proto.)"},
    {0, NULL}
};
#endif
static void
dissect_gtpv2_source_ident(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    uint8_t     source_type;

    /* Octet 5 to 12 Target Cell ID */
    de_cell_id(tvb, tree, pinfo, offset, 8, NULL, 0);
    offset += 8;
    /* Octet 13 Source Type */
    source_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_source_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Octet 14 to (n+4) Source ID */
    switch (source_type) {
    case 0:
        /* The Source Type is Cell ID for PS handover from GERAN A/Gb mode. In this case the coding of the Source ID field
         * shall be same as the Octets 3 to 10 of the Cell Identifier IEI in 3GPP TS 48.018 [34].
         */
        de_cell_id(tvb, tree, pinfo, offset, 8, NULL, 0);
        break;
    case 1:
        /* The Source Type is RNC ID for PS handover from GERAN Iu mode or for inter-RAT handover from UTRAN. In this
         * case the Source ID field shall be encoded as the Source RNC-ID part of the "Source ID" parameter in 3GPP TS
         * 25.413 [33].
         */
        /* RNC-ID M INTEGER (0..4095) */
        break;
    case 2:
        break;
    default:
        proto_tree_add_expert(tree, pinfo, &ei_gtpv2_source_type_unknown, tvb, offset-1, 1);
        break;
    }

}

 /*
  * 8.60 Bearer Control Mode
  */
static const value_string gtpv2_bearer_control_mode_vals[] = {
    {0, "Selected Bearer Control Mode-'MS_only'"},
    {1, "Selected Bearer Control Mode-'Network_only'"},
    {2, "Selected Bearer Control Mode-'MS/NW'"},
    {0, NULL}
};

static const value_string gtpv2_bearer_control_mode_short_vals[] = {
    {0, "MS_only"},
    {1, "Network_only"},
    {2, "MS/NW"},
    {0, NULL}
};

static void
dissect_gtpv2_bearer_control_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    uint8_t bcm;

    proto_tree_add_item(tree, hf_gtpv2_bearer_control_mode, tvb, 0, 1, ENC_BIG_ENDIAN);
    /* Add Bearer Control Mode to tree */
    bcm = tvb_get_uint8(tvb, 0);
    proto_item_append_text(item, "%s", val_to_str_const(bcm, gtpv2_bearer_control_mode_short_vals, "Unknown"));

}
/*
 * 8.61 Change Reporting Action
 */
static const value_string gtpv2_cng_rep_act_vals[] = {
    {0, "Stop Reporting"},
    {1, "Start Reporting CGI/SAI"},
    {2, "Start Reporting RAI"},
    {3, "Start Reporting TAI"},
    {4, "Start Reporting ECGI"},
    {5, "Start Reporting CGI/SAI and RAI"},
    {6, "Start Reporting TAI and ECGI"},
    {0, NULL}
};

static void
dissect_gtpv2_cng_rep_act(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    uint8_t action;

    /* Add Action to tree */
    action = tvb_get_uint8(tvb, 0);
    proto_tree_add_item(tree, hf_gtpv2_cng_rep_act, tvb, 0, 1, ENC_BIG_ENDIAN);

    proto_item_append_text(item, "%s", val_to_str_const(action, gtpv2_cng_rep_act_vals, "Unknown"));
}
/*
 * 8.62 Fully qualified PDN Connection Set Identifier (FQ-CSID)
 */
#if 0
static const value_string gtpv2_fq_csid_type_vals[] = {
    {0, "Global unicast IPv4 address"},
    {1, "Global unicast IPv6 address"},
    {2, "4 octets long field"},
    {0, NULL}
};
#endif

void
dissect_gtpv2_fq_csid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    uint8_t     octet, node_id_type, csids;

    /* Octet 5 Node-ID Type Number of CSIDs= m */

    octet = tvb_get_uint8(tvb, offset);
    node_id_type = octet >> 4;
    csids = octet & 0x0f;
    proto_tree_add_item(tree, hf_gtpv2_fq_csid_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_fq_csid_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    switch (node_id_type) {
    case 0:
        /* Indicates that Node-ID is a global unicast IPv4 address and p = 9 */
        proto_tree_add_item(tree, hf_gtpv2_fq_csid_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 1:
        /* Indicates that Node-ID is a global unicast IPv6 address and p = 21 */
        proto_tree_add_item(tree, hf_gtpv2_fq_csid_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;
    case 2:
        /* Node-ID is a 4 octets long field with a 32 bit value stored in network order, and p= 9. The coding
         * of the field is specified below:
         * - Most significant 20 bits are the binary encoded value of (MCC * 1000 + MNC).
         * - Least significant 12 bits is a 12 bit integer assigned by an operator to an MME, SGW or PGW. Other values of
         *   Node-ID Type are reserved.
         */
        proto_tree_add_item(tree, hf_gtpv2_fq_csid_node_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gtpv2_fq_csid_mcc_mnc, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_fq_csid_type_bad, tvb, offset-1, 1,
                                     "Wrong Node-ID Type %u, should be 0-2(Or this is a newer spec)", node_id_type);
        return;
    }

    /* First PDN Connection Set Identifier (CSID)
     * Second PDN Connection Set Identifier (CSID)
     *  :
     * m-th PDN Connection Set Identifier (CSID)
     */
    while ( csids-- ) {
        proto_tree_add_item(tree, hf_gtpv2_fq_csid_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

}

/*
 * 8.63 Channel needed
 */
static void
dissect_gtpv2_channel_needed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    /* The Channel needed shall be coded as depicted in Figure 8.63-1. Channel needed is coded as the IEI part and the value
     * part of the Channel Needed IE defined in 3GPP TS 44.018[28]
     */
    de_rr_chnl_needed(tvb, tree, pinfo, 0, length, NULL, 0);
}

/*
 * 8.64 eMLPP Priority
 * The eMLPP-Priority shall be coded as depicted in Figure 8.64-1. The eMLPP Priority is coded as the value part of the
 * eMLPP-Priority IE defined in 3GPP TS 48.008 [29] (not including 3GPP TS 48.008 IEI and 3GPP TS 48.008 [29]
 * length indicator).
 */
static void
dissect_gtpv2_emlpp_pri(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    be_emlpp_prio(tvb, tree, pinfo, 0, length, NULL, 0);

}

/*
 * 8.65 Node Type
 */
static const value_string gtpv2_node_type_vals[] = {
    {0, "MME"},
    {1, "SGSN"},
    {0, NULL}
};

static void
dissect_gtpv2_node_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    uint8_t node_type;

    proto_tree_add_item(tree, hf_gtpv2_node_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    /* Append Node Type to tree */
    node_type = tvb_get_uint8(tvb, 0);
    proto_item_append_text(item, "%s", val_to_str_const(node_type, gtpv2_node_type_vals, "Unknown"));

}

 /*
  * 8.66 Fully Qualified Domain Name (FQDN)
  */
static int
decode_gtpv2_fqdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, int offset, uint16_t length)
{
    int           name_len;
    const uint8_t *fqdn   = NULL;

    /* The FQDN field encoding shall be identical to the encoding of
     * a FQDN within a DNS message of section 3.1 of IETF
     * RFC 1035 [31] but excluding the trailing zero byte.
     *
     * XXX: is compression possible?
     */
    if (offset < length) {
        name_len = tvb_get_uint8(tvb, offset);

        /* "NOTE 1: The FQDN field in the IE is not encoded as a dotted string"
         * but if the first byte is large (in the letter range or higher),
         * assume that it is so encoded incorrectly.
         */
        if (name_len < 0x40) {
            proto_tree_add_item_ret_string(tree, hf_gtpv2_fqdn, tvb, offset, length, ENC_APN_STR, pinfo->pool, &fqdn);
        } else {
            proto_tree_add_item_ret_string(tree, hf_gtpv2_fqdn, tvb, offset, length, ENC_ASCII, pinfo->pool, &fqdn);
        }
        proto_item_append_text(item, "%s", fqdn);
    }

    return length; //TODO return length of fqdn
}

static void
dissect_gtpv2_fqdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    decode_gtpv2_fqdn(tvb, pinfo, tree, item, offset, length);
}

/*
 * 8.67 Private Extension
 */
static void
dissect_gtpv2_private_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance, session_args_t * args _U_)
{
    int       offset = 0;
    tvbuff_t *next_tvb;
    uint16_t  ext_id;
    gtpv2_priv_ext_info_t  gtpv2_inf;

    gtpv2_inf.instance = instance;
    gtpv2_inf.item = item;

    /* oct 5 -7 Enterprise ID */
    ext_id = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_enterprise_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_append_text(item, "%s (%u)", enterprises_lookup(ext_id, "Unknown"), ext_id);

    next_tvb = tvb_new_subset_length(tvb, offset, length-2);
    if (dissector_try_uint_with_data(gtpv2_priv_ext_dissector_table, ext_id, next_tvb, pinfo, tree, false, &gtpv2_inf)){
        return;
    }

    proto_tree_add_item(tree, hf_gtpv2_proprietary_value, tvb, offset, length-2, ENC_NA);
}

/*
 * 8.68 Transaction Identifier (TI)
 */
static void
dissect_gtpv2_ti(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    /* 5 to (n+4)  Transaction Identifier */
    proto_tree_add_item(tree, hf_gtpv2_ti, tvb, 0, length, ENC_NA);

}

/*
 * 8.69 MBMS Session Duration
 */
void
dissect_gtpv2_mbms_session_duration(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int     offset     = 0;
    int     bit_offset = 0;
    uint8_t  days;
    uint32_t hours;
    uint32_t minutes;
    uint32_t seconds;
    uint32_t durations_seconds;
    proto_item *day_item, *sec_item;

    /* From 3GPP TS 29.061 17.7.7 MBMS-Session-Duration AVP */
    /* Bits: ssss ssss ssss ssss sddd dddd where s bits = seconds, d bits = days */
    durations_seconds = tvb_get_bits32(tvb, bit_offset, 17, ENC_BIG_ENDIAN);
    bit_offset += 17;

    days = tvb_get_bits8(tvb, bit_offset, 7);

    /* The lowest value of this AVP (i.e. all 0:s) is reserved to indicate an indefinite value to denote sessions that are expected to be always-on. */
    if ((durations_seconds == 0) && (days == 0)) {
        day_item = proto_tree_add_item(tree, hf_gtpv2_mbms_session_duration_days, tvb, offset, 3, ENC_BIG_ENDIAN);
        sec_item = proto_tree_add_item(tree, hf_gtpv2_mbms_session_duration_secs, tvb, offset, 3, ENC_BIG_ENDIAN);
        proto_item_append_text(item, "Indefinite (always-on)");
    } else {
        hours = durations_seconds / 3600;
        minutes = (durations_seconds % 3600) / 60;
        seconds = (durations_seconds % 3600) % 60;

        day_item = proto_tree_add_item(tree, hf_gtpv2_mbms_session_duration_days, tvb, offset, 3, ENC_BIG_ENDIAN);
        sec_item = proto_tree_add_item(tree, hf_gtpv2_mbms_session_duration_secs, tvb, offset, 3, ENC_BIG_ENDIAN);
        proto_item_append_text(item, "%d days %02d:%02d:%02d (DD days HH:MM:SS)", days, hours, minutes, seconds);
    }

    /* Maximum allowed value for days: 18.
     * Maximum allowed value for seconds: 86,400 */
    if (days > 18) {
        expert_add_info(pinfo, day_item, &ei_gtpv2_mbms_session_duration_days);
    }
    if (durations_seconds > 86400) {
        expert_add_info(pinfo, sec_item, &ei_gtpv2_mbms_session_duration_secs);
    }

    offset += 3;
    if (length > 3)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-3, ENC_NA);
}

/*
 * 8.70 MBMS Service Area
 */
void
dissect_gtpv2_mbms_service_area(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    proto_item *sai_item;
    uint8_t     binary_nr;
    uint16_t    real_nr;
    uint16_t    sai;

    binary_nr = tvb_get_uint8(tvb, offset);
    real_nr = (uint16_t)binary_nr + 1;

    /* 3GPP TS 29.061 17.7.6 MBMS-Service-Area AVP */
    proto_tree_add_uint(tree, hf_gtpv2_mbms_service_area_nr, tvb, offset, 1, real_nr);
    offset += 1;

    /* A consecutive list of MBMS Service Area Identities follow, each with a length of two octets. */
    while (offset < length) {
        /* 3GPP TS 23.003 15.3 Structure of MBMS SAI */
        sai = tvb_get_ntohs(tvb, offset);
        sai_item = proto_tree_add_item(tree, hf_gtpv2_mbms_service_area_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        /* The value 0 denotes the whole of PLMN as the MBMS Service Area */
        if (sai == 0) {
            proto_item_append_text(sai_item, " Entire PLMN");
        }
        proto_item_append_text(item, " %u", sai);
        offset += 2;
    }
}

/*
 * 8.71 MBMS Session Identifier
 */
static void
dissect_gtpv2_mbms_session_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, _U_ uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    /* One octet OctetString. */
    proto_tree_add_item(tree, hf_gtpv2_mbms_session_id, tvb, offset, 1, ENC_NA);

    offset += 1;
    if (length > 1)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-1, ENC_NA);
}

/*
 * 8.72 MBMS Flow Identifier
 */
static void
dissect_gtpv2_mbms_flow_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    /* Two octets OctetString. */
    proto_tree_add_item(tree, hf_gtpv2_mbms_flow_id, tvb, offset, 2, ENC_NA);
    proto_item_append_text(item, " %s", tvb_bytes_to_str(pinfo->pool, tvb, offset, 2));

    offset += 2;
    if (length > 2)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-2, ENC_NA);
}

/*
 * 8.73 MBMS IP Multicast Distribution
 */
static const value_string gtpv2_mbms_hc_indicator_vals[] = {
    {0, "Uncompressed header"},
    {1, "Compressed header"},
    {0, NULL}
};

static void
dissect_gtpv2_mbms_ip_mc_dist(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_cteid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_gtpv2_ip_addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_ip_addr_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* IP Multicast Distribution Address */
    if ((tvb_get_uint8(tvb, offset) & 0x3f) == 4) {
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_mbms_ip_mc_dist_addrv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, " IPv4 Dist %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        offset += 4;
    } else if ((tvb_get_uint8(tvb, offset) & 0x3f) == 16) {
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_mbms_ip_mc_dist_addrv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, " IPv6 Dist %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        offset += 16;
    }

    proto_tree_add_item(tree, hf_gtpv2_ip_addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_ip_addr_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* IP Multicast Source Address */
    if ((tvb_get_uint8(tvb, offset) & 0x3f) == 4) {
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_mbms_ip_mc_src_addrv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, " IPv4 Src %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
        offset += 4;
    } else if ((tvb_get_uint8(tvb, offset) & 0x3f) == 16) {
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_mbms_ip_mc_src_addrv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, " IPv6 Src %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
        offset += 16;
    }

    proto_tree_add_item(tree, hf_gtpv2_mbms_hc_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    if (length > offset)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-offset, ENC_NA);

}

/*
 * 8.74 MBMS Distribution Acknowledge
 */
static const value_string gtpv2_mbms_dist_indication_vals[] = {
    {0, "No RNCs have accepted IP multicast distribution"},
    {1, "All RNCs have accepted IP multicast distribution"},
    {2, "Some RNCs have accepted IP multicast distribution"},
    {3, "Spare. For future use."},
    {0, NULL}
};

static void
dissect_gtpv2_mbms_dist_ack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_mbms_dist_indication, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    if (length > 1)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-1, ENC_NA);
}

/*
 * 8.75 User CSG Information (UCI)
 */
static const value_string gtpv2_uci_csg_membership_status[] = {
    {0, "Non CSG membership"},
    {1, "CSG membership"},
    {0, NULL }
};

static const value_string gtpv2_uci_access_mode[] = {
    {0, "Closed Mode"},
    {1, "Hybrid Mode"},
    {2, "Reserved" },
    {3, "Reserved"},
    {0, NULL }
};

static const value_string gtpv2_uci_leave_csg[] = {
    {0, "Access CSG cell/Hybrid cell"},
    {1, "Leaves CSG cell/Hybrid cell"},
    {0, NULL }
};

static void
dissect_gtpv2_uci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    /* Value of MCC & MNC */
    dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, E212_NONE, true);
    offset += 3;
    /* Value of CSG ID */
    proto_tree_add_item(tree, hf_gtpv2_uci_csg_id_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_uci_csg_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Value of access mode */
    proto_tree_add_item(tree, hf_gtpv2_uci_access_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Value of LCSG */
    proto_tree_add_item(tree, hf_gtpv2_uci_lcsg, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Value of CSG membership */
    proto_tree_add_item(tree, hf_gtpv2_uci_csg_membership, tvb, offset, 1, ENC_BIG_ENDIAN);

}

/* 8.76 CSG Information Reporting Action */
static void
dissect_gtpv2_csg_info_rep_action(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    static int * const flags[] = {
        &hf_gtpv2_csg_info_rep_action_b2,
        &hf_gtpv2_csg_info_rep_action_b1,
        &hf_gtpv2_csg_info_rep_action_b0,
        NULL
    };
    if (length == 0) {
        expert_add_info(pinfo, item, &ei_gtpv2_ie_len_invalid);
        return;
    }
    /* Spare    UCIUHC    UCISHC    UCICSG */

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

}

/* 8.77 RFSP Index */
static void
dissect_gtpv2_rfsp_index(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    if(instance == 0){
        proto_tree_add_item(tree, hf_gtpv2_subscriber_rfsp, tvb, offset, 2, ENC_BIG_ENDIAN);
    }else if(instance == 1){
        proto_tree_add_item(tree, hf_gtpv2_rfsp_inuse, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
}

/* 8.78 CSG ID */
static void
dissect_gtpv2_csg_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, 0, 5, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_csg_id, tvb, 0, 4, ENC_BIG_ENDIAN);
    if (length > 1) {
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, 1, length-1, ENC_NA);
    }
}

/* 8.79 CSG Membership Indication (CMI) */
static void
dissect_gtpv2_cmi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, 0, 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_cmi, tvb, 0, 1, ENC_BIG_ENDIAN);
    if (length > 1) {
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, 1, length-1, ENC_NA);
    }
}

/* 8.80 Service indicator */
static const value_string gtpv2_service_indicator_vals[] = {
    { 1, "CS call indicator" },
    { 2, "SMS indicator" },
    { 0, NULL }
};

static void
dissect_gtpv2_service_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_service_indicator, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* 8.81 Detach Type */
static const value_string gtpv2_detach_type_vals[] = {
    { 1, "PS Detach" },
    { 2, "Combined PS/CS Detach" },
    { 0, NULL }
};

static void
dissect_gtpv2_detach_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_detach_type, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* 8.82 Local Distinguished Name (LDN) */
static void
dissect_gtpv2_ldn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_ldn, tvb, 0, length, ENC_ASCII);
}

/* 8.83 Node Features */
static void
dissect_gtpv2_node_features(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    static int * const features[] = {
        &hf_gtpv2_node_features_psset,
        &hf_gtpv2_node_features_mtedt,
        &hf_gtpv2_node_features_eth,
        &hf_gtpv2_node_features_s1un,
        &hf_gtpv2_node_features_ciot,
        &hf_gtpv2_node_features_ntsr,
        &hf_gtpv2_node_features_mabr,
        &hf_gtpv2_node_features_prn,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, features, ENC_BIG_ENDIAN);
    offset++;
    if (length > offset)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-1, ENC_NA);
}

/* 8.84
 * MBMS Time to Data Transfer
 */
void
dissect_gtpv2_mbms_time_to_data_xfer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int     offset = 0;
    uint8_t binary_secs;
    uint16_t real_secs;

    binary_secs = tvb_get_uint8(tvb, offset);
    real_secs = (uint16_t)binary_secs + 1;

    proto_tree_add_string_format_value(tree, hf_gtpv2_time_to_data_xfer, tvb, offset, 1, "", "%d second(s)", real_secs);
    proto_item_append_text(item, " %u second(s)", real_secs);
    offset += 1;
    if (length > 1)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-1, ENC_NA);
}

static const value_string gtpv2_throttling_delay_unit_vals[] = {
    { 0, "value is incremented in multiples of 2 seconds" },
    { 1, "value is incremented in multiples of 1 minute" },
    { 2, "value is incremented in multiples of 10 minutes" },
    { 3, "value is incremented in multiples of 1 hour" },
    { 4, "value is incremented in multiples of 10 hour" },
    { 7, "value indicates that the timer is deactivated" },
    { 0, NULL }
};

/* 8.85 Throttling */
static void
dissect_gtpv2_throttling(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    uint8_t oct;

    proto_tree_add_item(tree, hf_gtpv2_throttling_delay_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_throttling_delay_value, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    oct = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_throttling_factor, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (oct > 0x64)
        proto_item_append_text(item, "Throttling factor: value beyond (0,100) is considered as 0");
    offset++;

    if (length > 2)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length - 2, ENC_NA);


}

/* 8.86 Allocation/Retention Priority (ARP) */
void
dissect_gtpv2_arp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_arp_pci, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_arp_pl, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_arp_pvi, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    if (length > 1)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-1, ENC_NA);
}

/* 8.87 EPC Timer */
static const value_string gtpv2_timer_unit_vals[] = {
    {0, "value is incremented in multiples of 2 seconds"},
    {1, "value is incremented in multiples of 1 minute"},
    {2, "value is incremented in multiples of 10 minutes"},
    {3, "value is incremented in multiples of 1 hour"},
    {4, "value is incremented in multiples of 10 hour"},
    {5, "Other values shall be interpreted as multiples of 1 minute(version 10.7.0)"},
    {6, "Other values shall be interpreted as multiples of 1 minute(version 10.7.0)"},
    {7, "value indicates that the timer is infinite"},
    {0, NULL}
};

void
dissect_gtpv2_epc_timer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length _U_, uint8_t message_type, uint8_t instance _U_, session_args_t * args _U_)
{
    switch (message_type) {
    case GTPV2_DL_DATA_NOTIF_ACK:
        proto_item_append_text(item, "DL Buffering Duration");
        break;
    }
    /* XXX Todo: use code from packet-gsm_a_gm.c ?  10.5.7.4a GPRS TIMER 3*/
    proto_tree_add_item(tree, hf_gtpv2_timer_unit, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_timer_value, tvb, 0, 1, ENC_BIG_ENDIAN);

}

/* 8.88 Signalling Priority Indication */
static void
dissect_gtpv2_sig_prio_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_lapi, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* 8.89 Temporary Mobile Group Identity (TMGI) */
static void
dissect_gtpv2_tmgi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int     offset = 0;
    uint64_t tmgi;

    tmgi = tvb_get_ntoh48(tvb, offset);

    proto_item_append_text(item, "%012" PRIx64, tmgi);

    proto_tree_add_item(tree, hf_gtpv2_mbms_service_id, tvb, offset, 3, ENC_NA);
    offset += 3;

    dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_NONE, true);
    offset += 3;

    if (length > offset)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-offset, ENC_NA);
}

/*
 * 8.90 Additional MM context for SRVCC
 * 3GPP TS 29.274 Figure 8.90-1
 */
static void
dissect_gtpv2_add_mm_cont_for_srvcc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    proto_item *ms_cm_item;
    proto_tree *ms_cm_tree;
    uint8_t     elm_len;

    /* Length of Mobile Station Classmark 2 */
    elm_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* For each of the Mobile Station Classmark 2, Mobile Station Classmark 3 and Supported Codec List parameters,
     * if they are not available, then the associated length field shall be set to zero, and the particular
     * parameter field shall not be present.
     */
    if(elm_len > 0){
        ms_cm_item = proto_tree_add_item(tree, hf_gtpv2_mobile_station_classmark2, tvb, offset, elm_len, ENC_NA);
        ms_cm_tree = proto_item_add_subtree(ms_cm_item, ett_gtpv2_ms_mark);
        /* Mobile Station Classmark 2 */
        de_ms_cm_2(tvb, ms_cm_tree, pinfo, offset, elm_len, NULL, 0);
        offset += elm_len;
    }

    /* Length of Mobile Station Classmark 3 */
    elm_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (elm_len > 0) {
        ms_cm_item = proto_tree_add_item(tree, hf_gtpv2_mobile_station_classmark3, tvb, offset, elm_len, ENC_NA);
        ms_cm_tree = proto_item_add_subtree(ms_cm_item, ett_gtpv2_ms_mark);
        /* Mobile Station Classmark 3 */
        de_ms_cm_3(tvb, ms_cm_tree, pinfo, offset, elm_len, NULL, 0);
        offset += elm_len;
    }

    /* Length of Supported Codec List */
    elm_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_supp_codec_list, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (elm_len > 0) {
        ms_cm_item = proto_tree_add_item(tree, hf_gtpv2_supported_codec_list, tvb, offset, elm_len, ENC_NA);
        ms_cm_tree = proto_item_add_subtree(ms_cm_item, ett_gtpv2_supp_codec_list);
        /* Supported Codec List */
        de_sup_codec_list(tvb, ms_cm_tree, pinfo, offset, elm_len, NULL, 0);
        offset += elm_len;
    }

    if (length > offset)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-offset, ENC_NA);
}

/* 8.91 Additional flags for SRVCC */
static void
dissect_gtpv2_add_flags_for_srvcc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_add_flags_for_srvcc_ics, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_vsrvcc_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (length > 1)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-1, ENC_NA);
}

/* 8.92 Max MBR/APN-AMBR (MMBR) */
static void
dissect_gtpv2_mmbr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int     offset = 0;
    uint32_t max_ul;
    uint32_t max_dl;

    max_ul = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_gtpv2_mmbr_ul, tvb, offset, 4, max_ul, "%u %s",
                                (max_ul) > 1000 ? max_ul/1000 : max_ul,
                                (max_ul) > 1000 ? "Mbps" : "kbps");

    offset += 4;

    max_dl = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_gtpv2_mmbr_dl, tvb, offset, 4, max_dl, "%u %s",
                                (max_dl) > 1000 ? max_dl/1000 : max_dl,
                                (max_dl) > 1000 ? "Mbps" : "kbps");
}

/* 8.93 MDT Configuration */
static void
dissect_gtpv2_mdt_config(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}

/* 8.94 Additional Protocol Configuration Options (APCO) */
static void
dissect_gtpv2_apco(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    switch (message_type) {
    case GTPV2_CREATE_SESSION_REQUEST:
    case GTPV2_DELETE_SESSION_REQUEST:
    case GTPV2_BEARER_RESOURCE_COMMAND:
    case GTPV2_CREATE_BEARER_RESPONSE:
    case GTPV2_UPDATE_BEARER_RESPONSE:
    case GTPV2_DELETE_BEARER_RESPONSE:
        /* PCO options as MS to network direction */
        pinfo->link_dir = P2P_DIR_UL;
        break;
    case GTPV2_CREATE_SESSION_RESPONSE:
    case GTPV2_MODIFY_BEARER_RESPONSE:
    case GTPV2_DELETE_SESSION_RESPONSE:
    case GTPV2_CREATE_BEARER_REQUEST:
    case GTPV2_UPDATE_BEARER_REQUEST:
    case GTPV2_DELETE_BEARER_REQUEST:
        /* PCO options as Network to MS direction: */
        pinfo->link_dir = P2P_DIR_DL;
        break;
    default:
        break;
    }
    de_sm_pco(tvb, tree, pinfo, 0, length, NULL, 0);
}

/* 8.95 Absolute Time of MBMS Data Transfer */
static void
dissect_gtpv2_abs_mbms_data_tf_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int          offset = 0;
    char        *time_str;

    proto_tree_add_item_ret_time_string(tree, hf_gtpv2_abs_time_mbms_data, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);

    offset += 8;
    if (length > offset)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-offset, ENC_NA);
}

/* 8.96 H(e)NB Information Reporting */
static const true_false_string gtpv2_henb_info_report_fti_vals = {
    "Start reporting H(e)NB local IP address and UDP port number information change",
    "Stop reporting H(e)NB local IP address and UDP port number information change",
};

static void
dissect_gtpv2_henb_info_report(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_henb_info_report_fti, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (length > 1)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-1, ENC_NA);
}

/* 8.97 IPv4 Configuration Parameters (IP4CP) */
static void
dissect_gtpv2_ip4cp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_ip4cp_subnet_prefix_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_gtpv2_ip4cp_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (length > offset)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-offset, ENC_NA);
}

/* 8.98 Change to Report Flags */
static void
dissect_gtpv2_change_report_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_change_report_flags_sncr, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_change_report_flags_tzcr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (length > 1)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-1, ENC_NA);
}

/* 8.99 Action Indication */
static const value_string gtpv2_action_indication_vals[] = {
    { 0, "No Action"},
    { 1, "Deactivation Indication"},
    { 2, "Paging Indication"},
    { 3, "Spare"},
    { 4, "Spare"},
    { 5, "Spare"},
    { 6, "Spare"},
    { 7, "Spare"},
    { 0, NULL}
};
static value_string_ext gtpv2_action_indication_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_action_indication_vals);

static void
dissect_gtpv2_action_indication(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_action_indication_val, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (length > 1)
        proto_tree_add_item(tree, hf_gtpv2_spare_bytes, tvb, offset, length-1, ENC_NA);
}

/*
 * 8.100        TWAN Identifier
 */
static const value_string gtpv2_twan_relay_id_type_vals[] = {
    { 0, "IPv4 or IPv6 Address" },
    { 1, "FQDN" },
    { 0, NULL }
};

void
dissect_gtpv2_twan_identifier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    uint8_t flags=0;
    uint32_t ssid_len, civa_len, op_name_len, relay_id_type, relay_id_len, circuit_id_id_len;
    static int* const twan_id_flags[] = {
        &hf_gtpv2_twan_laii,
        &hf_gtpv2_twan_opnai,
        &hf_gtpv2_twan_plmni,
        &hf_gtpv2_twan_civai,
        &hf_gtpv2_twan_bssidi,
        NULL
    };

    /* Octet 5 Spare    LAII OPNAI PLMNI CIVAI BSSIDI */
    flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_gtpv2_twan_flags, ett_gtpv2_twan_flags, twan_id_flags, ENC_BIG_ENDIAN);
    offset++;
    /* Octet 6 SSID Length */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_twan_ssid_len, tvb, offset, 1, ENC_BIG_ENDIAN, &ssid_len);
    offset += 1;
    /* 7 to k SSID */
    proto_tree_add_item(tree, hf_gtpv2_twan_ssid, tvb, offset, ssid_len, ENC_NA);
    offset += ssid_len;
    /* (k+1) to (k+6) BSSID The BSSIDI flag in octet 5 indicates whether the BSSID in octets 'k+1' to 'k+6' shall be present.*/
    if (flags & 0x01) {
        proto_tree_add_item(tree, hf_gtpv2_twan_bssid, tvb, offset, 6, ENC_NA);
        offset += 6;
    }
    /* q Civic Address Length The CIVAI flag in octet 5 indicates whether the Civic Address Length
     * and Civic Address Information in octets 'q' and 'q+1' to 'q+r' shall be present.
     */
    if (flags & 0x02) {
        proto_tree_add_item_ret_uint(tree, hf_gtpv2_twan_civa_len, tvb, offset, 1, ENC_BIG_ENDIAN, &civa_len);
        offset += 1;
        /* (q+1) to (q+r) Civic Address Information
         * ...it shall be encoded as defined in subclause 3.1 of IETF RFC 4776 [59] excluding the first 3 octets.
         * RFC 4776:
         * 3.1.  Overall Format for DHCPv4

         * 0                   1                   2                   3
         * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * | GEOCONF_CIVIC |       N       |      what     |    country    |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |    code       |        civic address elements                ...
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        proto_tree_add_item(tree, hf_gtpv2_twan_civa, tvb, offset, civa_len, ENC_NA);
        offset += civa_len;
    }
    /* s to (s+3) TWAN PLMN-ID The PLMNI flag in octet 5 indicates whether the TWAN PLMN-ID
     * in octets 's' to 's+3' shall be present
     */
    if (flags & 0x04) {
        proto_tree_add_item(tree, hf_gtpv2_twan_plmnid, tvb, offset, 3, ENC_NA);
        offset += 3;
        /* (q+1) to (q+r) Civic Address Information
        * ...it shall be encoded as defined in subclause 3.1 of IETF RFC 4776 [59] excluding the first 3 octets.
        */
    }
    /* t TWAN Operator Name Length, The OPNAI flag in octet 5 indicates whether the TWAN Operator Name Length and
     * TWAN Operator Name in octets 't' and 't+1' to 't+u' shall be present.
     */
    if (flags & 0x08) {
        proto_tree_add_item_ret_uint(tree, hf_gtpv2_twan_op_name_len, tvb, offset, 1, ENC_BIG_ENDIAN, &op_name_len);
        offset += 1;
        /* (t+1) to (t+u) TWAN Operator Name. The TWAN Operator Name shall be encoded as specified in subclause 19. 8 of 3GPP TS 23.003  */
        proto_tree_add_item(tree, hf_gtpv2_twan_op_name, tvb, offset, op_name_len, ENC_NA);
        offset += op_name_len;
    }
    /* The LAII flag in octet 5 indicates whether the Logical Access ID information is present in the TWAN Identifier  */
    if (flags & 0x10) {
        /* v Relay Identity Type */
        proto_tree_add_item_ret_uint(tree, hf_gtpv2_twan_relay_id_type, tvb, offset, 1, ENC_BIG_ENDIAN, &relay_id_type);
        offset += 1;
        /* (v+1) Relay Identity Length*/
        proto_tree_add_item_ret_uint(tree, hf_gtpv2_twan_relay_id_len, tvb, offset, 1, ENC_BIG_ENDIAN, &relay_id_len);
        offset += 1;
        /* (v+2) to (v+w) Relay Identity */
        switch (relay_id_type) {
        case 0:
            /* IPv4 or IPv6 Address */
            if (relay_id_len == 4) {
                /* IPv4 */
                proto_tree_add_item(tree, hf_gtpv2_twan_relay_id_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            } else {
                proto_tree_add_item(tree, hf_gtpv2_twan_relay_id_ipv6, tvb, offset, 16, ENC_NA);
                offset += 16;
            }
            break;
        case 1:
            /* fall trough */
            proto_tree_add_item(tree, hf_gtpv2_twan_relay_id, tvb, offset, relay_id_len, ENC_ASCII);
            offset += relay_id_len;
        default:
            break;
        }
        /* X Circuit-ID Length */
        proto_tree_add_item_ret_uint(tree, hf_gtpv2_twan_circuit_id_len, tvb, offset, 1, ENC_BIG_ENDIAN, &circuit_id_id_len);
        offset += 1;
        /* (x+1) to (x+y) Circuit-ID */
        proto_tree_add_item(tree, hf_gtpv2_twan_circuit_id, tvb, offset, circuit_id_id_len, ENC_NA);
        offset += circuit_id_id_len;
    }

    if (offset < (int)length) {
        proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");
    }

}
/*
 * 8.101        ULI Timestamp
 */
static void
dissect_gtpv2_uli_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    char *time_str;

    /* Octets 5 to 8 are encoded in the same format as the first four octets of the 64-bit timestamp
     * format as defined in section 6 of IETF RFC 5905
     */

    proto_tree_add_item_ret_time_string(tree, hf_gtpv2_uli_timestamp, tvb, 0, 4, ENC_TIME_NTP|ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);

}
/*
 * 8.102        MBMS Flags
 */
static void
dissect_gtpv2_mbms_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}
/*
 * 8.103        RAN/NAS Cause
 */
static const value_string ran_nas_prot_type_vals[] = {
    { 1, "S1AP Cause" },
    { 2, "EMM Cause" },
    { 3, "ESM Cause" },
    { 4, "Diameter Cause" },
    { 5, "IKEv2 Cause" },
    { 0, NULL },
};

static void
dissect_gtpv2_ran_nas_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    uint8_t octet = tvb_get_uint8(tvb, offset);
    uint8_t proto_type = (octet >> 4);
    int cause_type = 0;

    proto_tree_add_item(tree, hf_gtpv2_ran_nas_protocol_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    if (proto_type == 1) {
        proto_tree_add_item(tree, hf_gtpv2_ran_nas_cause_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        cause_type = octet & 0x0F;
    }
    offset += 1;

    switch (proto_type) {
        case 1:
                dissect_gtpv2_s1ap_cause(tvb, pinfo, tree, offset, cause_type);
                break;
        case 2:
                proto_tree_add_item(tree, hf_gtpv2_emm_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
        case 3:
                proto_tree_add_item(tree, hf_gtpv2_esm_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
        case 4:
                proto_tree_add_item(tree, hf_gtpv2_diameter_cause, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
        case 5:
                proto_tree_add_item(tree, hf_gtpv2_ikev2_cause, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
        default:
                proto_tree_add_item(tree, hf_gtpv2_ran_nas_cause_value, tvb, offset, length - offset, ENC_BIG_ENDIAN);
                break;
    }
}
/*
 * 8.104        CN Operator Selection Entity
 */
static void
dissect_gtpv2_cn_operator_selection_entity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}
/*
 * 8.105        Trusted WLAN Mode Indication
 */
static void
dissect_gtpv2_trust_wlan_mode_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}
/*
 * 8.106        Node Number
 */
static void
dissect_gtpv2_node_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    uint32_t len;
    tvbuff_t* new_tvb;

    /* Octet 5 Length of Node Number*/
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_node_number_len, tvb, offset, 1, ENC_BIG_ENDIAN, &len);
    offset += 1;

    /* The Node number shall carry an ISDN number...
     * shall be coded according to the contents of ISDN-AddressString data type
     * defined in 3GPP TS 29.002
     */
    new_tvb = tvb_new_subset_length(tvb, offset, len);
    dissect_gsm_map_msisdn(new_tvb, pinfo, tree);
}
/*
 * 8.107        Node Identifier
 */
static void
dissect_gtpv2_node_identifier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int   offset = 0;
    uint32_t name_len;

    /*
    RFC 6733
    DiameterIdentity

    The DiameterIdentity format is derived from the OctetString Basic
    AVP Format....In this document, note that DiameterIdentity is
      in ASCII form.

    TS 29.274

    If the Node Identifier contains a SGSN Identifier then:
    - the Node Name shall be coded as the Diameter identity of the SGSN as defined in subclause 6.4.13 of 3GPP TS 29.173 [57] and;
    - the Node Realm shall be coded as the Diameter realm identity of the SGSN and as defined in subclause 6.4.14 of 3GPP TS 29.173 [57] and;
    - Both the Node Name and the Node Realm shall be present and neither the Length of Node Name nor the Length of Node Realm shall be zero.
        6.4.13  SGSN-Name
        The SGSN-Name AVP is of type DiameterIdentity...see IETF RFC 6733
        6.4.14    SGSN-Realm
        The SGSN-Realm AVP is of type DiameterIdentity...see IETF RFC 6733

    If the Node Identifier contains a MME Identifier then:
    - the Node Name shall be coded as the Diameter identity of the MME as defined in subclause 6.4.4 of 3GPP TS 29.173 [57] and;
    - the Node Realm shall be coded as the Diameter realm identity of the MME as defined in subclause 6.4.12 of 3GPP TS 29.173 [57] and;
    -  Both the Node Name and the Node Realm shall be present and neither the Length of Node Name nor the Length of Node Realm shall be zero.
        6.4.4    MME-Name
        The MME-Name AVP is of type DiameterIdentity...see IETF RFC 6733
        6.4.12 MME-Realm
        The MME-Realm AVP is of type DiameterIdentity...see IETF RFC 6733

    If the Node Identifer contains a 3GPP AAA Server Identifier then:
    - the Node Name shall be coded as the 3GPP-AAA-Server-Name as defined in subclause 8.2.3.24 of 3GPP TS 29.273 [68] and;
        8.2.3.24    3GPP-AAA-Server-Name
        The 3GPP-AAA-Server-Name AVP is of type DiameterIdentity
    - the Node Realm shall be coded as the Diameter realm of the 3GPP AAA server in the format of a Diameter identity as defined in IETF RFC 3588 [39].

    If the Node Identifier contains an SCEF/IWK-SCEF information, then:
    - the Node Name shall be coded as the SCEF-ID as defined in subclause 8.4.5 of 3GPP TS 29.336 [69] and;
        8.4.5 SCEF-ID
        The SCEF- ID AVP is of type DiameterIdentity
    - the Node Realm shall be coded as the Diameter realm of the SCEF as defined in subclause 7.3.207 of 3GPP TS 29.272 [70].

    */
    /* Octet 5 Length of Node Name */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_length_of_node_name, tvb, offset, 1, ENC_BIG_ENDIAN, &name_len);
    offset++;
    /* Node Name */
    proto_tree_add_item(tree, hf_gtpv2_node_name, tvb, offset, name_len, ENC_UTF_8);
    offset = offset + name_len;
    /* Length of Node Realm */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_length_of_node_realm, tvb, offset, 1, ENC_BIG_ENDIAN, &name_len);
    offset++;
    /* Node Realm */
    proto_tree_add_item(tree, hf_gtpv2_node_realm, tvb, offset, name_len, ENC_UTF_8);
    offset = offset + name_len;
    if(offset < length){
        proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, length- offset);
    }
}
/*
 * 8.108        Presence Reporting Area Action
 */

/*
 * The Presence-Reporting-Area-Elements-List AVP (AVP code 2820)
 * is of type Octetstring and is coded as specified in 3GPP TS 29.274 [22]
 * in Presence Reporting Area Action IE, starting from octet 9.
 */

static int
dissect_diameter_3gpp_presence_reporting_area_elements_list(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /*diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;*/
    proto_tree *sub_tree;
    proto_item *item;
    int   offset = 0, i;
    unsigned length;
    uint32_t no_tai, no_rai, no_mENB, no_hENB, no_ECGI, no_sai, no_cgi, no_ext_mENB;
    char *append_str;
    length       = tvb_reported_length(tvb);

    /* Octet 9  Number of TAI   Number of RAI */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_pres_rep_area_act_no_tai, tvb, offset, 1, ENC_BIG_ENDIAN, &no_tai);
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_pres_rep_area_act_no_rai, tvb, offset, 1, ENC_BIG_ENDIAN, &no_rai);
    offset++;
    /* Octet 10 Spare   Number of Macro eNodeB */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_pres_rep_area_act_no_m_enodeb, tvb, offset, 1, ENC_BIG_ENDIAN, &no_mENB);
    offset++;
    /* Octet 11 Spare   Number of Home eNodeB */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_pres_rep_area_act_no_h_enodeb, tvb, offset, 1, ENC_BIG_ENDIAN, &no_hENB);
    offset++;
    /* Octet 12 Spare   Number of ECGI */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_pres_rep_area_act_no_ecgi, tvb, offset, 1, ENC_BIG_ENDIAN, &no_ECGI);
    offset++;
    /* Octet 13 Spare   Number of SAI */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_pres_rep_area_act_no_sai, tvb, offset, 1, ENC_BIG_ENDIAN, &no_sai);
    offset++;
    /* Octet 14 Spare   Number of CGI */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_pres_rep_area_act_no_cgi, tvb, offset, 1, ENC_BIG_ENDIAN, &no_cgi);
    offset++;
    /* Octet 15 to k    TAIs [1..15] */
    i = 1;
    while (no_tai > 0){
        sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 5, ett_gtpv2_preaa_tais, &item, "Tracking Area Identity (TAI) Number %u",i);
        append_str = dissect_gtpv2_tai(tvb, pinfo, sub_tree, &offset, false);
        proto_item_append_text(item, " %s",append_str);
        i++;
        no_tai--;
    }
    /* Octet (k+1) to m Macro eNB IDs [1..63]
     * Macro eNB IDs in octets 'k+1' to 'm', if any, shall be encoded as per octets 6 to 11 of the Target ID for type Macro eNodeB in figure 8.51-2.
     * Octets 'k+1' to 'm' shall be absent if the field 'Number of Macro eNodeB' is set to the value '0'.
     */
    i = 1;
    while (no_mENB > 0){
        sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 6, ett_gtpv2_preaa_menbs, &item, "Macro eNB ID %u",i);
        append_str = dissect_gtpv2_macro_enodeb_id(tvb, pinfo, sub_tree, &offset);
        proto_item_append_text(item, " %s",append_str);
        i++;
        no_mENB--;
    }
    /* Octet (m+1) to p Home eNB IDs [1..63]
     * Home eNB IDs in octets 'm+1' to 'p', if any, shall be encoded as per octets 6 to 12 of the Target ID for type Home eNodeB in figure 8.51-3.
     * Octets  'm+1' to 'p' shall be absent if the field 'Number of Home eNodeB' is set to the value '0'.
     */
    i = 1;
    while (no_hENB > 0){
        sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 7, ett_gtpv2_preaa_henbs, &item, "Home eNB ID %u",i);
        append_str = dissect_gtpv2_home_enodeb_id(tvb, pinfo, sub_tree, &offset);
        proto_item_append_text(item, " %s",append_str);
        i++;
        no_hENB--;
    }
    /* Octet (p+1) to q ECGIs [1..63]
     * ECGIs in octets 'p+1' to 'q', if any, shall be encoded as per the ECGI field in subclause 8.21.5.
     * Octets 'p+1' to 'q' shall be absent if the field 'Number of ECGI' is set to the value '0'.
     */
    i = 1;
    while (no_ECGI > 0){
        sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 7, ett_gtpv2_preaa_ecgis, &item, "ECGI ID %u",i);
        append_str = dissect_gtpv2_ecgi(tvb, pinfo, sub_tree, &offset);
        proto_item_append_text(item, " %s",append_str);
        i++;
        no_ECGI--;
    }
    /* Octet (q+1) to r RAIs [1..15]
     * RAIs in octets 'q+1' to 'r', if any, shall be encoded as per the RAI field in subclause 8.21.3.
     * Octets 'q+1' to 'r' shall be absent if the field 'Number of RAI' is set to the value '0'.
     */
    i = 1;
    while (no_rai > 0){
        sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 7, ett_gtpv2_preaa_rais, &item, "RAI ID %u",i);
        append_str = dissect_gtpv2_rai(tvb, pinfo, sub_tree, &offset);
        proto_item_append_text(item, " %s",append_str);
        i++;
        no_rai--;
    }
    /* Octet (r+1) to s SAIs [1..63]
     * SAIs in octets 'r+1' to 's', if any, shall be encoded as per the SAI field in subclause 8.21.2.
     * Octets 'r+1' to 's' shall be absent if the field 'Number of SAI' is set to the value '0'.
     */
    i = 1;
    while (no_sai > 0){
        sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 7, ett_gtpv2_preaa_sais, &item, "SAI ID %u",i);
        append_str = dissect_gtpv2_sai_common(tvb, pinfo, sub_tree, &offset);
        proto_item_append_text(item, " %s",append_str);
        i++;
        no_sai--;
    }
    /* Octet (s+1) to t CGIs [1..63]
     * CGIs in octets 's+1' to 't', if any, shall be encoded as per the CGI field in subclause 8.21.1.
     * Octets 's+1' to 't' shall be absent if the field 'Number of CGI' is set to the value '0'.
     */
    i = 1;
    while (no_cgi > 0){
        sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 7, ett_gtpv2_preaa_cgis, &item, "CGI ID %u",i);
        append_str = dissect_gtpv2_cgi(tvb, pinfo, sub_tree, &offset);
        proto_item_append_text(item, " %s",append_str);
        i++;
        no_cgi--;
    }
    if (offset >= (int) length)
        return length;
    /* Octet t+1 Spare   Number of Extended Macro eNodeB */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_pres_rep_area_act_no_ext_m_enodeb, tvb, offset, 1, ENC_BIG_ENDIAN, &no_ext_mENB);
    offset++;
    /* Octet (t+2) to v Extended Macro eNB IDs [1..63]
     * Extended Macro eNB IDs in octets 't+2' to 'v', if any, shall be encoded as per octets 6 to 11 of the Target ID for type Extended Macro eNodeB in figure 8.51-5.
     * Octets 'k+1' to 'm' shall be absent if the field 'Number of Extended Macro eNodeB' is set to the value '0'.
     */
    i = 1;
    while (no_ext_mENB > 0){
        sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, 6, ett_gtpv2_preaa_ext_menbs, &item, "Extended Macro eNB ID %u",i);
        append_str = dissect_gtpv2_ext_macro_enodeb_id(tvb, pinfo, sub_tree, &offset, hf_gtpv2_ext_macro_enodeb_id);
        proto_item_append_text(item, " %s",append_str);
        i++;
        no_ext_mENB--;
    }

    return length;
}

static const value_string gtpv2_pres_rep_area_action_vals[] = {
    { 1, "Start Reporting change"},
    { 2, "Stop Reporting change"},
    { 3, "Modify Presence Reporting Area elements"},
    { 0, NULL}
};

static void
dissect_gtpv2_pres_rep_area_action(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    tvbuff_t * new_tvb;

    static int * const flags[] = {
        &hf_gtpv2_pres_rep_area_act_inapra,
        &hf_gtpv2_pres_rep_area_action,
        NULL
    };

    /* Octet 5  Spare INAPRA Action */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);
    offset++;

    if (length == 1)
        return;
    /* Octet 6 to 8     Presence Reporting Area Identifier */
    proto_tree_add_item(tree, hf_gtpv2_pres_rep_area_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset+=3;
    if (length == 4)
        return;

    new_tvb = tvb_new_subset_length(tvb, offset, length-4);

    /* Share the rest of the dissection with the AVP dissector */
    dissect_diameter_3gpp_presence_reporting_area_elements_list(new_tvb, pinfo, tree, NULL);

}
/*
 * 8.109        Presence Reporting Area Information
 */
static void
dissect_gtpv2_pres_rep_area_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    uint64_t gtpv2_pres_rep_area_info_flags_val = 0;

    /*Octet 5 to 7      Presence Reporting Area Identifier */
    proto_tree_add_item(tree, hf_gtpv2_pres_rep_area_info_id, tvb, offset, 3 , ENC_BIG_ENDIAN);
    offset+=3;

    /*Octet 8    Spare Spare Spare Spare INAPRA APRA OPRA IPRA */
    static int * const gtpv2_pres_rep_area_info_flags[] = {
        &hf_gtpv2_pres_rep_area_info_flags_b4_b7_spare,
        &hf_gtpv2_pres_rep_area_info_flags_b3_inapra,
        &hf_gtpv2_pres_rep_area_info_flags_b2_apra,
        &hf_gtpv2_pres_rep_area_info_flags_b1_opra,
        &hf_gtpv2_pres_rep_area_info_flags_b0_ipra,
        NULL
    };

    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_gtpv2_pres_rep_area_info_flags, ett_gtpv2_pres_rep_area_info,
            gtpv2_pres_rep_area_info_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT | BMT_NO_TFS, &gtpv2_pres_rep_area_info_flags_val);
    offset+=1;

    /* 3GPP TS 29.212 v14.7.0:
     * If the Additional PRA (APRA) flag is set to 1, [...]
     * subsequent 4 octets shall then be present
     * and shall contain the identifier of the individual PRA
     */
    if(gtpv2_pres_rep_area_info_flags_val & 0x04){
        /* Octets a to (a+2)        Additional PRA Identifier  */
    proto_tree_add_item(tree, hf_gtpv2_pres_rep_area_info_additional_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset+=3;

        /*Octet a+3          Spare Spare Spare Spare Spare APRA OPRA IPRA */
    static int * const gtpv2_pres_rep_area_info_flags_no_inapra[] = {
      &hf_gtpv2_pres_rep_area_info_flags_b3_b7_spare,
      &hf_gtpv2_pres_rep_area_info_flags_b2_apra,
      &hf_gtpv2_pres_rep_area_info_flags_b1_opra,
      &hf_gtpv2_pres_rep_area_info_flags_b0_ipra,
      NULL
    };

        while(offset < length){
            proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_gtpv2_pres_rep_area_info_flags_no_inapra, ett_gtpv2_pres_rep_area_info,
                         gtpv2_pres_rep_area_info_flags_no_inapra, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT | BMT_NO_TFS, &gtpv2_pres_rep_area_info_flags_val);
            offset+=1;

            if(gtpv2_pres_rep_area_info_flags_val & 0x04){
                /* Octets b to (b+2)     Additional PRA Identifier  */
                proto_tree_add_item(tree, hf_gtpv2_pres_rep_area_info_additional_id, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset+=3;
            }
        }
    }
}
/*
 * 8.110        TWAN Identifier Timestamp
 */
static void
dissect_gtpv2_twan_identifier_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    char *time_str;

    /* TWAN Identifier Timestamp value */
    /* Octets 5 to 8 are encoded in the same format as the first four octets of the 64-bit timestamp
    * format as defined in section 6 of IETF RFC 5905
    */

    proto_tree_add_item_ret_time_string(tree, hf_gtpv2_twan_id_ts, tvb, 0, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &time_str);
    proto_item_append_text(item, "%s", time_str);

}
/*
 * 8.111        Overload Control Information
 */
static void

dissect_gtpv2_overload_control_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{

    int         offset = 0;
    proto_tree *grouped_tree;
    tvbuff_t   *new_tvb;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(item, ett_gtpv2_overload_control_information);
    new_tvb = tvb_new_subset_length(tvb, offset, length);

    dissect_gtpv2_ie_common(new_tvb, pinfo, grouped_tree, offset, message_type, args, GTPV2_IE_OVERLOAD_CONTROL_INF);
}
/*
 * 8.112        Load Control Information
 */
static void
dissect_gtpv2_load_control_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, proto_item *item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int         offset = 0;
    tvbuff_t   *new_tvb;
    proto_tree *grouped_tree;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(item, ett_gtpv2_load_control_inf);

    new_tvb = tvb_new_subset_length(tvb, offset, length);
    dissect_gtpv2_ie_common(new_tvb, pinfo, grouped_tree, 0, message_type, args, GTPV2_IE_LOAD_CONTROL_INF);
}
/*
 * 8.113        Metric
 */
static void
dissect_gtpv2_metric(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
   uint32_t oct;

   proto_tree_add_item_ret_uint(tree, hf_gtpv2_metric, tvb, 0, 1, ENC_BIG_ENDIAN, &oct);
   if (oct > 0x64) {
       proto_item_append_text(item, "Metric: value beyond 100 is considered as 0");
   } else {
       proto_item_append_text(item, "%u", oct);

   }
}
/*
 * 8.114        Sequence Number
 */
static void
dissect_gtpv2_seq_no(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    uint32_t seq;
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_sequence_number, tvb, 0, 4, ENC_BIG_ENDIAN, &seq);
    proto_item_append_text(item, "%u", seq);
}
/*
 * 8.115        APN and Relative Capacity
 */
static void
dissect_gtpv2_apn_and_relative_capacity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int       offset = 0;
    uint8_t oct, apn_length;
    const uint8_t *apn    = NULL;

    oct = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_relative_capacity, tvb, offset, 1, ENC_BIG_ENDIAN);
    if((oct > 0x64) || (oct < 0x01))
        proto_item_append_text(item, "Relative Capacity: value beyond (1,100) is considered as 0");
    offset += 1;
    apn_length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_apn_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (apn_length > 0) {
        proto_item* pi;
        pi = proto_tree_add_item_ret_string(tree, hf_gtpv2_apn, tvb, offset, apn_length, ENC_APN_STR | ENC_NA, pinfo->pool, &apn);
        if (apn_length > 100)
            expert_add_info(pinfo, pi, &ei_gtpv2_apn_too_long);
    }
}
/*
 * 8.117        Paging and Service Information
 */
static void
dissect_gtpv2_paging_and_service_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    uint8_t ppi_flag;

    /* Spare (all bits set to 0) B8 - B5 */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* EPS Bearer ID (EBI) B4 - B1 */
    proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Spare B8 - B2 */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset << 3, 7, ENC_BIG_ENDIAN);
    /* Paging Policy Indication flag (PPI) */
    ppi_flag = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_ppi_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if(ppi_flag & 1){
        /* Spare B8 - B7 */
        proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset << 3, 2, ENC_BIG_ENDIAN);
        /* Paging Policy Indication Value */
        proto_item_append_text(tree, " (PPI Value: %s)", val_to_str_ext_const(tvb_get_uint8(tvb, offset), &dscp_vals_ext, "Unknown"));
        proto_tree_add_item(tree, hf_gtpv2_ppi_value, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
}
/*
 * 8.118        Integer Number
 */
static void
dissect_gtpv2_integer_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, uint16_t length, uint8_t message_type, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    /* The Integer Number value shall be encoded as further described below for the following information elements:
     * Maximum Wait Time IE:  the length shall be set to 2, i.e. the integer number value shall be encoded as a 16 bit unsigned integer.
     * DL Buffering Suggested Packet Count IE: the length shall be set to 1 or 2;
     * UE Usage Type IE: the length shall be set to 1, i.e. the integer number value shall be encoded as a 8 bit unsigned integer as specified in subclause 7.3.202 of 3GPP TS 29.272 [70].
     */
    if (length <= 4) {
        /* Only handle up to 32 bits for now */
        switch (message_type) {
        case GTPV2_CREATE_SESSION_REQUEST:
            proto_item_append_text(item, "Maximum Wait Time");
            proto_tree_add_item(tree, hf_gtpv2_maximum_wait_time, tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case GTPV2_DL_DATA_NOTIF_ACK:
            proto_item_append_text(item, "DL Buffering Suggested Packet Count");
            proto_tree_add_item(tree, hf_gtpv2_dl_buf_sug_pkt_cnt, tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        case GTPV2_FORWARD_RELOCATION_REQ:
        case GTPV2_CONTEXT_RESPONSE:
        case GTPV2_IDENTIFICATION_RESPONSE:
            switch (instance) {
            case 0:
                /* If the UE Usage Type is not available in the old MME/SGSN/AMF, the length field of this IE shall be set to 0. */
                proto_item_append_text(item, "UE Usage Type");
                if (length > 0) {
                    proto_tree_add_item(tree, hf_gtpv2_ue_usage_type, tvb, offset, length, ENC_BIG_ENDIAN);
                } else {
                    proto_item_append_text(item, " not available in the old MME/SGSN/AMF");
                }
                break;
            case 1:
                /* Remaining Running Service Gap Timer */
                proto_tree_add_item(tree, hf_gtpv2_rem_run_serv_gap_t, tvb, offset, length, ENC_BIG_ENDIAN);
                break;
            default:
                proto_tree_add_item(tree, hf_gtpv2_integer_number_val, tvb, offset, length, ENC_BIG_ENDIAN);
                break;
            }
            break;
        default:
            proto_tree_add_item(tree, hf_gtpv2_integer_number_val, tvb, offset, length, ENC_BIG_ENDIAN);
            break;
        }
    } else {
        /* value not handled, yet*/
        proto_tree_add_expert(tree, pinfo, &ei_gtpv2_int_size_not_handled, tvb, offset, length);

    }

}
/*
 * 8.119 Millisecond Time Stamp
 */

static void
dissect_gtpv2_ms_ts(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    /* Octets 5 to 10 represent a 48 bit unsigned integer in network order format and are encoded as
     * the number of milliseconds since 00:00:00 January 1, 1900 00:00 UTC, i.e. as the
     * rounded value of 1000 x the value of the 64-bit timestamp (Seconds  + (Fraction / (1<<32)))
     * defined in section 6 of IETF RFC 5905
     */
    switch (message_type) {
    case GTPV2_CREATE_SESSION_REQUEST:
        /*proto_item_append_text(item, "Origination time stamp");*/
        proto_tree_add_item(tree, hf_gtpv2_origination_ts, tvb, offset, length, ENC_TIME_MSEC_NTP | ENC_BIG_ENDIAN);
        break;
    default:
        proto_tree_add_item(tree, hf_gtpv2_ms_ts, tvb, offset, 6, ENC_TIME_MSEC_NTP | ENC_BIG_ENDIAN);
        break;
    }
}

/*
 * 8.120        Monitoring Event Information
 */
static void
dissect_gtpv2_mon_event_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    bool srie;
    uint32_t scef_id_len;

    /* Octet 4 higher four bits flags SIRE, NSCF, NSUI and NSUR */
    proto_tree_add_item_ret_boolean(tree, hf_gtpv2_mon_event_inf_srie, tvb, offset, 1, ENC_BIG_ENDIAN, &srie);
    proto_tree_add_item(tree, hf_gtpv2_mon_event_inf_nscf, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_mon_event_inf_nsui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_mon_event_inf_nsur, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Octet 4 lower four bits Instance */
    proto_tree_add_item(tree, hf_gtpv2_instance, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Octet 5 to 8 SCEF Reference ID */
    proto_tree_add_item(tree, hf_gtpv2_mon_event_inf_scef_reference_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* Octet 9 Length of SCEF ID */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_mon_event_inf_scef_id_length, tvb, offset, 1, ENC_BIG_ENDIAN, &scef_id_len);
    offset++;
    /* Octet 10 to k SCEF ID */
    proto_tree_add_item(tree, hf_gtpv2_mon_event_inf_scef_id, tvb, offset, scef_id_len, ENC_UTF_8);
    offset = offset + scef_id_len;
    /* Octet (k+1) to (k+2) Remaining Number of Reports */
    proto_tree_add_item(tree, hf_gtpv2_mon_event_inf_remaining_number_of_reports, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    if (srie) {
        proto_tree_add_item(tree, hf_gtpv2_mon_event_inf_scef_reference_id_ext, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if(offset < length){
        proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, length - offset);
    }
}

/*
 * 8.125 CIoT Optimizations Support Indication
 */
static void
dissect_gtpv2_ciot_opt_support_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
   int               offset;
   static int * const ciot_flags[] = {
       &hf_gtpv2_ciot_support_ind_spare_bits,
       &hf_gtpv2_ciot_support_ind_bit4,
       &hf_gtpv2_ciot_support_ind_bit3,
       &hf_gtpv2_ciot_support_ind_bit2,
       &hf_gtpv2_ciot_support_ind_bit1,
       NULL
   };

   offset = 0;
   proto_tree_add_bitmask_with_flags(tree, tvb, 0, hf_gtpv2_ciot_support_ind, ett_gtpv2_ciot_support_ind, ciot_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);

   offset += 1;
   if (length - offset) {
      proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");
   }
}

/*
 * 8.126 SCEF PDN Connection
 */
static void
dissect_gtpv2_scef_pdn_connection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree  _U_, proto_item *item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args)
{
   int         offset = 0;
   proto_tree *grouped_tree;
   tvbuff_t   *new_tvb;

   proto_item_append_text(item, "[Grouped IE]");
   grouped_tree = proto_item_add_subtree(item, ett_gtpv2_PDN_conn);
   new_tvb = tvb_new_subset_length(tvb, offset, length);

   dissect_gtpv2_ie_common(new_tvb, pinfo, grouped_tree, offset, message_type, args, GTPV2_IE_SCEF_PDN_CONNECTION);

}


/*
 * 8.127 Header Compression Configuration
 */
static void
dissect_gtpv2_header_comp_comf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    static int * const gtpv2_rohc_profile_flags_flags[] = {
        &hf_gtpv2_rohc_profiles_bit7,
        &hf_gtpv2_rohc_profiles_bit6,
        &hf_gtpv2_rohc_profiles_bit5,
        &hf_gtpv2_rohc_profiles_bit4,
        &hf_gtpv2_rohc_profiles_bit3,
        &hf_gtpv2_rohc_profiles_bit2,
        &hf_gtpv2_rohc_profiles_bit1,
        &hf_gtpv2_rohc_profiles_bit0,
        NULL
    };

    /* Octet 5 to 6   ROHC Profiles */

    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_gtpv2_rohc_profile_flags,
        ett_gtpv2_rohc_profile_flags, gtpv2_rohc_profile_flags_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT);
    offset++;
    proto_tree_add_item(tree, hf_gtpv2_spare_w0, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Octet 7 to 8 MAX_CID*/
    proto_tree_add_item(tree, hf_gtpv2_max_cid, tvb, offset, 2, ENC_BIG_ENDIAN);

}

/*
 * 8.129 Serving PLMN Rate Control
 */
static void
dissect_gtpv2_serv_plmn_rate_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_uplink_rate_limit, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_gtpv2_downlink_rate_limit, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/*
 * 8.130 Counter
 */
static void
dissect_gtpv2_counter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    /* Timestamp value */
    /* Octets 5 to 8 shall be encoded in the same format as the first four octets of the 64-bit timestamp
     *format as defined in section 6 of IETF RFC 5905
     */

    proto_tree_add_item(tree, hf_gtpv2_timestamp_value, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_gtpv2_counter_value, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/*
 * 8.131 Mapped UE Usage Type
 */

static void
dissect_gtpv2_mapped_ue_usage_type(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_mapped_ue_usage_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (length > offset) {
        proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");
    }
}

/*
 * 8.132 Secondary RAT Usage Data Report
 */
static const value_string gtpv2_secondary_rat_type_vals[] = {
    { 0, "NR" },
    { 1, "Unlicensed Spectrum"},
    { 0, NULL }
};

static void
dissect_gtpv2_secondary_rat_usage_data_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
   tvbuff_t   *new_tvb;
   proto_tree *sub_tree;
   int offset = 0;
   uint32_t srudn_len;
   uint64_t gtpv2_secondary_rat_usage_data_report_flags_val = 0;

   static int * const secondary_rat_usage_data_report_flags[] = {
       &hf_gtpv2_secondary_rat_usage_data_report_spare_bits,
       &hf_gtpv2_secondary_rat_usage_data_report_bit3,
       &hf_gtpv2_secondary_rat_usage_data_report_bit2,
       &hf_gtpv2_secondary_rat_usage_data_report_bit1,
       NULL
   };

  /*
   * The following bits within Octet 5 shall indicate:
   * Bit 8 to 3 - Spare, for future use and set to zero.
   * Bit 3 - SRUDN (Secondary RAT Usage Report from NG-RAN)
   * Bit 2 - IRSGW (Intended Receiver SGW)
   * Bit 1 - IRPGW (Intended Receiver PGW)
   */
   proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, 0, hf_gtpv2_secondary_rat_usage_data_report, ett_gtpv2_secondary_rat_usage_data_report,
        secondary_rat_usage_data_report_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND, &gtpv2_secondary_rat_usage_data_report_flags_val);
   offset += 1;

    /* Octet 6 RAT Type */
    proto_tree_add_item(tree, hf_gtpv2_secondary_rat_usage_data_report_rat_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 7 EPS Bearer ID */
    /* Spare (all bits set to 0) B8 - B5 */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
    /* EPS Bearer ID (EBI) B4 - B1 */
    proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*
    * Octets 8 to 11 and 12 to 15 shall be encoded in the same format as the first four octets of the 64-bit timestamp
    * format as defined in section 6 of IETF RFC 5905
    */

    /* Octets 8 to 11 Start timestamp */
    proto_tree_add_item(tree, hf_gtpv2_secondary_rat_usage_data_report_start_timestamp, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN);
    offset += 4;

    /* Octets 12 to 15 End timestamp */
    proto_tree_add_item(tree, hf_gtpv2_secondary_rat_usage_data_report_end_timestamp, tvb, offset, 4, ENC_TIME_NTP | ENC_BIG_ENDIAN);
    offset += 4;

    /* 16 to 23 Usage Data DL */
    proto_tree_add_item(tree, hf_gtpv2_secondary_rat_usage_data_report_usage_data_dl, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* 24 to 32 Usage Data UL */
    proto_tree_add_item(tree, hf_gtpv2_secondary_rat_usage_data_report_usage_data_ul, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    if(gtpv2_secondary_rat_usage_data_report_flags_val & 0x04) {
        /* Octet k Length of Secondary RAT Data Usage Report Transfer */
        proto_tree_add_item_ret_uint(tree, hf_gtpv2_secondary_rat_usage_data_report_srudn_length, tvb, offset, 1, ENC_BIG_ENDIAN, &srudn_len);
        offset++;
        /* Octet (k+1) to a SRUDN */
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, srudn_len, ett_gtpv2_son_con, NULL, "SecondaryRATDataUsageReportTransfer");
        new_tvb = tvb_new_subset_length(tvb, offset, srudn_len);
        asn1_ctx_t asn1_ctx;
        asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
        dissect_ngap_SecondaryRATDataUsageReportTransfer(new_tvb, 0, &asn1_ctx, sub_tree, hf_gtpv2_secondary_rat_usage_data_report_srudn_value);
        offset = offset + srudn_len;
    }

   if (length - offset) {
      proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, -1, "The rest of the IE not dissected yet");
   }
}



/*
 * 8.133 UP Function Selection Indication Flags
 */

static void
dissect_gtpv2_up_func_slec_indic_flg(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t * args _U_)
{
    int offset = 0;

    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset << 3, 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_dcnr, tvb, offset, 1, ENC_BIG_ENDIAN);

}

/* 8.134 Maximum Packet Loss Rate */
static void
dissect_gtpv2_max_pkt_loss_rte(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, proto_item* item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    int offset = 0;
    uint8_t oct;

    static int* const flags_oct1[] = {
        &hf_gtpv2_spare_b7_b2,
        &hf_gtpv2_max_pkt_loss_rte_dl_flg,
        &hf_gtpv2_max_pkt_loss_rte_ul_flg,
        NULL
    };
    /*5 Spare DL UL*/
    oct = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_oct1, ENC_BIG_ENDIAN);
    offset++;

    if((oct & 0x01) == 1){
        /*m to m+1 Maximum Packet Loss Rate UL*/
        proto_tree_add_item(tree, hf_gtpv2_max_pkt_loss_rte_ul, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    if ((oct & 0x02) == 2) {
        /*o to o+1 Maximum Packet Loss Rate DL*/
        proto_tree_add_item(tree, hf_gtpv2_max_pkt_loss_rte_dl, tvb, offset, 2, ENC_BIG_ENDIAN);
    }


}

/* 8.135 APN Rate Control Status */
static void
dissect_gtpv2_apn_rte_cntrl_status(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, proto_item* item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    int offset = 0;

    /*5 to 8 Number of Uplink packets allowed*/
    proto_tree_add_item(tree, hf_gtpv2_nr_ul_pkts_all, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /*9 to 12 Number of additional exception reports*/
    proto_tree_add_item(tree, hf_gtpv2_nr_add_exception_rpts, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /*13 to 16 Number of Downlink packets allowed*/
    proto_tree_add_item(tree, hf_gtpv2_nr_dl_pkts_all, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /*17 to 24 APN Rate Control Status validity Time*/
    proto_tree_add_item(tree, hf_apn_rte_cntrl_status_val_time, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);

}
/* 3GPP TS 32.422 V15.1.0 (2018-06) 5.5 List of interfaces (O)*/

static int* const ext_tra_info_list_of_if_flags_oct1[] = {
    &hf_gtpv2_ext_tra_info_loi_mscs_cap,
    &hf_gtpv2_ext_tra_info_loi_mscs_map_f,
    &hf_gtpv2_ext_tra_info_loi_mscs_map_e,
    &hf_gtpv2_ext_tra_info_loi_mscs_map_b,
    &hf_gtpv2_ext_tra_info_loi_mscs_map_g,
    &hf_gtpv2_ext_tra_info_loi_mscs_mc,
    &hf_gtpv2_ext_tra_info_loi_mscs_iu,
    &hf_gtpv2_ext_tra_info_loi_mscs_a,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct2[] = {
    &hf_gtpv2_ext_tra_info_loi_mscs_map_c,
    &hf_gtpv2_ext_tra_info_loi_mscs_map_d,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct3[] = {
    &hf_gtpv2_ext_tra_info_loi_mgw_iuup,
    &hf_gtpv2_ext_tra_info_loi_mgw_nbup,
    &hf_gtpv2_ext_tra_info_loi_mgw_mc,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct4[] = {
    &hf_gtpv2_ext_tra_info_loi_sgsn_ge,
    &hf_gtpv2_ext_tra_info_loi_sgsn_gs,
    &hf_gtpv2_ext_tra_info_loi_sgsn_map_gf,
    &hf_gtpv2_ext_tra_info_loi_sgsn_map_gd,
    &hf_gtpv2_ext_tra_info_loi_sgsn_map_gr,
    &hf_gtpv2_ext_tra_info_loi_sgsn_gn,
    &hf_gtpv2_ext_tra_info_loi_sgsn_iu,
    &hf_gtpv2_ext_tra_info_loi_sgsn_gb,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct5[] = {
    &hf_gtpv2_ext_tra_info_loi_sgsn_s13,
    &hf_gtpv2_ext_tra_info_loi_sgsn_s3,
    &hf_gtpv2_ext_tra_info_loi_sgsn_s4,
    &hf_gtpv2_ext_tra_info_loi_sgsn_s6d,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct6[] = {
    &hf_gtpv2_ext_tra_info_loi_ggsn_gmb,
    &hf_gtpv2_ext_tra_info_loi_ggsn_gi,
    &hf_gtpv2_ext_tra_info_loi_ggsn_gn,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct7[] = {
    &hf_gtpv2_ext_tra_info_loi_rnc_uu,
    &hf_gtpv2_ext_tra_info_loi_rnc_iub,
    &hf_gtpv2_ext_tra_info_loi_rnc_iur,
    &hf_gtpv2_ext_tra_info_loi_rnc_iu,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct8[] = {
    &hf_gtpv2_ext_tra_info_loi_bm_sc_gmb,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct9[] = {
    &hf_gtpv2_ext_tra_info_loi_mme_s13,
    &hf_gtpv2_ext_tra_info_loi_mme_s11,
    &hf_gtpv2_ext_tra_info_loi_mme_s10,
    &hf_gtpv2_ext_tra_info_loi_mme_s6a,
    &hf_gtpv2_ext_tra_info_loi_mme_s3,
    &hf_gtpv2_ext_tra_info_loi_mme_s1_mme,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct10[] = {
    &hf_gtpv2_ext_tra_info_loi_sgw_gxc,
    &hf_gtpv2_ext_tra_info_loi_sgw_s11,
    &hf_gtpv2_ext_tra_info_loi_sgw_s8b,
    &hf_gtpv2_ext_tra_info_loi_sgw_s5,
    &hf_gtpv2_ext_tra_info_loi_sgw_s4,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct11[] = {
    &hf_gtpv2_ext_tra_info_loi_pdn_gw_sgi,
    &hf_gtpv2_ext_tra_info_loi_pdn_gw_s8b,
    &hf_gtpv2_ext_tra_info_loi_pdn_gw_gx,
    &hf_gtpv2_ext_tra_info_loi_pdn_gw_s6b,
    &hf_gtpv2_ext_tra_info_loi_pdn_gw_s5,
    &hf_gtpv2_ext_tra_info_loi_pdn_gw_s2c,
    &hf_gtpv2_ext_tra_info_loi_pdn_gw_s2b,
    &hf_gtpv2_ext_tra_info_loi_pdn_gw_s2a,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct12[] = {
    &hf_gtpv2_ext_tra_info_loi_enb_uu,
    &hf_gtpv2_ext_tra_info_loi_enb_x2,
    &hf_gtpv2_ext_tra_info_loi_enb_s1_mme,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct13[] = {
    &hf_gtpv2_ext_tra_info_loi_hss_sh,
    &hf_gtpv2_ext_tra_info_loi_hss_s6a,
    &hf_gtpv2_ext_tra_info_loi_hss_s6d,
    &hf_gtpv2_ext_tra_info_loi_hss_cx,
    &hf_gtpv2_ext_tra_info_loi_hss_map_gr,
    &hf_gtpv2_ext_tra_info_loi_hss_map_gc,
    &hf_gtpv2_ext_tra_info_loi_hss_map_d,
    &hf_gtpv2_ext_tra_info_loi_hss_map_c,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct14[] = {
    &hf_gtpv2_ext_tra_info_loi_eir_map_gf,
    &hf_gtpv2_ext_tra_info_loi_eir_s13p,
    &hf_gtpv2_ext_tra_info_loi_eir_s13,
    &hf_gtpv2_ext_tra_info_loi_eir_map_f,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct15[] = {
    &hf_gtpv2_ext_tra_info_loi_amf_n20,
    &hf_gtpv2_ext_tra_info_loi_amf_n15,
    &hf_gtpv2_ext_tra_info_loi_amf_n14,
    &hf_gtpv2_ext_tra_info_loi_amf_n12,
    &hf_gtpv2_ext_tra_info_loi_amf_n11,
    &hf_gtpv2_ext_tra_info_loi_amf_n8,
    &hf_gtpv2_ext_tra_info_loi_amf_n2,
    &hf_gtpv2_ext_tra_info_loi_amf_n1,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct16[] = {
    &hf_gtpv2_ext_tra_info_loi_amf_n22,
    &hf_gtpv2_ext_tra_info_loi_amf_n26,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct17[] = {
    &hf_gtpv2_ext_tra_info_loi_pcf_n15,
    &hf_gtpv2_ext_tra_info_loi_pcf_n7,
    &hf_gtpv2_ext_tra_info_loi_pcf_n5,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct18[] = {
    &hf_gtpv2_ext_tra_info_loi_smf_s5_c,
    &hf_gtpv2_ext_tra_info_loi_smf_n11,
    &hf_gtpv2_ext_tra_info_loi_smf_n10,
    &hf_gtpv2_ext_tra_info_loi_smf_n7,
    &hf_gtpv2_ext_tra_info_loi_smf_n4,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct19[] = {
    &hf_gtpv2_ext_tra_info_loi_upf_n4,
    NULL
};

static int* const ext_tra_info_list_of_if_flags_oct20[] = {
    &hf_gtpv2_ext_tra_info_loi_ng_ran_node_e1_c,
    &hf_gtpv2_ext_tra_info_loi_ng_ran_node_f1_c,
    &hf_gtpv2_ext_tra_info_loi_ng_ran_node_Uu,
    &hf_gtpv2_ext_tra_info_loi_ng_ran_node_xn_c,
    &hf_gtpv2_ext_tra_info_loi_ng_ran_node_ng_c,
    NULL
};

/* 8.136 Extended Trace Information */
static void
dissect_gtpv2_ext_trs_inf(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, proto_item* item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    proto_tree *trigg_tree, *ne_tree, *if_tree;
    proto_item* ti;
    int offset = 0;
    uint32_t tid, ev_len;

    dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, E212_NONE, true);
    offset += 3;

    /* Append Trace ID to main tree */
    tid = tvb_get_ntohs(tvb, offset);

    proto_tree_add_item_ret_uint(tree, hf_gtpv2_trace_id, tvb, offset, 3, ENC_BIG_ENDIAN, &tid);
    proto_item_append_text(item, "Trace ID: %d  ", tid);

    offset += 3;

    /* Triggering Events, put all into a new tree called triggering_tree */
    trigg_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_gtpv2_tra_info_trigg, &ti, "Triggering Events");
    /* Octet 11 Length of Triggering Events */
    proto_tree_add_item_ret_uint(trigg_tree, hf_gtpv2_trig_event_len, tvb, offset, 1, ENC_BIG_ENDIAN, &ev_len);
    offset++;

    proto_item_set_len(ti, ev_len + 1);
    offset += ev_len;

    ne_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_gtpv2_tra_info_trigg, &ti, "List of NE Types");
    /* m + 1*/
    /* Length of List of NE Types */
    proto_tree_add_item_ret_uint(ne_tree, hf_gtpv2_ne_list_len, tvb, offset, 1, ENC_BIG_ENDIAN, &ev_len);
    offset++;
    if (ev_len > 0) {
        proto_tree_add_bitmask_list(ne_tree, tvb, offset, 1, trace_ne_types_flags_oct1, ENC_BIG_ENDIAN);
    }
    if (ev_len > 1) {
        proto_tree_add_bitmask_list(ne_tree, tvb, offset+1, 1, trace_ne_types_flags_oct2, ENC_BIG_ENDIAN);
    }

    proto_item_set_len(ti, ev_len + 1);
    offset += ev_len;

    /* p+1 Session Trace Depth */
    proto_tree_add_item(tree, hf_gtpv2_ses_trs_depth, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;


    if_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_gtpv2_tra_info_trigg, &ti, "List of Interfaces");
    /* p+2 Length of List of Interfaces */
    proto_tree_add_item_ret_uint(if_tree, hf_gtpv2_list_of_if_len, tvb, offset, 1, ENC_BIG_ENDIAN, &ev_len);
    offset++;

    if (ev_len > 1) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset, 2,
            ett_gtpv2_if_mgcs, NULL, "MSC Server interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, ext_tra_info_list_of_if_flags_oct1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 1, 1, ext_tra_info_list_of_if_flags_oct2, ENC_BIG_ENDIAN);
    }
    if (ev_len > 2) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 2, 1,
            ett_gtpv2_if_mgw, NULL, "MGW interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 2, 1, ext_tra_info_list_of_if_flags_oct3, ENC_BIG_ENDIAN);
    }

    if (ev_len > 4) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 3, 2,
            ett_gtpv2_if_sgsn, NULL, "SGSN interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 3, 1, ext_tra_info_list_of_if_flags_oct4, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 4, 1, ext_tra_info_list_of_if_flags_oct5, ENC_BIG_ENDIAN);
    }

    if (ev_len > 5) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 5, 1,
            ett_gtpv2_if_ggsn, NULL, "GGSN interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 5, 1, ext_tra_info_list_of_if_flags_oct6, ENC_BIG_ENDIAN);
    }
    if (ev_len > 6) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 6, 1,
            ett_gtpv2_if_rnc, NULL, "RNC interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 6, 1, ext_tra_info_list_of_if_flags_oct7, ENC_BIG_ENDIAN);
    }
    if (ev_len > 7) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 7, 1,
            ett_gtpv2_if_bm_sc, NULL, "BM-SC interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 7, 1, ext_tra_info_list_of_if_flags_oct8, ENC_BIG_ENDIAN);
    }
    if (ev_len > 8) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 8, 1,
            ett_gtpv2_if_mme, NULL, "MME interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 8, 1, ext_tra_info_list_of_if_flags_oct9, ENC_BIG_ENDIAN);
    }
    if (ev_len > 9) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 9, 1,
            ett_gtpv2_if_sgw, NULL, "SGW interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 9, 1, ext_tra_info_list_of_if_flags_oct10, ENC_BIG_ENDIAN);
    }
    if (ev_len > 10) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 10, 1,
            ett_gtpv2_if_pdn_gw, NULL, "PDN GW interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 10, 1, ext_tra_info_list_of_if_flags_oct11, ENC_BIG_ENDIAN);
    }
    if (ev_len > 11) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 11, 1,
            ett_gtpv2_if_enb, NULL, "eNB interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 11, 1, ext_tra_info_list_of_if_flags_oct12, ENC_BIG_ENDIAN);
    }
    if (ev_len > 12) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 12, 1,
            ett_gtpv2_if_hss, NULL, "HSS interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 11, 1, ext_tra_info_list_of_if_flags_oct13, ENC_BIG_ENDIAN);
    }
    if (ev_len > 13) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 13, 1,
            ett_gtpv2_if_eir, NULL, "EIR interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 11, 1, ext_tra_info_list_of_if_flags_oct14, ENC_BIG_ENDIAN);
    }
    if (ev_len > 15) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 14, 2,
            ett_gtpv2_if_amf, NULL, "AMF interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 14, 1, ext_tra_info_list_of_if_flags_oct15, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 15, 1, ext_tra_info_list_of_if_flags_oct16, ENC_BIG_ENDIAN);
    }
    if (ev_len > 16) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 16, 1,
            ett_gtpv2_if_pcf, NULL, "PCF interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 16, 1, ext_tra_info_list_of_if_flags_oct17, ENC_BIG_ENDIAN);
    }
    if (ev_len > 17) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 17, 1,
            ett_gtpv2_if_smf, NULL, "SMF interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 17, 1, ext_tra_info_list_of_if_flags_oct18, ENC_BIG_ENDIAN);
    }
    if (ev_len > 18) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 18, 1,
            ett_gtpv2_if_upf, NULL, "UPF interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 18, 1, ext_tra_info_list_of_if_flags_oct19, ENC_BIG_ENDIAN);
    }
    if (ev_len > 19) {
        proto_tree* sub_tree = proto_tree_add_subtree(if_tree, tvb, offset + 19, 1,
            ett_gtpv2_if_upf, NULL, "NG-RAN node interfaces");
        proto_tree_add_bitmask_list(sub_tree, tvb, offset + 19, 1, ext_tra_info_list_of_if_flags_oct20, ENC_BIG_ENDIAN);
    }

    proto_item_set_len(ti, ev_len + 1);
    offset += ev_len;

    /* q+1 Length of IP Address of Trace Collection Entity */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_trs_coll_ip_addr_len, tvb, offset, 1, ENC_BIG_ENDIAN, &ev_len);
    offset++;
    /*(q+2) to r IP Address of Trace Collection Entity */
    if (ev_len == 4) {
        proto_tree_add_item(tree, hf_gtpv2_trs_coll_ipv4_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
    }

    if (ev_len == 16) {
        proto_tree_add_item(tree, hf_gtpv2_trs_coll_ipv6_addr, tvb, offset, 16, ENC_NA);
    }
}

/* 8.137 Monitoring Event Extension Information */
static void
dissect_gtpv2_ie_mon_event_ext_inf(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    int offset = 0;
    bool lrtp;
    bool srie;
    uint32_t scef_id_len;

    /* Octet 5  Bit 8-3 Spare Bit 2 SRIE Bit 1 LRTP */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset, 6, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_boolean(tree, hf_gtpv2_mon_event_ext_inf_srie, tvb, offset, 1, ENC_BIG_ENDIAN, &srie);
    proto_tree_add_item_ret_boolean(tree, hf_gtpv2_mon_event_ext_inf_lrtp, tvb, offset, 1, ENC_BIG_ENDIAN, &lrtp);
    offset++;
    /* Octet 6 to 9 SCEF Reference ID */
    proto_tree_add_item(tree, hf_gtpv2_mon_event_ext_inf_scef_reference_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* Octet 10 Length of SCEF ID */
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_mon_event_ext_inf_scef_id_length, tvb, offset, 1, ENC_BIG_ENDIAN, &scef_id_len);
    offset++;
    /* Octet 11 to k SCEF ID */
    proto_tree_add_item(tree, hf_gtpv2_mon_event_ext_inf_scef_id, tvb, offset, scef_id_len, ENC_UTF_8);
    offset = offset + scef_id_len;
    if (lrtp) {
        proto_tree_add_item(tree, hf_gtpv2_mon_event_ext_inf_remain_min_period_loc_report_type, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (srie) {
        proto_tree_add_item(tree, hf_gtpv2_mon_event_ext_inf_scef_reference_id_ext, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if(offset < length){
        proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, length- offset);
    }
}

/* 207 Additional RRM Policy Index Fixed Length / 8.138 */
static void
dissect_gtpv2_ie_additional_rrm_policy_index(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, proto_item* item, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    uint32_t rrm_policy_index;

    /*5 to 8 Additional RRM Policy Index, The ARPI is encoded as Unsigned32 binary integer values.*/
    proto_tree_add_item_ret_uint(tree, hf_gtpv2_additional_rrm_policy_index, tvb, 0, 4, ENC_BIG_ENDIAN, &rrm_policy_index);
    proto_item_append_text(item, "%u", rrm_policy_index);
}

/* 208 V2X Context Extendable / 8.139 */
static void
dissect_gtpv2_ie_v2x_context(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}

/* 209 PC5 QoS Parameters Extendable / 8.140 */
static void
dissect_gtpv2_ie_pc5_qos_parameters(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}

/* 210 Services Authorized Extendable / 8.141 */
static void
dissect_gtpv2_ie_services_authorized(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}

/* 211 Bit Rate Extendable / 8.142 */
static void
dissect_gtpv2_ie_bit_rate(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}

/* 212 PC5 QoS Flow Extendable / 8.143 */
static void
dissect_gtpv2_ie_pc5_qos_flow(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}

/* 213 SGi PtP Tunnel Address Extendable / 8.144 */
static void
dissect_gtpv2_ie_sgi_ptp_tunnel_address(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 0, length);
}

/* 214 PGW Change Info Extendable / 8.145 */
static void
dissect_gtpv2_ie_pgw_change_info(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, proto_item* item, uint16_t length, uint8_t message_type, uint8_t instance _U_, session_args_t* args)
{
    int         offset = 0;
    proto_tree *grouped_tree;
    tvbuff_t   *new_tvb;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(item, ett_gtpv2_PGW_change_info);
    new_tvb = tvb_new_subset_length(tvb, offset, length);

    dissect_gtpv2_ie_common(new_tvb, pinfo, grouped_tree, offset, message_type, args, GTPV2_IE_PGW_CHANGE_INFO);
}

/* 215 PGW FQDN Extendable / 8.146 */
static void
dissect_gtpv2_ie_pgw_fqdn(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    int offset = 0;
    offset = decode_gtpv2_fqdn(tvb, pinfo, tree, item, offset, length);

    if(offset < length){
        proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, offset, length- offset);
    }
}

/* 216 Group Id / 8.147 */
static void
dissect_gtpv2_ie_group_id(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, proto_item* item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_group_id, tvb, 0, length, ENC_UTF_8);
}

/* 217 PSCell Id / 8.148 */
static void
dissect_gtpv2_ie_pscell_id(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item _U_, uint16_t length _U_, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    int offset = 0;

    dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_NONE, true);
    offset += 3;
    proto_tree_add_item(tree, hf_gtpv2_ie_pscell_id_spare, tvb, offset, 5, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_ie_pscell_id_nr_cgi, tvb, offset, 5, ENC_BIG_ENDIAN);

}

/* 218 UP Security Policy / 8.149 */
static const value_string gtpv2_up_ip_policy_vals[] = {
    {0, "User Plane Integrity protection with EPS is not needed"},
    {1, "User Plane Integrity protection with EPS is preferred"},
    {2, "User Plane Integrity protection with EPS is required"},
    {3, "Spare"},
    {0, NULL}
};

static void
dissect_gtpv2_ie_up_security_policy(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item _U_, uint16_t length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_ie_up_security_policy_spare, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_ie_up_security_policy_up_ip_policy, tvb, 0, 1, ENC_BIG_ENDIAN);
    if (length > 2) {
        proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 1, length - 2);
    }
}

/* 219 Alternative IMSI / 8.150 */
static void
dissect_gtpv2_ie_alternative_imsi(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item, uint16_t length, uint8_t message_type, uint8_t instance, session_args_t* args)
{
    /*
     * TS 29.274 V18.4.0 says:
     * Alternative IMSI is in the form of an IMSI as defined in 3GPP TS 23.003.
     */
    dissect_gtpv2_imsi(tvb, pinfo, tree, item, length, message_type, instance, args);
}

/* 220 NF Instance ID / 8.151 */
static void
dissect_gtpv2_ie_nf_instance_id(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, proto_item* item _U_, uint16_t _U_ length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    /*
     *  String uniquely identifying a NF instance. The format of the NF Instance ID shall be a
     *  Universally Unique Identifier (UUID) version 4, as described in IETF RFC 4122 [15]. The
     *  hexadecimal letters should be formatted as lower-case characters by the sender, and they
     *  shall be handled as case-insensitive by the receiver.
     *
     *  Example: "4ace9d34-2c69-4f99-92d5-a73a3fe8e23b"
     */
    proto_tree_add_item(tree, hf_gtpv2_nf_instance_id_nf_instance_id, tvb, 0, 36, ENC_BIG_ENDIAN);
}

/* 221 Timer in Seconds / 8.152 */
static void
dissect_gtpv2_timer_in_seconds(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, proto_item* item _U_, uint16_t _U_ length, uint8_t message_type _U_, uint8_t instance _U_, session_args_t* args _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_nf_timer_in_seconds_timer_value, tvb, 0, 3, ENC_BIG_ENDIAN);
    if (length > 4) {
        proto_tree_add_expert(tree, pinfo, &ei_gtpv2_ie_data_not_dissected, tvb, 3, length - 4);
    }
}

/* Table 8.1-1: Information Element types for GTPv2 */

typedef struct _gtpv2_ie {
    int ie_type;
    void (*decode) (tvbuff_t *, packet_info *, proto_tree *, proto_item *, uint16_t, uint8_t, uint8_t, session_args_t *);
} gtpv2_ie_t;

static const gtpv2_ie_t gtpv2_ies[] = {
    {GTPV2_IE_IMSI, dissect_gtpv2_imsi},                                   /* 1, Internal Mobile Subscriber Identity (IMSI) */
    {GTPV2_IE_CAUSE, dissect_gtpv2_cause},                                 /* 2, Cause (without embedded offending IE) 8.4 */
    {GTPV2_REC_REST_CNT, dissect_gtpv2_recovery},                          /* 3, Recovery (Restart Counter) 8.5 */
                                                                           /* 4-50 Reserved for S101 interface Extendable / See 3GPP TS 29.276 [14] */
    /*Start SRVCC Messages 3GPP TS 29.280 */
    {GTPV2_IE_STN_SR, dissect_gtpv2_stn_sr},                               /* 51 STN-SR */
    {GTPV2_IE_SRC_TGT_TRANS_CON, dissect_gtpv2_src_tgt_trans_con},         /* 52 Source to Target Transparent Container */
    {GTPV2_IE_TGT_SRC_TRANS_CON , dissect_gtpv2_tgt_src_trans_con},        /* 53 Target to Source Transparent Container */
    {GTPV2_IE_MM_CON_EUTRAN_SRVCC, dissect_gtpv2_mm_con_eutran_srvcc},     /* 54 MM Context for E-UTRAN SRVCC */
    {GTPV2_IE_MM_CON_UTRAN_SRVCC, dissect_gtpv2_mm_con_utran_srvcc},       /* 55 MM Context for UTRAN SRVCC */
    {GTPV2_IE_SRVCC_CAUSE, dissect_gtpv2_srvcc_cause},                     /* 56 SRVCC Cause */
    {GTPV2_IE_TGT_RNC_ID, dissect_gtpv2_tgt_rnc_id},                       /* 57 Target RNC ID */
    {GTPV2_IE_TGT_GLOGAL_CELL_ID, dissect_gtpv2_tgt_global_cell_id},       /* 58 Target Global Cell ID */
    {GTPV2_IE_TEID_C, dissect_gtpv2_teid_c},                               /* 59 TEID-C */
    {GTPV2_IE_SV_FLAGS, dissect_gtpv2_sv_flags},                           /* 60 Sv Flags */
    {GTPV2_IE_SAI, dissect_gtpv2_sai},                                     /* 61 Service Area Identifier */
    {GTPV2_IE_MM_CTX_FOR_CS_TO_PS_SRVCC, dissect_gtpv2_mm_ctx_for_cs_to_ps_srvcc },  /* 62 Service Area Identifier */
                                                                           /* 61-70 Reserved for Sv interface Extendable / See 3GPP TS 29.280 [15] */
    {GTPV2_APN, dissect_gtpv2_apn},                                        /* 71, Access Point Name (APN) 8.6 */
    {GTPV2_AMBR, dissect_gtpv2_ambr},                                      /* 72, Aggregate Maximum Bit Rate (AMBR) */
    {GTPV2_EBI, dissect_gtpv2_ebi},                                        /* 73, EPS Bearer ID (EBI)  8.8 */
    {GTPV2_IP_ADDRESS, dissect_gtpv2_ip_address},                          /* 74, IP Address */
    {GTPV2_MEI, dissect_gtpv2_mei},                                        /* 74, Mobile Equipment Identity */
    {GTPV2_IE_MSISDN, dissect_gtpv2_msisdn},                               /* 76, MSISDN 8.11 */
    {GTPV2_INDICATION, dissect_gtpv2_ind},                                 /* 77 Indication 8.12 */
    {GTPV2_PCO, dissect_gtpv2_pco},                                        /* 78 Protocol Configuration Options (PCO) 8.13 */
    {GTPV2_PAA, dissect_gtpv2_paa},                                        /* 79 PDN Address Allocation (PAA) 8.14 */
    {GTPV2_BEARER_QOS, dissect_gtpv2_bearer_qos},                          /* 80 Bearer Level Quality of Service (Bearer QoS) 8.15 */
    {GTPV2_IE_FLOW_QOS, dissect_gtpv2_flow_qos},                           /* 81 Flow Quality of Service (Flow QoS) 8.16 */
    {GTPV2_IE_RAT_TYPE, dissect_gtpv2_rat_type},                           /* 82, RAT Type  8.17 */
    {GTPV2_IE_SERV_NET, dissect_gtpv2_serv_net},                           /* 83, Serving Network 8.18 */
    {GTPV2_IE_BEARER_TFT, dissect_gtpv2_bearer_tft},                       /* 84, Bearer TFT 8.19 */
    {GTPV2_IE_TAD, dissect_gtpv2_tad},                                     /* 85, Traffic Aggregate Description 8.20 */
    {GTPV2_IE_ULI, dissect_gtpv2_uli},                                     /* 86, User Location Info (ULI) 8.22 */
    {GTPV2_IE_F_TEID, dissect_gtpv2_f_teid},                               /* 87, Fully Qualified Tunnel Endpoint Identifier (F-TEID) 8.23 */
    {GTPV2_IE_TMSI, dissect_gtpv2_tmsi},                                   /* 88, TMSI 8.23 */
    {GTPV2_IE_GLOBAL_CNID, dissect_gtpv2_g_cn_id},                         /* 89, Global CN-Id 8.25 */
    {GTPV2_IE_S103PDF, dissect_gtpv2_s103pdf},                             /* 90, S103 PDN Data Forwarding Info (S103PDF) 8.25 */
    {GTPV2_IE_S1UDF, dissect_gtpv2_s1udf},                                 /* 91, S1-U Data Forwarding (S1UDF) 8.26 */
    {GTPV2_IE_DEL_VAL, dissect_gtpv2_delay_value},                         /* 92, Delay Value 8.29 */
    {GTPV2_IE_BEARER_CTX, dissect_gtpv2_bearer_ctx},                       /* 93, Bearer Context  8.31 */
    {GTPV2_IE_CHAR_ID, dissect_gtpv2_charging_id},                         /* 94, Charging Id */
    {GTPV2_IE_CHAR_CHAR, dissect_gtpv2_char_char},                         /* 95 Charging Characteristic */
    {GTPV2_IE_TRA_INFO, dissect_gtpv2_tra_info},                           /* 96, Trace Information 8.31 */
    {GTPV2_BEARER_FLAG, dissect_gtpv2_bearer_flag},                        /* 97, Bearer Flag */
                                                                           /* 98, Void 8.33 */
    {GTPV2_IE_PDN_TYPE, dissect_gtpv2_pdn_type},                           /* 99, PDN Type */
    {GTPV2_IE_PTI, dissect_gtpv2_pti},                                     /* 100, Procedure Transaction Id */
    {GTPV2_IE_DRX_PARAM, dissect_gtpv2_drx_param},                         /* 101, DRX Parameter 8.36 */
    {GTPV2_IE_UE_NET_CAPABILITY, dissect_gtpv2_ue_net_capability},         /* 102, UE network capability 8.37 */
    {GTPV2_IE_MM_CONTEXT_GSM_T, dissect_gtpv2_mm_context_gsm_t},           /* 103, MM Context 8.38 GSM Key and Triplets */
    {GTPV2_IE_MM_CONTEXT_UTMS_CQ, dissect_gtpv2_mm_context_utms_cq},       /* 104, MM Context 8.38 */
    {GTPV2_IE_MM_CONTEXT_GSM_CQ, dissect_gtpv2_mm_context_gsm_cq},         /* 105, MM Context 8.38 */
    {GTPV2_IE_MM_CONTEXT_UTMS_Q, dissect_gtpv2_mm_context_utms_q},         /* 106, MM Context 8.38 */
    {GTPV2_IE_MM_CONTEXT_EPS_QQ, dissect_gtpv2_mm_context_eps_qq},         /* 107, MM Context 8.38 */
    {GTPV2_IE_MM_CONTEXT_UTMS_QQ, dissect_gtpv2_mm_context_utms_qq},       /* 108, MM Context 8.38 */
    {GTPV2_IE_PDN_CONNECTION, dissect_gtpv2_PDN_conn},                     /* 109, PDN Connection */
    {GTPV2_IE_PDN_NUMBERS, dissect_gtpv2_pdn_numbers},                     /* 110, PDN Numbers 8.40 */
    {GTPV2_IE_P_TMSI, dissect_gtpv2_p_tmsi},                               /* 111, P-TMSI 8.41 */
    {GTPV2_IE_P_TMSI_SIG, dissect_gtpv2_p_tmsi_sig},                       /* 112, P-TMSI Signature 8.42 */
    {GTPV2_IE_HOP_COUNTER, dissect_gtpv2_hop_counter},                     /* 113, Hop Counter 8.43 */
    {GTPV2_IE_UE_TIME_ZONE, dissect_gtpv2_ue_time_zone},                   /* 114, UE Time Zone */
    {GTPV2_IE_TRACE_REFERENCE, dissect_gtpv2_trace_reference},             /* 115, Trace Reference 8.45 */
    {GTPV2_IE_COMPLETE_REQUEST_MSG, dissect_complete_request_msg},         /* 116, Complete Request message 8.46 */
    {GTPV2_IE_GUTI, dissect_gtpv2_guti},                                   /* 117, GUTI 8.47 */
    {GTPV2_IE_F_CONTAINER, dissect_gtpv2_F_container},                     /* 118, Fully Qualified Container (F-Container) */
    {GTPV2_IE_F_CAUSE, dissect_gtpv2_F_cause},                             /* 119, Fully Qualified Cause (F-Cause) */
    {GTPV2_IE_PLMN_ID, dissect_gtpv2_plmn_id},                             /* 120, PLMN ID 8.50 */
    {GTPV2_IE_TARGET_ID, dissect_gtpv2_target_id},                         /* 121, Target Identification */
                                                                           /* 122, Void 8.52 */
    {GTPV2_IE_PKT_FLOW_ID, dissect_gtpv2_pkt_flow_id},                     /* 123, Packet Flow ID 8.53 */
    {GTPV2_IE_RAB_CONTEXT, dissect_gtpv2_rab_context},                     /* 124, RAB Context 8.54 */
    {GTPV2_IE_S_RNC_PDCP_CTX_INFO, dissect_gtpv2_s_rnc_pdcp_ctx_info},     /* 125, Source RNC PDCP context info 8.55 */
    {GTPV2_IE_PORT_NR, dissect_port_nr},                                   /* 126, Port Number 8.56 */
    {GTPV2_IE_APN_RESTRICTION, dissect_gtpv2_apn_rest},                    /* 127, APN Restriction */
    {GTPV2_IE_SEL_MODE, dissect_gtpv2_selec_mode},                         /* 128, Selection Mode */
    {GTPV2_IE_SOURCE_IDENT, dissect_gtpv2_source_ident},                   /* 129, Source Identification 8.59 */
    {GTPV2_IE_BEARER_CONTROL_MODE, dissect_gtpv2_bearer_control_mode},     /* 130, Bearer Control Mode */
    {GTPV2_IE_CNG_REP_ACT , dissect_gtpv2_cng_rep_act},                    /* 131, Change Reporting Action 8.61 */
    {GTPV2_IE_FQ_CSID, dissect_gtpv2_fq_csid},                             /* 132, Fully Qualified PDN Connection Set Identifier (FQ-CSID) 8.62 */
    {GTPV2_IE_CHANNEL_NEEDED, dissect_gtpv2_channel_needed},               /* 133, Channel Needed 8.63 */
    {GTPV2_IE_EMLPP_PRI, dissect_gtpv2_emlpp_pri},                         /* 134, eMLPP Priority 8.64 */
    {GTPV2_IE_NODE_TYPE , dissect_gtpv2_node_type},                        /* 135, Node Type 8.65 */
    {GTPV2_IE_FQDN, dissect_gtpv2_fqdn},                                   /* 136, 8.66 Fully Qualified Domain Name (FQDN) */
    {GTPV2_IE_TI, dissect_gtpv2_ti},                                       /* 137, 8.68 Transaction Identifier (TI) */
    {GTPV2_IE_MBMS_SESSION_DURATION, dissect_gtpv2_mbms_session_duration}, /* 138, 8.69 MBMS Session Duration */
    {GTPV2_IE_MBMS_SERVICE_AREA, dissect_gtpv2_mbms_service_area},         /* 139, 8.70 MBMS Service Area */
    {GTPV2_IE_MBMS_SESSION_ID, dissect_gtpv2_mbms_session_id},             /* 140, 8.71 MBMS Session Identifier */
    {GTPV2_IE_MBMS_FLOW_ID, dissect_gtpv2_mbms_flow_id},                   /* 141, 8.72 MBMS Flow Identifier */
    {GTPV2_IE_MBMS_IP_MC_DIST, dissect_gtpv2_mbms_ip_mc_dist},             /* 142, 8.73 MBMS IP Multicast Distribution */
    {GTPV2_IE_MBMS_DIST_ACK, dissect_gtpv2_mbms_dist_ack},                 /* 143, 8.74 MBMS Distribution Acknowledge */
    {GTPV2_IE_RFSP_INDEX, dissect_gtpv2_rfsp_index},                       /* 144, 8.77 RFSP Index */
    {GTPV2_IE_UCI, dissect_gtpv2_uci},                                     /* 145, 8.75 User CSG Information (UCI) */
    {GTPV2_IE_CSG_INFO_REP_ACTION, dissect_gtpv2_csg_info_rep_action},     /* 146, 8.76 CSG Information Reporting Action */
    {GTPV2_IE_CSG_ID, dissect_gtpv2_csg_id},                               /* 147, 8.78 CSG ID */
    {GTPV2_IE_CMI, dissect_gtpv2_cmi},                                     /* 148, 8.79 CSG Membership Indication (CMI) */
    {GTPV2_IE_SERVICE_INDICATOR, dissect_gtpv2_service_indicator},         /* 149, 8.80 Service indicator */
    {GTPV2_IE_DETACH_TYPE, dissect_gtpv2_detach_type},                     /* 150, 8.81 Detach Type */
    {GTPV2_IE_LDN, dissect_gtpv2_ldn},                                     /* 151, 8.82 Local Distinguished Name (LDN) */
    {GTPV2_IE_NODE_FEATURES, dissect_gtpv2_node_features},                 /* 152, 8.83 Node Features */
    {GTPV2_IE_MBMS_TIME_TO_DATA_XFER, dissect_gtpv2_mbms_time_to_data_xfer}, /* 153, 8.84 MBMS Time to Data Transfer */
    {GTPV2_IE_THROTTLING, dissect_gtpv2_throttling},                       /* 154, 8.85 Throttling */
    {GTPV2_IE_ARP, dissect_gtpv2_arp},                                     /* 155, 8.86 Allocation/Retention Priority (ARP) */
    {GTPV2_IE_EPC_TIMER, dissect_gtpv2_epc_timer},                         /* 156, 8.87 EPC Timer */
    {GTPV2_IE_SIG_PRIO_IND, dissect_gtpv2_sig_prio_ind},                   /* 157, 8.88 Signalling Priority Indication */
    {GTPV2_IE_TMGI, dissect_gtpv2_tmgi},                                   /* 158, 8.89 Temporary Mobile Group Identity (TMGI) */
    {GTPV2_IE_ADD_MM_CONT_FOR_SRVCC, dissect_gtpv2_add_mm_cont_for_srvcc}, /* 159, 8.90 Additional MM context for SRVCC */
    {GTPV2_IE_ADD_FLAGS_FOR_SRVCC, dissect_gtpv2_add_flags_for_srvcc},     /* 160, 8.91 Additional flags for SRVCC */
    {GTPV2_IE_MMBR, dissect_gtpv2_mmbr},                                   /* 161, 8.92 Max MBR/APN-AMBR (MMBR) */
    {GTPV2_IE_MDT_CONFIG, dissect_gtpv2_mdt_config},                       /* 162, 8.93 MDT Configuration */
    {GTPV2_IE_APCO, dissect_gtpv2_apco},                                   /* 163, 8.94 Additional Protocol Configuration Options (APCO) */
    {GTPV2_IE_ABS_MBMS_DATA_TF_TIME, dissect_gtpv2_abs_mbms_data_tf_time}, /* 164, 8.95 Absolute Time of MBMS Data Transfer */
    {GTPV2_IE_HENB_INFO_REPORT, dissect_gtpv2_henb_info_report},           /* 165, 8.96 H(e)NB Information Reporting */
    {GTPV2_IE_IP4CP, dissect_gtpv2_ip4cp},                                 /* 166, 8.97 IPv4 Configuration Parameters (IPv4CP) */
    {GTPV2_IE_CHANGE_TO_REPORT_FLAGS, dissect_gtpv2_change_report_flags},  /* 167, 8.98 Change to Report Flags */
    {GTPV2_IE_ACTION_INDICATION, dissect_gtpv2_action_indication},         /* 168, 8.99 Action Indication */
    {GTPV2_IE_TWAN_IDENTIFIER, dissect_gtpv2_twan_identifier},             /* 169, 8.100 TWAN Identifier */
    {GTPV2_IE_ULI_TIMESTAMP, dissect_gtpv2_uli_timestamp},                 /* 170, 8.101 ULI Timestamp */
    {GTPV2_IE_MBMS_FLAGS, dissect_gtpv2_mbms_flags},                       /* 171, 8.102 MBMS Flags */
    {GTPV2_IE_RAN_NAS_CAUSE, dissect_gtpv2_ran_nas_cause},                 /* 172, 8.103 RAN/NAS Cause */
    {GTPV2_IE_CN_OP_SEL_ENT, dissect_gtpv2_cn_operator_selection_entity},  /* 173, 8.104 CN Operator Selection Entity */
    {GTPV2_IE_TRUST_WLAN_MODE_IND, dissect_gtpv2_trust_wlan_mode_ind},     /* 174, 8.105 Trusted WLAN Mode Indication */
    {GTPV2_IE_NODE_NUMBER, dissect_gtpv2_node_number},                     /* 175, 8.106 Node Number */
    {GTPV2_IE_NODE_IDENTIFIER, dissect_gtpv2_node_identifier},             /* 176, 8.107 Node Identifier */
    {GTPV2_IE_PRES_REP_AREA_ACT, dissect_gtpv2_pres_rep_area_action},      /* 177, 8.108 Presence Reporting Area Action */
    {GTPV2_IE_PRES_REP_AREA_INF, dissect_gtpv2_pres_rep_area_information}, /* 178, 8.109 Presence Reporting Area Information */
    {GTPV2_IE_TWAN_ID_TS, dissect_gtpv2_twan_identifier_timestamp},        /* 179, 8.110 TWAN Identifier Timestamp */
    {GTPV2_IE_OVERLOAD_CONTROL_INF, dissect_gtpv2_overload_control_inf},   /* 180, 8.111 Overload Control Information */
    {GTPV2_IE_LOAD_CONTROL_INF, dissect_gtpv2_load_control_inf},           /* 181, 8.112 Load Control Information */
    {GTPV2_IE_METRIC, dissect_gtpv2_metric},                               /* 182, 8.113 Metric */
    {GTPV2_IE_SEQ_NO, dissect_gtpv2_seq_no},                               /* 183, 8.114 Sequence Number */
    {GTPV2_IE_APN_AND_REL_CAP, dissect_gtpv2_apn_and_relative_capacity},   /* 184, 8.115 APN and Relative Capacity */
    {GTPV2_IE_WLAN_OFFLOADABILITY_IND,dissect_gtpv2_unknown },             /* 185, 8.116 WLAN Offloadability Indication */

    {GTPV2_IE_PAGING_AND_SERVICE_INF, dissect_gtpv2_paging_and_service_inf}, /* 186, 8.117 Paging and Service Information */
    {GTPV2_IE_INTEGER_NUMBER, dissect_gtpv2_integer_number},                 /* 187, 8.118 Integer Number */
    {GTPV2_IE_MILLISECOND_TS, dissect_gtpv2_ms_ts},                          /* 188, 8.119 Millisecond Time Stamp */
    {GTPV2_IE_MON_EVENT_INF, dissect_gtpv2_mon_event_inf},                   /* 189, 8.120 Monitoring Event Information */
                                                                             /* 190, 8.121 ECGI List */
                                                                             /* 191, 8.122 Remote UE Context */
                                                                             /* 192, 8.123 Remote User ID */
                                                                             /* 193, 8.124 Remote UE IP Information */
    {GTPV2_IE_CIOT_OPT_SUPPORT_IND, dissect_gtpv2_ciot_opt_support_ind},     /* 194, 8.125 CIoT Optimizations Support Indication */
    {GTPV2_IE_SCEF_PDN_CONNECTION , dissect_gtpv2_scef_pdn_connection },     /* 195, 8.126 SCEF PDN Connection */
    {GTPV2_IE_HEADER_COMP_CONF, dissect_gtpv2_header_comp_comf},             /* 196, 8.127 Header Compression Configuration */
    {GTPV2_IE_EXTENDED_PCO, dissect_gtpv2_pco},                              /* 197, 8.128 Extended Protocol Configuration Options (ePCO) */
    {GTPV2_IE_SERV_PLMN_RATE_CONTROL, dissect_gtpv2_serv_plmn_rate_control}, /* 198, 8.129 Serving PLMN Rate Control */
    {GTPV2_IE_COUNTER, dissect_gtpv2_counter},                               /* 199, 8.130 Counter */
    {GTPV2_IE_MAPPED_UE_USAGE_TYPE, dissect_gtpv2_mapped_ue_usage_type },    /* 199, 8.131 Mapped UE Usage Type */
    {GTPV2_IE_SECONDARY_RAT_USAGE_DATA_REPORT, dissect_gtpv2_secondary_rat_usage_data_report}, /* 201, 8.132 Secondary RAT Usage Data Report */
    {GTPV2_IE_UP_FUNC_SEL_INDI_FLG, dissect_gtpv2_up_func_slec_indic_flg },  /* 202, 8.133 UP Function Selection Indication Flags */
    {GTPV2_IE_MAX_PKT_LOSS_RTE, dissect_gtpv2_max_pkt_loss_rte },            /* 203, 8.134 Maximum Packet Loss Rate */
    {GTPV2_IE_APN_RTE_CNTRL_STATUS, dissect_gtpv2_apn_rte_cntrl_status },    /* 204, 8.135 APN Rate Control Status */
    {GTPV2_IE_EXT_TRS_INF, dissect_gtpv2_ext_trs_inf },                      /* 205, 8.136 Extended Trace Information */
    {GTPV2_IE_MON_EVENT_EXT_INF, dissect_gtpv2_ie_mon_event_ext_inf },       /* 206, 8.137 Monitoring Event Extension Information */
    {GTPV2_IE_ADDITIONAL_RRM_POLICY_INDEX, dissect_gtpv2_ie_additional_rrm_policy_index },  /* 207 Additional RRM Policy Index Fixed Length / 8.138 */
    {GTPV2_IE_V2X_CONTEXT, dissect_gtpv2_ie_v2x_context },                   /* 208 V2X Context Extendable / 8.139 */
    {GTPV2_IE_PC5_QOS_PARAMETERS, dissect_gtpv2_ie_pc5_qos_parameters },     /* 209 PC5 QoS Parameters Extendable / 8.140 */
    {GTPV2_IE_SERVICES_AUTHORIZED, dissect_gtpv2_ie_services_authorized },   /* 210 Services Authorized Extendable / 8.141 */
    {GTPV2_IE_BIT_RATE, dissect_gtpv2_ie_bit_rate },                         /* 211 Bit Rate Extendable / 8.142 */
    {GTPV2_IE_PC5_QOS_FLOW, dissect_gtpv2_ie_pc5_qos_flow },                 /* 212 PC5 QoS Flow Extendable / 8.143 */
    {GTPV2_IE_SGI_PTP_TUNNEL_ADDRESS, dissect_gtpv2_ie_sgi_ptp_tunnel_address }, /* 213 SGi PtP Tunnel Address Extendable / 8.144 */
    {GTPV2_IE_PGW_CHANGE_INFO, dissect_gtpv2_ie_pgw_change_info },           /* 214 PGW Change Info Extendable / 8.145 */
    {GTPV2_IE_PGW_FQDN, dissect_gtpv2_ie_pgw_fqdn },                         /* 215 PGW FQDN Extendable / 8.146 */
    {GTPV2_IE_GROUP_ID, dissect_gtpv2_ie_group_id },                         /* 216 Group Id Variable Length / 8.147 */
    {GTPV2_IE_PSCELL_ID, dissect_gtpv2_ie_pscell_id },                       /* 217 PSCell Id Fixed Length / 8.148 */
    {GTPV2_IE_UP_SECURITY_POLICY, dissect_gtpv2_ie_up_security_policy },     /* 218 UP Security Policy Extendable / 8.149 */
    {GTPV2_IE_ALT_IMSI, dissect_gtpv2_ie_alternative_imsi },                 /* 219 Alternative IMSI Variable Length / 8.150 */
    {GTPV2_IE_NF_INSTANCE_ID, dissect_gtpv2_ie_nf_instance_id },              /* 220 NF Instance ID*/
    {GTPV2_IE_TIMER_IN_SECONDS, dissect_gtpv2_timer_in_seconds },             /* 221 Timer in Seconds*/
    {GTPV2_IE_PRIVATE_EXT, dissect_gtpv2_private_ext },
    {0, dissect_gtpv2_unknown}
};

static gtpv2_msg_hash_t *
gtpv2_match_response(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int seq_nr, unsigned msgtype, gtpv2_conv_info_t *gtpv2_info, uint8_t last_cause)
{
    gtpv2_msg_hash_t   gcr, *gcrp = NULL;
    uint32_t session;

    gcr.seq_nr = seq_nr;
    gcr.req_time = pinfo->abs_ts;

    switch (msgtype) {
    case GTPV2_CREATE_SESSION_REQUEST:
    case GTPV2_CREATE_BEARER_REQUEST:
    case GTPV2_UPDATE_BEARER_REQUEST:
    case GTPV2_MODIFY_BEARER_REQUEST:
    case GTPV2_DELETE_BEARER_REQUEST:
    case GTPV2_DELETE_SESSION_REQUEST:
    case GTPV2_MODIFY_BEARER_COMMAND:
    case GTPV2_DELETE_BEARER_COMMAND:
    case GTPV2_BEARER_RESOURCE_COMMAND:
    case GTPV2_SRVCC_PS_TO_CS_REQUEST:
    case GTPV2_SRVCC_PS_TO_CS_COMPLETE_NOTIFICATION:
    case GTPV2_SRVCC_PS_TO_CS_CANCEL_NOTIFICATION:
    case GTPV2_CONTEXT_REQUEST:
    case GTPV2_FORWARD_RELOCATION_REQ:
    case GTPV2_RELOCATION_CANCEL_REQUEST:
    case GTPV2_FORWARD_CTX_NOTIFICATION:
    case GTPV2_FORWARD_RELOCATION_COMPLETE_NOTIFICATION:
    case GTPV2_RELEASE_ACCESS_BEARERS_REQUEST:
    case GTPV2_DL_DATA_NOTIF:
        gcr.is_request = true;
        gcr.req_frame = pinfo->num;
        gcr.rep_frame = 0;
        break;
    case GTPV2_CREATE_SESSION_RESPONSE:
    case GTPV2_CREATE_BEARER_RESPONSE:
    case GTPV2_UPDATE_BEARER_RESPONSE:
    case GTPV2_MODIFY_BEARER_RESPONSE:
    case GTPV2_DELETE_BEARER_RESPONSE:
    case GTPV2_DELETE_SESSION_RESPONSE:
    case GTPV2_MODIFY_BEARER_FAILURE_INDICATION:
    case GTPV2_DELETE_BEARER_FAILURE_INDICATION:
    case GTPV2_BEARER_RESOURCE_FAILURE_INDICATION:
    case GTPV2_SRVCC_PS_TO_CS_RESPONSE:
    case GTPV2_SRVCC_PS_TO_CS_COMPLETE_ACKNOWLEDGE:
    case GTPV2_SRVCC_PS_TO_CS_CANCEL_ACKNOWLEDGE:
    case GTPV2_CONTEXT_RESPONSE:
    case GTPV2_FORWARD_RELOCATION_RESP:
    case GTPV2_RELOCATION_CANCEL_RESPONSE:
    case GTPV2_FORWARD_CTX_ACKNOWLEDGE:
    case GTPV2_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE:
    case GTPV2_RELEASE_ACCESS_BEARERS_RESPONSE:
    case GTPV2_DL_DATA_NOTIF_ACK:

        gcr.is_request = false;
        gcr.req_frame = 0;
        gcr.rep_frame = pinfo->num;
        break;
    default:
        gcr.is_request = false;
        gcr.req_frame = 0;
        gcr.rep_frame = 0;
        break;
    }

    gcrp = (gtpv2_msg_hash_t *)wmem_map_lookup(gtpv2_info->matched, &gcr);

    if (gcrp) {
        gcrp->is_request = gcr.is_request;
    } else {
        /*no match, let's try to make one*/
        switch (msgtype) {
        case GTPV2_CREATE_SESSION_REQUEST:
        case GTPV2_CREATE_BEARER_REQUEST:
        case GTPV2_UPDATE_BEARER_REQUEST:
        case GTPV2_MODIFY_BEARER_REQUEST:
        case GTPV2_DELETE_BEARER_REQUEST:
        case GTPV2_DELETE_SESSION_REQUEST:
        case GTPV2_MODIFY_BEARER_COMMAND:
        case GTPV2_DELETE_BEARER_COMMAND:
        case GTPV2_BEARER_RESOURCE_COMMAND:
        case GTPV2_SRVCC_PS_TO_CS_REQUEST:
        case GTPV2_SRVCC_PS_TO_CS_COMPLETE_NOTIFICATION:
        case GTPV2_SRVCC_PS_TO_CS_CANCEL_NOTIFICATION:
        case GTPV2_CONTEXT_REQUEST:
        case GTPV2_FORWARD_RELOCATION_REQ:
        case GTPV2_RELOCATION_CANCEL_REQUEST:
        case GTPV2_FORWARD_CTX_NOTIFICATION:
        case GTPV2_FORWARD_RELOCATION_COMPLETE_NOTIFICATION:
        case GTPV2_RELEASE_ACCESS_BEARERS_REQUEST:
        case GTPV2_DL_DATA_NOTIF:

            gcr.seq_nr = seq_nr;

            gcrp = (gtpv2_msg_hash_t *)wmem_map_lookup(gtpv2_info->unmatched, &gcr);
            if (gcrp) {
                wmem_map_remove(gtpv2_info->unmatched, gcrp);
            }
            /* if we can't reuse the old one, grab a new chunk */
            if (!gcrp) {
                gcrp = wmem_new(wmem_file_scope(), gtpv2_msg_hash_t);
            }
            gcrp->seq_nr = seq_nr;
            gcrp->req_frame = pinfo->num;
            gcrp->req_time = pinfo->abs_ts;
            gcrp->rep_frame = 0;
            gcrp->msgtype = msgtype;
            gcrp->is_request = true;
            wmem_map_insert(gtpv2_info->unmatched, gcrp, gcrp);
            return NULL;
        case GTPV2_CREATE_SESSION_RESPONSE:
        case GTPV2_CREATE_BEARER_RESPONSE:
        case GTPV2_UPDATE_BEARER_RESPONSE:
        case GTPV2_MODIFY_BEARER_RESPONSE:
        case GTPV2_DELETE_BEARER_RESPONSE:
        case GTPV2_DELETE_SESSION_RESPONSE:
        case GTPV2_MODIFY_BEARER_FAILURE_INDICATION:
        case GTPV2_DELETE_BEARER_FAILURE_INDICATION:
        case GTPV2_BEARER_RESOURCE_FAILURE_INDICATION:
        case GTPV2_SRVCC_PS_TO_CS_RESPONSE:
        case GTPV2_SRVCC_PS_TO_CS_COMPLETE_ACKNOWLEDGE:
        case GTPV2_SRVCC_PS_TO_CS_CANCEL_ACKNOWLEDGE:
        case GTPV2_CONTEXT_RESPONSE:
        case GTPV2_FORWARD_RELOCATION_RESP:
        case GTPV2_RELOCATION_CANCEL_RESPONSE:
        case GTPV2_FORWARD_CTX_ACKNOWLEDGE:
        case GTPV2_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE:
        case GTPV2_RELEASE_ACCESS_BEARERS_RESPONSE:
        case GTPV2_DL_DATA_NOTIF_ACK:

            gcr.seq_nr = seq_nr;
            gcrp = (gtpv2_msg_hash_t *)wmem_map_lookup(gtpv2_info->unmatched, &gcr);

            if (gcrp) {
                if (!gcrp->rep_frame) {
                    wmem_map_remove(gtpv2_info->unmatched, gcrp);
                    gcrp->rep_frame = pinfo->num;
                    gcrp->is_request = false;
                    wmem_map_insert(gtpv2_info->matched, gcrp, gcrp);
                }
            }
            break;
        default:
            break;
        }
    }

    /* we have found a match */
    if (gcrp) {
        proto_item *it;

        if (gcrp->is_request) {
            it = proto_tree_add_uint(tree, hf_gtpv2_response_in, tvb, 0, 0, gcrp->rep_frame);
            proto_item_set_generated(it);
        } else {
            nstime_t ns;

            it = proto_tree_add_uint(tree, hf_gtpv2_response_to, tvb, 0, 0, gcrp->req_frame);
            proto_item_set_generated(it);
            nstime_delta(&ns, &pinfo->abs_ts, &gcrp->req_time);
            it = proto_tree_add_time(tree, hf_gtpv2_response_time, tvb, 0, 0, &ns);
            proto_item_set_generated(it);
            if (g_gtp_session && !PINFO_FD_VISITED(pinfo)) {
                /* GTP session */
                /* If it's not already in the list */
                session = GPOINTER_TO_UINT(wmem_map_lookup(session_table, GUINT_TO_POINTER(pinfo->num)));
                if (!session) {
                    session = GPOINTER_TO_UINT(wmem_map_lookup(session_table, GUINT_TO_POINTER(gcrp->req_frame)));
                    if (session) {
                        add_gtp_session(pinfo->num, session);
                    }
                }

                if (!is_cause_accepted(last_cause, 2)){
                    /* If the cause is not accepted then we have to remove all the session information about its corresponding request */
                    remove_frame_info(gcrp->req_frame);
                }
            }
        }
    }
    return gcrp;
}

static void
track_gtpv2_session(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gtpv2_hdr_t * gtpv2_hdr, session_args_t * args)
{
    uint32_t session, frame_teid_cp;
    proto_item *it;
    char *imsi = NULL;

    /* GTP session */
    if (!PINFO_FD_VISITED(pinfo)) {
        /* If the message does not have any session ID */
        session = GPOINTER_TO_UINT(wmem_map_lookup(session_table, GUINT_TO_POINTER(pinfo->num)));
        if (!session) {
            /* If the message is not a CSESRES, CSESREQ, UBEAREQ, UBEARES, CBEAREQ, CBEARES, MBEAREQ or MBEARES then we remove its information from teid and ip lists */
            if ((gtpv2_hdr->message != GTPV2_CREATE_SESSION_RESPONSE && gtpv2_hdr->message != GTPV2_CREATE_SESSION_REQUEST && gtpv2_hdr->message != GTPV2_UPDATE_BEARER_RESPONSE
                && gtpv2_hdr->message != GTPV2_UPDATE_BEARER_REQUEST && gtpv2_hdr->message != GTPV2_CREATE_BEARER_REQUEST && gtpv2_hdr->message != GTPV2_CREATE_BEARER_RESPONSE
                && gtpv2_hdr->message != GTPV2_MODIFY_BEARER_REQUEST && gtpv2_hdr->message != GTPV2_MODIFY_BEARER_RESPONSE)) {
                /* If the lists are not empty*/
                if (wmem_list_count(args->teid_list) && wmem_list_count(args->ip_list)) {
                    remove_frame_info(pinfo->num);
                }
            }

            if (gtpv2_hdr->message == GTPV2_CREATE_SESSION_REQUEST){
                /* If CPDPCREQ and not already in the list then we create a new session*/
                add_gtp_session(pinfo->num, gtp_session_count);

                if (args->imsi) {
                    imsi = wmem_strdup(wmem_file_scope(), args->imsi);
                    wmem_map_insert(session_imsi, GUINT_TO_POINTER(gtp_session_count++), imsi);
                }
            }
            else if (gtpv2_hdr->message != GTPV2_CREATE_SESSION_RESPONSE) {
                /* We have to check if its teid == teid_cp and ip.dst == gsn_ipv4 from the lists, if that is the case then we have to assign
                the corresponding session ID */
                if ((get_frame(pinfo->dst, (uint32_t)gtpv2_hdr->teid, &frame_teid_cp) == 1)) {
                    /* Then we have to set its session ID */
                    session = GPOINTER_TO_UINT(wmem_map_lookup(session_table, GUINT_TO_POINTER(frame_teid_cp)));
                    if (session) {
                        /* We add the corresponding session to the list so that when a response came we can associate its session ID*/
                        add_gtp_session(pinfo->num, session);

                        if (args->imsi) {
                            imsi = wmem_strdup(wmem_file_scope(), args->imsi);
                            wmem_map_insert(session_imsi, GUINT_TO_POINTER(session), imsi);
                        }
                    }
                }
                else if (gtpv2_hdr->message == GTPV2_MODIFY_BEARER_REQUEST) {
                    /* If MBEAREQ and not already in the list then we create a new session*/
                    add_gtp_session(pinfo->num, gtp_session_count);

                    if (args->imsi) {
                        imsi = wmem_strdup(wmem_file_scope(), args->imsi);
                        wmem_map_insert(session_imsi, GUINT_TO_POINTER(gtp_session_count++), imsi);
                    } else {
                        /* If handover from 5G, look up referenceid from earlier HTTP2 streams */
                        static char to_str_back_buf[32];
                        #define BACK_PTR (&to_str_back_buf[31]) /* pointer to NUL string terminator */

                        char* referenceid = uint_to_str_back(BACK_PTR, (uint32_t)gtpv2_hdr->teid);
                        imsi = http2_get_imsi_from_referenceid(referenceid);
                        if(imsi) {
                            wmem_map_insert(session_imsi, GUINT_TO_POINTER(gtp_session_count++), imsi);
                        }
                    }
                }
            }
        }
    }

    if (tree) {
        session = GPOINTER_TO_UINT(wmem_map_lookup(session_table, GUINT_TO_POINTER(pinfo->num)));
        if (session) {
            it = proto_tree_add_uint(tree, hf_gtpv2_session, tvb, 0, 0, session);
            proto_item_set_generated(it);

            imsi = wmem_map_lookup(session_imsi, GUINT_TO_POINTER(session));
            if (imsi) {
                add_assoc_imsi_item(tvb, tree, imsi);
            }
        }
    }
}

void
dissect_gtpv2_ie_common(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, uint8_t message_type, session_args_t * args, uint8_t parent_ie)
{
    proto_tree *ie_tree;
    proto_item *ti;
    tvbuff_t   *ie_tvb;
    uint8_t     type, instance;
    uint16_t    length;
    int         i, remaining_length, msg_length;
    unsigned    info_elem;
    /*
     * Octets   8   7   6   5       4   3   2   1
     *  1       Type
     *  2-3     Length = n
     *  4       CR          Spare   Instance
     * 5-(n+4)  IE specific data
     */
    msg_length = (int)tvb_reported_length(tvb);
    while (offset < msg_length) {
        /* Get the type and length */
        remaining_length = msg_length - offset;
        if (remaining_length < 3) {
            proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_len_invalid, tvb, offset, remaining_length,
                "Not enough data left for IE and length, %i bytes", remaining_length);
            return;
        }
        type    = tvb_get_uint8(tvb, offset);
        length  = tvb_get_ntohs(tvb, offset + 1);
        remaining_length = remaining_length -4;
        if (remaining_length < length) {
            proto_tree_add_expert_format(tree, pinfo, &ei_gtpv2_ie_len_invalid, tvb, offset+4, remaining_length,
                "Less data left than indicated by length %u, remaining length %i", length, remaining_length);
            /* Octet 1 */
            proto_tree_add_item(tree, hf_gtpv2_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            /*Octet 2 - 3 */
            proto_tree_add_item(tree, hf_gtpv2_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            return;
        }
        ie_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 + length, ett_gtpv2_ies[type], &ti, "%s: ",
                                      val_to_str_ext_const(type, &gtpv2_element_type_vals_ext, "Unknown"));

        /* Octet 1 */
        proto_tree_add_item(ie_tree, hf_gtpv2_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /*Octet 2 - 3 */
        proto_tree_add_item(ie_tree, hf_gtpv2_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* ch8.120 breaks the format described in ch8.2.1 */
        if (type == GTPV2_IE_MON_EVENT_INF) {
            instance = tvb_get_uint8(tvb, offset) & 0x0f;
        } else {
            /* CR Spare Instance Octet 4*/
            proto_tree_add_item(ie_tree, hf_gtpv2_cr, tvb, offset, 1, ENC_BIG_ENDIAN);

            instance = tvb_get_uint8(tvb, offset) & 0x0f;
            proto_tree_add_item(ie_tree, hf_gtpv2_instance, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* Add Info element on IE types with multiple instances in same group */
            if (tree && message_type > 0) {
                /* XXX - This has 250+ entries and should really be a different
                 * data structure, perhaps lazily creating a table. */
                for (info_elem = 0; info_elem < NUM_GTPV2_IE_INFO_ELEM_INSTANCES; info_elem++) {
                    if (gtpv2_information_element_instance_vals[info_elem].message_type == message_type &&
                        gtpv2_information_element_instance_vals[info_elem].parent_ie == parent_ie &&
                        gtpv2_information_element_instance_vals[info_elem].type == type &&
                        gtpv2_information_element_instance_vals[info_elem].instance == instance)
                    {
                        proto_item_append_text(ie_tree, "%s: ", gtpv2_information_element_instance_vals[info_elem].info_element);
                        break;
                    }
                }
            }
            offset++;
        }

        /* TODO: call IE dissector here */
        if (type == GTPV2_IE_RESERVED) {
            /* Treat IE type zero special as type zero is used to end the loop in the else branch */
            expert_add_info(pinfo, ti, &ei_gtpv2_ie);
        } else {
            i = -1;
            /* Loop over the IE dissector list to se if we find an entry;
               the last entry will have ie_type=0 breaking the loop */
            while (gtpv2_ies[++i].ie_type) {
                if (gtpv2_ies[i].ie_type == type)
                    break;
            }
            /* Just give the IE dissector the IE */
            ie_tvb = tvb_new_subset_remaining(tvb, offset);
            (*gtpv2_ies[i].decode) (ie_tvb, pinfo , ie_tree, ti, length, message_type, instance, args);
        }

        /* ch8.120 breaks the format described in ch8.2.1 */
        if (type == GTPV2_IE_MON_EVENT_INF) {
            offset++;
        }

        offset += length;
    }
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_gtpv2(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
    proto_tree *gtpv2_tree;
    proto_item *ti;
    uint8_t     message_type, t_flag, p_flag, mp_flag, cause_aux;
    int         offset = 0;
    uint16_t    msg_length;
    tvbuff_t   *msg_tvb;
    int         seq_no = 0;
    conversation_t  *conversation;
    gtpv2_conv_info_t *gtpv2_info;
    session_args_t  *args = NULL;
    gtpv2_hdr_t * gtpv2_hdr = NULL;
    gtpv2_msg_hash_t *gcrp = NULL;
    uint64_t gtpv2_hdr_flags;

    static int * const gtpv2_flags[] = {
        &hf_gtpv2_version,
        &hf_gtpv2_p,
        &hf_gtpv2_t,
        &hf_gtpv2_mp,
        NULL
    };

    gtpv2_hdr = wmem_new0(pinfo->pool, gtpv2_hdr_t);

    /* Setting the TEID to -1 to say that the TEID is not valid for this packet */
    gtpv2_hdr->teid = -1;

    /* Currently we get called from the GTP dissector no need to check the version */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTPv2");
    col_clear(pinfo->cinfo, COL_INFO);

    /* message type is in octet 2 */
    message_type = tvb_get_uint8(tvb, 1);
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(message_type, &gtpv2_message_type_vals_ext, "Unknown"));


    msg_length = tvb_get_ntohs(tvb, offset + 2);
    ti = proto_tree_add_item(tree, proto_gtpv2, tvb, offset, msg_length + 4, ENC_NA);
    gtpv2_tree = proto_item_add_subtree(ti, ett_gtpv2);

    if (g_gtp_session) {
        args = wmem_new0(pinfo->pool, session_args_t);
        args->last_cause = 16;                                         /* It stores the last cause decoded. Cause accepted by default */
        /* We create the auxiliary lists */
        args->teid_list = wmem_list_new(pinfo->pool);
        args->ip_list = wmem_list_new(pinfo->pool);
    }

    /*
    * Do we have a conversation for this connection?
    */
    conversation = find_or_create_conversation(pinfo);

    /*
    * Do we already know this conversation?
    */
    gtpv2_info = (gtpv2_conv_info_t *)conversation_get_proto_data(conversation, proto_gtpv2);
    if (gtpv2_info == NULL) {
        /* No.  Attach that information to the conversation, and add
        * it to the list of information structures.
        */
        gtpv2_info = wmem_new(wmem_file_scope(), gtpv2_conv_info_t);
        /*Request/response matching tables*/
        gtpv2_info->matched = wmem_map_new(wmem_file_scope(), gtpv2_sn_hash, gtpv2_sn_equal_matched);
        gtpv2_info->unmatched = wmem_map_new(wmem_file_scope(), gtpv2_sn_hash, gtpv2_sn_equal_unmatched);

        conversation_add_proto_data(conversation, proto_gtpv2, gtpv2_info);
    }

    /* Control Plane GTP uses a variable length header. Control Plane GTP header
        * length shall be a multiple of 4 octets.
        * Figure 5.1-1 illustrates the format of the GTPv2-C Header.
        * Bits       8  7  6   5       4   3       2       1
        * Octets   1 Version   P       T   Spare   Spare   Spare
        *          2 Message Type
        *          3 Message Length (1st Octet)
        *          4 Message Length (2nd Octet)
        *  m-k(m+3)    If T flag is set to 1, then TEID shall be placed into octets 5-8.
        *              Otherwise, TEID field is not present at all.
        *  n-(n+2)   Sequence Number
        * (n+3)      Spare
        * Figure 5.1-1: General format of GTPv2 Header for Control Plane
        */

    /* 5.4  EPC specific GTP-C header
     * Bits          8  7  6   5       4   3       2       1
     * Octets      1 Version   P       T=1 MP      Spare   Spare
     *             2 Message Type
     *             3 Message Length (1st Octet)
     *             4 Message Length (2nd Octet)
     *             5 Tunnel Endpoint Identifier (1st Octet)
     *             6 Tunnel Endpoint Identifier (2nd Octet)
     *             7 Tunnel Endpoint Identifier (3rd Octet)
     *             8 Tunnel Endpoint Identifier (4th Octet)
     *             9 Sequence Number (1st Octet)
     *            10 Sequence Number (2nd Octet)
     *            11 Sequence Number (3rd Octet)
     *            12 Message Priority  Spare
     */

    /* Octet 1 */
    proto_tree_add_bitmask_with_flags_ret_uint64(gtpv2_tree, tvb, offset, hf_gtpv2_flags,
        ett_gtpv2_flags, gtpv2_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT, &gtpv2_hdr_flags);

    gtpv2_hdr->flags = (uint8_t)gtpv2_hdr_flags;
    p_flag  = (gtpv2_hdr->flags & 0x10) >> 4;
    t_flag  = (gtpv2_hdr->flags & 0x08) >> 3;
    mp_flag = (gtpv2_hdr->flags & 0x04) >> 2;

    offset += 1;

    /* Octet 2 */
    gtpv2_hdr->message = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(gtpv2_tree, hf_gtpv2_message_type, tvb, offset, 1, gtpv2_hdr->message);
    offset += 1;
    /* Octet 3 - 4 */
    gtpv2_hdr->length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(gtpv2_tree, hf_gtpv2_msg_length, tvb, offset, 2, gtpv2_hdr->length);
    offset += 2;

    if (t_flag) {
        /* Tunnel Endpoint Identifier 4 octets */
        gtpv2_hdr->teid = tvb_get_ntohl(tvb, offset);
        proto_tree_add_uint(gtpv2_tree, hf_gtpv2_teid, tvb, offset, 4, (uint32_t)gtpv2_hdr->teid);
        offset += 4;
    }
    /* Sequence Number 3 octets */
    proto_tree_add_item_ret_uint(gtpv2_tree, hf_gtpv2_seq, tvb, offset, 3, ENC_BIG_ENDIAN, &seq_no);
    offset += 3;

    /* Spare 1 octet or if the "MP" flag is set to "1",
     * then bits 8 to 5 of octet 12 shall indicate the message priority.
     */
    if (mp_flag) {
        /* Bits 8 to 5 of octet 12 shall be encoded as the binary value of the Message Priority
         * and it may take any value between 0 and 15, where 0 corresponds to the highest priority
         * and 15 the lowest priority.
         */
        proto_tree_add_item(gtpv2_tree, hf_gtpv2_msg_prio, tvb, offset, 1, ENC_BIG_ENDIAN);
    }else{
        proto_tree_add_item(gtpv2_tree, hf_gtpv2_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset += 1;

    if (p_flag) {
        msg_tvb = tvb_new_subset_length(tvb, 0, msg_length + 4);
        dissect_gtpv2_ie_common(msg_tvb, pinfo, gtpv2_tree, offset, message_type, args, 0);
    } else {
        dissect_gtpv2_ie_common(tvb, pinfo, gtpv2_tree, offset, message_type, args, 0);
    }
    /*Use sequence number to track Req/Resp pairs*/
    cause_aux = 16; /* Cause accepted by default. Only used when args is NULL */
    if (args && !PINFO_FD_VISITED(pinfo)) {
        /* We insert the lists inside the table*/
        fill_map(args->teid_list, args->ip_list, pinfo->num);
        cause_aux = args->last_cause;
    }
    gcrp = gtpv2_match_response(tvb, pinfo, gtpv2_tree, seq_no, message_type, gtpv2_info, cause_aux);
    if (gcrp) {
        tap_queue_packet(gtpv2_tap, pinfo, gcrp);
    }
    if (args) {
        track_gtpv2_session(tvb, pinfo, gtpv2_tree, gtpv2_hdr, args);
    }

    /* Bit 5 represents a "P" flag. If the "P" flag is set to "0",
     * no piggybacked message shall be present. If the "P" flag is set to "1",
     * then another GTPv2-C message with its own header and body shall be present
     * at the end of the current message.
     */
    if (p_flag) {
        tvbuff_t   *new_p_tvb;
        /* Octets 3 to 4 represent the Length field. This field shall indicate the
         * length of the message in octets excluding the
         * mandatory part of the GTP-C header (the first 4 octets).
         */
        new_p_tvb = tvb_new_subset_remaining(tvb, msg_length + 4);
        col_append_str(pinfo->cinfo, COL_INFO, " / ");
        col_set_fence(pinfo->cinfo, COL_INFO);
        increment_dissection_depth(pinfo);
        dissect_gtpv2(new_p_tvb, pinfo, tree, NULL);
        decrement_dissection_depth(pinfo);
    }

    return tvb_captured_length(tvb);
}

void proto_register_gtpv2(void)
{
    unsigned  i, last_offset;

    static hf_register_info hf_gtpv2[] = {
        { &hf_gtpv2_response_in,
        { "Response In", "gtpv2.response_in",
        FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
        "The response to this GTP request is in this frame", HFILL }
        },
        { &hf_gtpv2_response_to,
        { "Response To", "gtpv2.response_to",
        FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
        "This is a response to the GTP request in this frame", HFILL }
        },
        { &hf_gtpv2_response_time,
        { "Response Time", "gtpv2.response_time",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "The time between the Request and the Response", HFILL }
        },
        { &hf_gtpv2_spare_half_octet,
          {"Spare half octet", "gtpv2.spare_half_octet",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_gtpv2_spare_bits,
          {"Spare bit(s)", "gtpv2.spare_bits",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        //{ &hf_gtpv2_spare_b7_b1,
        //  {"Spare bit(s)", "gtpv2.spare_b7_b1",
        //   FT_UINT8, BASE_DEC, NULL, 0xfe,
        //   NULL, HFILL }
        //},
        { &hf_gtpv2_spare_b7_b2,
        { "Spare", "gtpv2.spare.b7_b2",
            FT_UINT8, BASE_HEX, NULL, 0xfc,
            NULL, HFILL }
        },
        { &hf_gtpv2_spare_b7_b3,
        {"Spare bit(s)", "gtpv2.spare_b7_b3",
            FT_UINT8, BASE_DEC, NULL, 0xf8,
            NULL, HFILL }
        },
        { &hf_gtpv2_spare_b7_b4,
        { "Spare", "gtpv2.spare.b7_b4",
            FT_UINT8, BASE_HEX, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_gtpv2_spare_b7_b5,
        { "Spare", "gtpv2.spare.b7_b5",
            FT_UINT8, BASE_HEX, NULL, 0xe0,
            NULL, HFILL }
        },
        {&hf_gtpv2_flags,
         {"Flags", "gtpv2.flags",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_version,
         {"Version", "gtpv2.version",
          FT_UINT8, BASE_DEC, NULL, 0xe0,
          NULL, HFILL}
        },
        {&hf_gtpv2_p,
         {"Piggybacking flag (P)", "gtpv2.p",
          FT_UINT8, BASE_DEC, NULL, 0x10,
          "If Piggybacked message is present or not", HFILL}
        },
        { &hf_gtpv2_t,
          {"TEID flag (T)", "gtpv2.t",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "If TEID field is present or not", HFILL}
        },
        { &hf_gtpv2_mp,
          {"Message Priority(MP)", "gtpv2.mp",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "If Message Priority field is present or not", HFILL}
        },
        { &hf_gtpv2_message_type,
          {"Message Type", "gtpv2.message_type",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_message_type_vals_ext, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_msg_length,
          {"Message Length", "gtpv2.msg_length",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_teid,
          {"Tunnel Endpoint Identifier", "gtpv2.teid",
           FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
           "TEID", HFILL}
        },
        { &hf_gtpv2_seq,
          {"Sequence Number", "gtpv2.seq",
           FT_UINT24, BASE_HEX_DEC, NULL, 0x0,
           "SEQ", HFILL}
        },
        { &hf_gtpv2_msg_prio,
          {"Message Priority", "gtpv2.mp",
           FT_UINT8, BASE_HEX_DEC, NULL, 0xf0,
           NULL, HFILL}
        },
        { &hf_gtpv2_spare,
          {"Spare", "gtpv2.spare",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_spare_w0,
        { "Spare", "gtpv2.spare.w0",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_gtpv2_ie,
          {"IE Type", "gtpv2.ie_type",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_element_type_vals_ext, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ie_len,
          {"IE Length", "gtpv2.ie_len",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "length of the information element excluding the first four octets", HFILL}
        },
        { &hf_gtpv2_cr,
          {"CR flag", "gtpv2.cr",
           FT_UINT8, BASE_DEC, NULL, 0xf0, /* SRVCC */
           NULL, HFILL}
        },
        { &hf_gtpv2_instance,
          {"Instance", "gtpv2.instance",
           FT_UINT8, BASE_DEC, NULL, 0x0f,
           NULL, HFILL}
        },
        { &hf_gtpv2_ipv4_addr,
          {"IPv4 Address", "gtpv2.ipv4_addr",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_cause,
          {"Cause", "gtpv2.cause",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_cause_vals_ext, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_cause_cs,
         {"CS (Cause Source)", "gtpv2.cs",
          FT_BOOLEAN, 8, TFS(&gtpv2_cause_cs), 0x01,
          NULL, HFILL}
        },
        { &hf_gtpv2_cause_bce,
          {"BCE (Bearer Context IE Error)", "gtpv2.bce",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_cause_pce,
          {"PCE (PDN Connection IE Error)", "gtpv2.pce",
           FT_BOOLEAN, 8, NULL, 0x04,
           NULL, HFILL}
        },
        { &hf_gtpv2_cause_off_ie_t,
          {"Type of the offending IE", "gtpv2.cause_off_ie_t",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_element_type_vals_ext, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_rec,
          {"Restart Counter", "gtpv2.rec",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
/*Start SRVCC Messages*/
        { &hf_gtpv2_stn_sr,
          {"STN-SR", "gtpv2.stn_sr",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_len_trans_con,
          {"Length of the Transparent Container", "gtpv2.len_trans_con",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_eksi,
          {"eKSI", "gtpv2.eksi",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_ck,
          {"CK", "gtpv2.ck",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ik,
          {"IK", "gtpv2.ik",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_len_ms_classmark2,
          {"Length of Mobile Station Classmark2", "gtpv2.len_ms_classmark2",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_len_ms_classmark3,
          {"Length of Mobile Station Classmark3", "gtpv2.len_ms_classmark3",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_len_supp_codec_list,
          {"Length of Supported Codec List", "gtpv2.len_supp_codec_list",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ksi,
          {"KSI'cs", "gtpv2.ksi",
           FT_UINT8, BASE_DEC, NULL, 0x0F,
           NULL, HFILL}
        },
        { &hf_gtpv2_cksn,
          {"CKSN'", "gtpv2.cksn",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_srvcc_cause,
          {"SRVCC Cause", "gtpv2.srvcc_cause",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_srvcc_cause_vals_ext, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_rac,
         { "Routing Area Code (RAC)", "gtpv2.rac",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },

        { &hf_gtpv2_rnc_id,
          {"RNC ID", "gtpv2.rnc_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ext_rnc_id,
          {"Extended RNC-ID", "gtpv2.ext_rnc_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_lac,
          { "Location Area Code (LAC)", "gtpv2.lac",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gtpv2_sac,
          { "Service Area Code (SAC)", "gtpv2.sac",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gtpv2_tgt_g_cell_id,
          {"Cell ID", "gtpv2.tgt_g_cell_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_teid_c,
         {"Tunnel Endpoint Identifier for Control Plane(TEID-C)", "gtpv2.teid_c",
          FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_sv_sti,
         {"STI (Session Transfer Indicator)", "gtpv2.sv_sti",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        {&hf_gtpv2_sv_ics,
         {"ICS (IMS Centralized Service)", "gtpv2.sv_ics",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_sv_emind,
         {"EmInd(Emergency Indicator)", "gtpv2.sv_emind",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },

/*End SRVCC Messages*/
        {&hf_gtpv2_apn,
         {"APN (Access Point Name)", "gtpv2.apn",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_ambr_up,
         {"AMBR Uplink (Aggregate Maximum Bit Rate for Uplink)", "gtpv2.ambr_up",
          FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_ambr_down,
         {"AMBR Downlink (Aggregate Maximum Bit Rate for Downlink)", "gtpv2.ambr_down",
          FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_ebi,
         {"EPS Bearer ID (EBI)", "gtpv2.ebi",
          FT_UINT8, BASE_DEC, NULL, 0x0f,
          NULL, HFILL}
        },
        { &hf_gtpv2_ip_address_ipv4,
          {"IP address IPv4", "gtpv2.ip_address_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ip_address_ipv6,
          {"IP address IPv6", "gtpv2.ip_address_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_mei,
         {"MEI(Mobile Equipment Identity)", "gtpv2.mei",
          FT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        { &hf_gtpv2_pdn_numbers_nsapi,
          {"NSAPI", "gtpv2.pdn_numbers_nsapi",
           FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL}
        },
        { &hf_gtpv2_p_tmsi,
          {"Packet TMSI (P-TMSI)", "gtpv2.p_tmsi",
           FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gtpv2_p_tmsi_sig,
          {"P-TMSI Signature", "gtpv2.p_tmsi_sig",
           FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gtpv2_daf,
         {"DAF (Dual Address Bearer Flag)", "gtpv2.daf",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        {&hf_gtpv2_dtf,
         {"DTF (Direct Tunnel Flag)", "gtpv2.dtf",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        {&hf_gtpv2_hi,
         {"HI (Handover Indication)", "gtpv2.hi",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        {&hf_gtpv2_dfi,
         {"DFI (Direct Forwarding Indication)", "gtpv2.dfi",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        {&hf_gtpv2_oi,
         {"OI (Operation Indication)", "gtpv2.oi",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        {&hf_gtpv2_isrsi,
         {"ISRSI (Idle mode Signalling Reduction Supported Indication)", "gtpv2.isrsi",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        {&hf_gtpv2_israi,
         {"ISRAI (Idle mode Signalling Reduction Activation Indication)",    "gtpv2.israi",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_sgwci,
         {"SGWCI (SGW Change Indication)", "gtpv2.sgwci",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        {&hf_gtpv2_sqci,
         {"SQCI (Subscribed QoS Change Indication)", "gtpv2.sqci",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        {&hf_gtpv2_uimsi,
         {"UIMSI (Unauthenticated IMSI)", "gtpv2.uimsi",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        {&hf_gtpv2_cfsi,
         {"CFSI (Change F-TEID support indication)", "gtpv2.cfsi",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        {&hf_gtpv2_crsi,
         {"CRSI (Change Reporting support indication)", "gtpv2.crsi",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        {&hf_gtpv2_ps,
         {"PS (Piggybacking Supported)", "gtpv2.ps",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        {&hf_gtpv2_pt,
         {"PT (Protocol Type)", "gtpv2.pt",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        {&hf_gtpv2_si,
         {"SI (Scope Indication)", "gtpv2.si",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_msv,
         {"MSV (MS Validated)", "gtpv2.msv",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        {&hf_gtpv2_retloc,
         {"RetLoc (Retrieve Location Indication Flag)", "gtpv2.retloc",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        {&hf_gtpv2_pbic,
         {"PBIC (Propagate BBAI Information Change)", "gtpv2.pbic",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        {&hf_gtpv2_srni,
         {"SRNI (SGW Restoration Needed Indication)", "gtpv2.snri",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        {&hf_gtpv2_s6af,
         {"S6AF (Static IPv6 Address Flag)", "gtpv2.s6af",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        {&hf_gtpv2_s4af,
         {"S4AF (Static IPv4 Address Flag)", "gtpv2.s4af",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        {&hf_gtpv2_mbmdt,
         {"MBMDT (Management Based MDT allowed flag)", "gtpv2.mbmdt",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        {&hf_gtpv2_israu,
         {"ISRAU (ISR is activated for the UE)", "gtpv2.israu",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_ccrsi,
         {"CCRSI (CSG Change Reporting support indication)", "gtpv2.ccrsi",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },

        {&hf_gtpv2_cprai,
         {"CPRAI (Change of Presence Reporting Area information Indication)", "gtpv2.cprai",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        {&hf_gtpv2_arrl,
         {"ARRL (Abnormal Release of Radio Link)", "gtpv2.arrl",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        {&hf_gtpv2_ppof,
         {"PPOFF (PDN Pause Off Indication)", "gtpv2.ppof",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        {&hf_gtpv2_ppon_ppei,
         {"PPON (PDN Pause On Indication) / PPEI (PDN Pause Enabled Indication)", "gtpv2.ppon_ppei",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        {&hf_gtpv2_ppsi,
         {"PPSI (PDN Pause Support Indication)", "gtpv2.ppsi",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        {&hf_gtpv2_csfbi,
         {"CSFBI (CSFB Indication)", "gtpv2.csfbi",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        {&hf_gtpv2_clii,
         {"CLII (Change of Location Information Indication)", "gtpv2.clii",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_cpsr,
         {"CPSR (CS to PS SRVCC Indication)", "gtpv2.cpsr",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        {&hf_gtpv2_nsi,
         {"NSI (NBIFOM Support Indication)", "gtpv2.nsi",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        {&hf_gtpv2_uasi,
         {"UASI (UE Available for Signalling Indication)", "gtpv2.uasi",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        {&hf_gtpv2_dtci,
         {"DTCI (Delay Tolerant Connection Indication)", "gtpv2.dtci",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        {&hf_gtpv2_bdwi,
         {"BDWI (Buffered DL Data Waiting Indication)", "gtpv2.bdwi",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        {&hf_gtpv2_psci,
         {"PSCI (Pending Subscription Change Indication)", "gtpv2.psci",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        {&hf_gtpv2_pcri,
         {"PCRI (P-CSCF Restoration Indication)", "gtpv2.pcri",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        {&hf_gtpv2_aosi,
         {"AOSI (Associate OCI with SGW node's Identity)", "gtpv2.aosi",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_aopi,
         {"AOPI (Associate OCI with PGW node's Identity)", "gtpv2.aopi",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        {&hf_gtpv2_roaai,
         {"ROAAI (Release Over Any Access Indication)", "gtpv2.roaai",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        {&hf_gtpv2_epcosi,
         {"EPCOSI (Extended PCO Support Indication)", "gtpv2.epcosi",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        {&hf_gtpv2_cpopci,
         {"CPOPCI (Control Plane Only PDN Connection Indication)", "gtpv2.cpopci",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        {&hf_gtpv2_pmtsmi,
         {"PMTSMI (Pending MT Short Message Indication)", "gtpv2.pmtsmi",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        {&hf_gtpv2_s11tf,
         {"S11TF (S11-U Tunnel Flag)", "gtpv2.s11tf",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        {&hf_gtpv2_pnsi,
         {"PNSI (Pending Network Initiated PDN Connection Signalling Indication)", "gtpv2.pnsi",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        {&hf_gtpv2_unaccsi,
         {"UNACCSI (UE Not Authorized Cause Code Support Indication)", "gtpv2.unaccsi",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_wpmsi,
         {"WPMSI (WLCP PDN Connection Modification Support Indication)", "gtpv2.wpmsi",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        {&hf_gtpv2_5gsnn26,
        { "5GSNN26 (5GS Interworking without N26 Indication)", "gtpv2.5gsnn26",
         FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        {&hf_gtpv2_reprefi,
        { "REPREFI (Return Preferred Indication)", "gtpv2.reprefi",
         FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }
        },
        {&hf_gtpv2_5gsiwk,
        { "5GSIWKI (5GS Interworking Indication)", "gtpv2.5gsiwk",
         FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }
        },
        {&hf_gtpv2_eevrsi,
        { "EEVRSI (Extended EBI Value Range Support Indication)", "gtpv2.eevrsi",
         FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
        },
        {&hf_gtpv2_ltemui,
        { "LTEMUI (LTE-M UE Indication)", "gtpv2.ltemui",
         FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
        },
        {&hf_gtpv2_ltempi,
        { "LTEMPI (LTE-M RAT Type reporting to PGW Indication)", "gtpv2.ltempi",
         FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
        },
        {&hf_gtpv2_enbcrsi,
         {"ENBCRSI (eNB Change Reporting Support Indication)", "gtpv2.enbcrsi",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_tspcmi,
         {"TSPCMI (Triggering SGSN Initiated PDP Context Creation/Modification Indication)", "gtpv2.tspcmi",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        {&hf_gtpv2_csrmfi,
         { "CSRMFI (Create Session Request Message Forwarded Indication)", "gtpv2.csrmfi",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        {&hf_gtpv2_mtedtn,
         { "MTEDTN (MT-EDT Not Applicable)", "gtpv2.mtedtn",
          FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40, NULL, HFILL }
        },

        {&hf_gtpv2_mtedta,
         { "MTEDTA (MT-EDT Applicable)", "gtpv2.mtedta",
          FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20, NULL, HFILL }
        },

        {&hf_gtpv2_n5gnmi,
        { "N5GNMI (No 5GS N26 Mobility Indication)", "gtpv2.n5gnmi",
         FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
        },
        { &hf_gtpv2_5gcnrs,
        { "5GCNRS (5GC Not Restricted Support)", "gtpv2.5gcnrs",
         FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08, NULL, HFILL }
        },
        { &hf_gtpv2_5gcnri,
        { "5GCNRI (5GC Not Restricted Indication)", "gtpv2.5gcnri",
         FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL }
        },
        { &hf_gtpv2_5srhoi,
        { "5SRHOI (5G-SRVCC HO Indication)", "gtpv2.5srhoi",
         FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }
        },
        { &hf_gtpv2_ethpdn,
         {"ETHPDN (Ethernet PDN Support Indication)", "gtpv2.ethpdn",
          FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL}
        },
        { &hf_gtpv2_nspusi,
         {"NSPUSI (Notify Start of Pause of Charging via User plane Support Indication)", "gtpv2.nspusi",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_gtpv2_pgwrnsi,
         {"PGWRNSI (PGW Redirection due to mismatch with Network Slice subscribed by UE Support Indication)", "gtpv2.pgwrnsi",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        { &hf_gtpv2_rppcsi,
         {"RPPCSI (Restoration of PDN connections after an PGW-C/SMF change Support Indication)", "gtpv2.rppcsi",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        { &hf_gtpv2_pgwchi,
         {"PGWCHI (PGW CHange Indication)", "gtpv2.pgwchi",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_gtpv2_sissme,
         {"SISSME (Same IWK-SCEF Selected for Monitoring Event Indication)", "gtpv2.sissme",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        { &hf_gtpv2_nsenbi,
         {"NSENBI (Notify Source eNodeB Indication)", "gtpv2.nsenbi",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        { &hf_gtpv2_idfupf,
         {"IDFUPF (Indirect Data Forwarding with UPF Indication)", "gtpv2.idfupf",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_gtpv2_emci,
         {"EMCI (Emergency PDU Session Indication)", "gtpv2.emci",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_gtpv2_lapcosi,
         {"LAPCOSI (Large Additional Protocol Configuration Options Support Indication)", "gtpv2.lapcosi",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        { &hf_gtpv2_ltemsai,
         {"LTEMSAI (LTE-M Satellite Access Indication)", "gtpv2.ltemsai",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        { &hf_gtpv2_srtpi,
         {"SRTPI (Satellite RAT Type reporting to PGW Indication)", "gtpv2.srtpi",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_gtpv2_upipsi,
         {"UPIPSI (User Plane Integrity Protection Support Indication)", "gtpv2.upipsi",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },


        { &hf_gtpv2_pdn_type,
          {"PDN Type", "gtpv2.pdn_type",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_pdn_type_vals_ext, 0x07,
           NULL, HFILL}
        },
#if 0
        { &hf_gtpv2_tra_info,
          {"Trace ID", "gtpv2.tra_info",
           FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
#endif
        { &hf_gtpv2_tra_info_msc_momt_calls,
          {"MO and MT calls", "gtpv2.tra_info_msc_momt_calls",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_msc_momt_sms,
          {"MO and MT SMS", "gtpv2.tra_info_msc_momt_sms",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_msc_lu_imsi_ad,
          {"LU, IMSI attach, IMSI detach", "gtpv2.tra_info_msc_lu_imsi_ad",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_msc_handovers,
          {"Handovers", "gtpv2.tra_info_msc_handovers",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_msc_ss,
          {"SS", "gtpv2.tra_info_msc_ss",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_mgw_context,
          {"Context", "gtpv2.tra_info_mgw_context",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MGW", HFILL}
        },
        { &hf_gtpv2_tra_info_sgsn_pdp_context,
          {"PDP context", "gtpv2.tra_info_sgsn_pdp_context",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_sgsn_momt_sms,
          {"MO and MT SMS", "gtpv2.tra_info_sgsn_momt_sms",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_sgsn_rau_gprs_ad,
          {"RAU, GPRS attach, GPRS detach", "gtpv2.tra_info_sgsn_rau_gprs_ad",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_sgsn_mbms,
          {"MBMS Context", "gtpv2.tra_info_sgsn_mbms",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_sgsn_reserved,
          {"Reserved", "gtpv2.tra_info_sgsn_reserved",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_ggsn_pdp,
          {"PDP Context", "gtpv2.tra_info_ggsn_pdp",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "GGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_ggsn_mbms,
          {"MBMS Context", "gtpv2.tra_info_ggsn_mbms",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "GGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_bm_sc,
          {"MBMS Multicast service activation", "gtpv2.tra_info_bm_sc",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "BM-SC", HFILL}
        },
        { &hf_gtpv2_tra_info_mme_sgw_ss,
          {"Session setup", "gtpv2.tra_info_mme_sgw_ss",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_mme_sgw_sr,
          {"Service Request", "gtpv2.tra_info_mme_sgw_sr",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_mme_sgw_iataud,
          {"Initial Attach, Tracking area update, Detach", "gtpv2.tra_info_mme_sgw_iataud",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_mme_sgw_ue_init_pdn_disc,
          {"UE initiated PDN disconnection", "gtpv2.tra_info_mme_sgw_ue_init_pdn_disc",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_mme_sgw_bearer_act_mod_del,
          {"Bearer Activation Modification Deletion", "gtpv2.tra_info_mme_sgw_bearer_act_mod_del",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_mme_sgw_ho,
          {"Handover", "gtpv2.tra_info_mme_sgw_ho",
           FT_UINT8, BASE_DEC, NULL, 0x20,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_sgw_pdn_con_creat,
          {"PDN Connection creation", "gtpv2.tra_info_sgw_pdn_con_creat",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_sgw_pdn_con_term,
          {"PDN connection termination", "gtpv2.tra_info_sgw_pdn_con_term",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_sgw_bearer_act_mod_del,
          {"Bearer Activation Modification Deletion", "gtpv2.tra_info_sgw_bearer_act_mod_del",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_pgw_pdn_con_creat,
          {"PDN Connection creation", "gtpv2.tra_info_pgw_pdn_con_creat",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "PGW", HFILL}
        },
        { &hf_gtpv2_tra_info_pgw_pdn_con_term,
          {"PDN connection termination", "gtpv2.tra_info_pgw_pdn_con_term",
           FT_UINT8, BASE_DEC, NULL, 0x20,
           "PGW", HFILL}
        },
        { &hf_gtpv2_tra_info_pgw_bearer_act_mod_del,
          {"Bearer Activation Modification Deletion", "gtpv2.tra_info_pgw_bearer_act_mod_del",
           FT_UINT8, BASE_DEC, NULL, 0x40,
           "PGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_msc_s,
          {"MSC-S", "gtpv2.tra_info_lne_msc_s",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_mgw,
          {"MGW", "gtpv2.tra_info_lne_mgw",
          FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_sgsn,
          {"SGSN", "gtpv2.tra_info_lne_sgsn",
           FT_BOOLEAN, 8, NULL, 0x04,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_ggsn,
          {"GGSN", "gtpv2.tra_info_lne_ggsn",
          FT_BOOLEAN, 8, NULL, 0x08,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_rnc,
          {"RNC", "gtpv2.tra_info_lne_rnc",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_bm_sc,
          {"BM-SC", "gtpv2.tra_info_lne_bm_sc",
           FT_BOOLEAN, 8, NULL, 0x20,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_mme,
          {"MME", "gtpv2.tra_info_lne_mme",
           FT_BOOLEAN, 8, NULL, 0x40,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_sgw,
          {"SGW", "gtpv2.tra_info_lne_sgw",
          FT_BOOLEAN, 8, NULL, 0x80,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_pdn_gw,
          {"PDN GW", "gtpv2.tra_info_lne_pdn_gw",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_enb,
          {"eNB", "gtpv2.tra_info_lne_enb",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_amf,
          {"AMF", "gtpv2.tra_info_lne_amf",
           FT_BOOLEAN, 8, NULL, 0x04,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_smf,
          {"SMF", "gtpv2.tra_info_lne_smf",
           FT_BOOLEAN, 8, NULL, 0x08,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_pcf,
          {"PCF", "gtpv2.tra_info_lne_pcf",
           FT_BOOLEAN, 8, NULL, 0x10,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lne_upf,
          {"UPF", "gtpv2.tra_info_lne_upf",
           FT_BOOLEAN, 8, NULL, 0x20,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_tra_info_ng_ran_node,
          {"NG-RAN node", "gtpv2.tra_info_ng_ran_node",
           FT_BOOLEAN, 8, NULL, 0x40,
           NULL, HFILL}
        },

        { &hf_gtpv2_tra_info_tdl,
          {"Trace Depth Length", "gtpv2.tra_info_tdl",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_a,
          {"A", "gtpv2.tra_info_lmsc_a",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_lu,
          {"Iu", "gtpv2.tra_info_lmsc_lu",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_mc,
          {"Mc", "gtpv2.tra_info_lmsc_mc",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_g,
          {"MAP-G", "gtpv2.tra_info_lmsc_map_g",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_b,
          {"MAP-B", "gtpv2.tra_info_lmsc_map_b",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_e,
          {"MAP-E", "gtpv2.tra_info_lmsc_map_e",
           FT_UINT8, BASE_DEC, NULL, 0x20,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_f,
          {"MAP-F", "gtpv2.tra_info_lmsc_map_f",
           FT_UINT8, BASE_DEC, NULL, 0x40,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_cap,
          {"CAP", "gtpv2.tra_info_lmsc_cap",
           FT_UINT8, BASE_DEC, NULL, 0x80,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_d,
          {"MAP-D", "gtpv2.tra_info_lmsc_map_d",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_c,
          {"MAP-C", "gtpv2.tra_info_lmsc_map_c",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmgw_mc,
          {"Mc", "gtpv2.tra_info_lmgw_mc",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lmgw_nb_up,
          {"Nb-UP", "gtpv2.tra_info_lmgw_nb_up",
           FT_UINT8, BASE_DEC, NULL, 0x2,
           "MGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lmgw_lu_up,
          {"Iu-UP", "gtpv2.tra_info_lmgw_lu_up",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "MGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_gb,
          {"Gb", "gtpv2.tra_info_lsgsn_gb",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_lu,
          {"Iu", "gtpv2.tra_info_lsgsn_lu",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_gn,
          {"Gn", "gtpv2.tra_info_lsgsn_gn",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_map_gr,
          {"MAP-Gr", "gtpv2.tra_info_lsgsn_map_gr",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_map_gd,
          {"MAP-Gd", "gtpv2.tra_info_lsgsn_map_gd",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_map_gf,
          {"MAP-Gf", "gtpv2.tra_info_lsgsn_map_gf",
           FT_UINT8, BASE_DEC, NULL, 0x20,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_gs,
          {"Gs", "gtpv2.tra_info_lsgsn_gs",
           FT_UINT8, BASE_DEC, NULL, 0x40,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_ge,
          {"Ge", "gtpv2.tra_info_lsgsn_ge",
           FT_UINT8, BASE_DEC, NULL, 0x80,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lggsn_gn,
          {"Gn", "gtpv2.tra_info_lggsn_gn",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "GGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lggsn_gi,
          {"Gi", "gtpv2.tra_info_lggsn_gi",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "GGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lggsn_gmb,
          {"Gmb", "gtpv2.tra_info_lggsn_gmb",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "GGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lrnc_lu,
          {"Iu", "gtpv2.tra_info_lrnc_lu",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "RNC", HFILL}
        },
        { &hf_gtpv2_tra_info_lrnc_lur,
          {"Iur", "gtpv2.tra_info_lrnc_lur",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "RNC", HFILL}
        },
        { &hf_gtpv2_tra_info_lrnc_lub,
          {"Iub", "gtpv2.tra_info_lrnc_lub",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "RNC", HFILL}
        },
        { &hf_gtpv2_tra_info_lrnc_uu,
          {"Uu", "gtpv2.tra_info_lrnc_uu",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "RNC", HFILL}
        },
        { &hf_gtpv2_tra_info_lbm_sc_gmb,
          {"Gmb", "gtpv2.tra_info_lbm_sc_gmb",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "BM-SC", HFILL}
        },
        { &hf_gtpv2_tra_info_lmme_s1_mme,
          {"S1-MME", "gtpv2.tra_info_lmme_s1_mme",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lmme_s3,
          {"S3", "gtpv2.tra_info_lmme_s3",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lmme_s6a,
          {"S6a", "gtpv2.tra_info_lmme_s6a",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lmme_s10,
          {"S10", "gtpv2.tra_info_lmme_s10",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lmme_s11,
          {"S11", "gtpv2.tra_info_lmme_s11",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgw_s4,
          {"S4", "gtpv2.tra_info_lsgw_s4",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgw_s5,
          {"S5", "gtpv2.tra_info_lsgw_s5",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgw_s8b,
          {"S8b", "gtpv2.tra_info_lsgw_s8b",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgw_s11,
          {"S11", "gtpv2.tra_info_lsgw_s11",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s2a,
          {"S2a", "gtpv2.tra_info_lpdn_gw_s2a",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s2b,
          {"S2b", "gtpv2.tra_info_lpdn_gw_s2b",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s2c,
          {"S2c", "gtpv2.tra_info_lpdn_gw_s2c",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s5,
          {"S5", "gtpv2.tra_info_lpdn_gw_s5",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s6c,
          {"S6c", "gtpv2.tra_info_lpdn_gw_s6c",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_gx,
          {"Gx", "gtpv2.tra_info_lpdn_gw_gx",
           FT_UINT8, BASE_DEC, NULL, 0x20,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s8b,
          {"S8b", "gtpv2.tra_info_lpdn_gw_s8b",
           FT_UINT8, BASE_DEC, NULL, 0x40,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_sgi,
          {"SGi", "gtpv2.tra_info_lpdn_gw_sgi",
           FT_UINT8, BASE_DEC, NULL, 0x80,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lenb_s1_mme,
          {"S1-MME", "gtpv2.tra_info_lenb_s1_mme",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "eNB", HFILL}
        },
        { &hf_gtpv2_tra_info_lenb_x2,
          {"X2", "gtpv2.tra_info_lenb_x2",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "eNB", HFILL}
        },
        { &hf_gtpv2_tra_info_lenb_uu,
          {"Uu", "gtpv2.tra_info_lenb_uu",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "eNB", HFILL}
        },
        { &hf_gtpv2_pdn_ipv4,
          {"PDN Address and Prefix(IPv4)", "gtpv2.pdn_addr_and_prefix.ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_pdn_ipv6_len,
          {"IPv6 Prefix Length", "gtpv2.pdn_ipv6_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_pdn_ipv6,
          {"PDN Address and Prefix(IPv6)", "gtpv2.pdn_addr_and_prefix.ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        /* Bit 7 - PCI (Pre-emption Capability): See 3GPP TS 29.212[29], clause 5.3.46 Pre-emption-Capability AVP.
         * clause 5.3.46 Pre-emption-Capability AVP.
         * 5.3.46 Pre-emption-Capability AVP
         * The following values are defined:
         * PRE-EMPTION_CAPABILITY_ENABLED (0)
         * PRE-EMPTION_CAPABILITY_DISABLED (1)
         */
        {&hf_gtpv2_bearer_qos_pci,
         {"PCI (Pre-emption Capability)", "gtpv2.bearer_qos_pci",
          FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled), 0x40,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_pl,
         {"PL (Priority Level)", "gtpv2.bearer_qos_pl",
          FT_UINT8, BASE_DEC, NULL, 0x3c,
          NULL, HFILL}
        },
        /* Bit 1 - PVI (Pre-emption Vulnerability): See 3GPP TS 29.212[29],
         * clause 5.3.47 Pre-emption-Vulnerability AVP.
         * 5.3.47 Pre-emption-Vulnerability AVP
         * The following values are defined:
         * PRE-EMPTION_VULNERABILITY_ENABLED (0)
         * PRE-EMPTION_VULNERABILITY_DISABLED (1)
         */
        {&hf_gtpv2_bearer_qos_pvi,
         {"PVI (Pre-emption Vulnerability)", "gtpv2.bearer_qos_pvi",
          FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled), 0x01,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_label_qci,
         {"Label (QCI)", "gtpv2.bearer_qos_label_qci",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_mbr_up,
         {"Maximum Bit Rate For Uplink", "gtpv2.bearer_qos_mbr_up",
          FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_mbr_down,
         {"Maximum Bit Rate For Downlink", "gtpv2.bearer_qos_mbr_down",
          FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_gbr_up,
         {"Guaranteed Bit Rate For Uplink", "gtpv2.bearer_qos_gbr_up",
          FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_gbr_down,
         {"Guaranteed Bit Rate For Downlink", "gtpv2.bearer_qos_gbr_down",
          FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_label_qci,
         {"Label (QCI)", "gtpv2.flow_qos_label_qci",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_mbr_up,
         {"Maximum Bit Rate For Uplink", "gtpv2.flow_qos_mbr_up",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_mbr_down,
         {"Maximum Bit Rate For Downlink", "gtpv2.flow_qos_mbr_down",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_gbr_up,
         {"Guaranteed Bit Rate For Uplink", "gtpv2.flow_qos_gbr_up",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_gbr_down,
         {"Guaranteed Bit Rate For Downlink", "gtpv2.flow_qos_gbr_down",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_rat_type,
          {"RAT Type", "gtpv2.rat_type",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_rat_type_vals_ext, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_ecgi_flg,
          {"ECGI Present", "gtpv2.uli_ecgi_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_ECGI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_ext_macro_enb_id_flg,
          {"Extended Macro eNodeB ID Present", "gtpv2.uli_ext_macro_enb_id_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_EXT_MACRO_eNB_ID_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_macro_enb_id_flg,
          {"Macro eNodeB ID Present", "gtpv2.uli_macro_enb_id_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_MACRO_eNB_ID_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_lai_flg,
          {"LAI Present", "gtpv2.uli_lai_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_LAI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_tai_flg,
          {"TAI Present", "gtpv2.uli_tai_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_TAI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_rai_flg,
          {"RAI Present", "gtpv2.uli_rai_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_RAI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_sai_flg,
          {"SAI Present", "gtpv2.uli_sai_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_SAI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_cgi_flg,
          {"CGI Present", "gtpv2.uli_cgi_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_CGI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_glt,
          {"Geographic Location Type", "gtpv2.glt",
           FT_UINT8, BASE_DEC, VALS(geographic_location_type_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_cgi_lac,
          {"Location Area Code", "gtpv2.uli_cgi_lac",
           FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_cgi_ci,
          {"Cell Identity", "gtpv2.uli_cgi_ci",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_sai_lac,
          {"Location Area Code", "gtpv2.sai_lac",
           FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_sai_sac,
          {"Service Area Code", "gtpv2.sai_sac",
           FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_rai_lac,
          {"Location Area Code", "gtpv2.rai_lac",
           FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_rai_rac,
          {"Routing Area Code", "gtpv2.rai_rac",
           FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_tai_tac,
          {"Tracking Area Code", "gtpv2.tai_tac",
           FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_5gs_tai_tac,
          {"5GS Tracking Area Code", "gtpv2.5gs_tai_tac",
           FT_UINT24, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_ecgi_eci,
         {"ECI (E-UTRAN Cell Identifier)", "gtpv2.ecgi_eci",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_ncgi_nrci,
         {"NR Cell Identifier", "gtpv2.ncgi_nrci",
          FT_UINT40, BASE_HEX, NULL, 0xfffffffff0,
          NULL, HFILL}
        },
        {&hf_gtpv2_uli_lai_lac,
         {"Location Area Code (LAC)", "gtpv2.uli_lai_lac",
          FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_ecgi_eci_spare,
         {"Spare", "gtpv2.uli_ecgi_eci_spare",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_nsapi,
          {"NSAPI", "gtpv2.nsapi",
           FT_UINT8, BASE_DEC, NULL, 0x0f,
           NULL, HFILL}
        },
        {&hf_gtpv2_f_teid_v4,
         {"V4", "gtpv2.f_teid_v4",
          FT_BOOLEAN, 8, TFS(&gtpv2_f_teid_v4_vals), 0x80,
          NULL, HFILL}
        },
        {&hf_gtpv2_f_teid_v6,
         {"V6", "gtpv2.f_teid_v6",
          FT_BOOLEAN, 8, TFS(&gtpv2_f_teid_v6_vals), 0x40,
          NULL, HFILL}
        },
        {&hf_gtpv2_f_teid_interface_type,
         {"Interface Type", "gtpv2.f_teid_interface_type",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_f_teid_interface_type_vals_ext, 0x3f,
          NULL , HFILL}
        },
        {&hf_gtpv2_f_teid_gre_key,
         {"TEID/GRE Key", "gtpv2.f_teid_gre_key",
          FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
          NULL , HFILL}
        },
        { &hf_gtpv2_f_teid_ipv4,
          {"F-TEID IPv4", "gtpv2.f_teid_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_f_teid_ipv6,
          {"F-TEID IPv6", "gtpv2.f_teid_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_tmsi,
          {"TMSI", "gtpv2.tmsi",
           FT_UINT32, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_hsgw_addr_f_len,
          {"HSGW Address for forwarding Length", "gtpv2.hsgw_addr_f_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_hsgw_addr_ipv4,
          {"HSGW Address for forwarding", "gtpv2.hsgw_addr_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_hsgw_addr_ipv6,
          {"HSGW Address for forwarding", "gtpv2.hsgw_addr_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_gre_key,
          {"GRE Key", "gtpv2.gre_key",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL , HFILL}
        },
        { &hf_gtpv2_sgw_addr_ipv4,
          {"Serving GW Address", "gtpv2.sgw_addr_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_sgw_addr_ipv6,
          {"Serving GW Address", "gtpv2.sgw_addr_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_sgw_s1u_teid,
          {"Serving GW S1-U TEID", "gtpv2.sgw_s1u_teid",
           FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_delay_value,
         {"Delay Value (In integer multiples of 50 milliseconds or zero)", "gtpv2.delay_value",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_charging_id,
         {"Charging id", "gtpv2.charging_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_charging_characteristic,
         {"Charging Characteristic", "gtpv2.charging_characteristic",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_flag_ppc,
         {"PPC (Prohibit Payload Compression)", "gtpv2.bearer_flag.ppc",
          FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_flag_vb,
         {"VB (Voice Bearer)", "gtpv2.bearer_flag.vb",
          FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL}
        },
        {&hf_gtpv2_pti,
         {"Procedure Transaction Id", "gtpv2.pti",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* MM Context */
        { &hf_gtpv2_mm_context_sm,
          {"Security Mode", "gtpv2.mm_context_sm",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mm_context_security_mode), 0xe0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_nhi,
          {"NHI(Next Hop Indicator)", "gtpv2.mm_context_nhi",
           FT_BOOLEAN, 8, TFS(&gtpv2_nhi_vals), 0x10,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_drxi,
          {"DRXI", "gtpv2.mm_context_drxi",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_cksn,
          {"CKSN", "gtpv2.mm_context_cksn",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_cksn_ksi,
          {"CKSN/KSI", "gtpv2.mm_context_cksn_ksi",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_metric,
          {"Metric", "gtpv2.metric",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_throttling_factor,
          {"Throttling Factor", "gtpv2.throttling_factor",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_gtpv2_relative_capacity,
          {"Relative Capacity", "gtpv2.relative_capacity",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_apn_length,
          {"APN Length", "gtpv2.apn_length",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_sequence_number,
          {"Sequence Number", "gtpv2.sequence_number",
           FT_UINT32, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_ksi_a,
          {"KSI_asme", "gtpv2.mm_context_ksi_a",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_nr_tri,
          {"Number of Triplet", "gtpv2.mm_context_nr_tri",
           FT_UINT8, BASE_DEC, NULL, 0xe0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_used_cipher,
          {"Used Cipher", "gtpv2.mm_context_used_cipher",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mm_context_used_cipher_vals), 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_unipa,
          {"Used NAS integrity protection algorithm", "gtpv2.mm_context_unipa",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mm_context_unipa_vals), 0x70,
           NULL, HFILL}
        },

        { &hf_gtpv2_mm_context_unc,
          {"Used NAS Cipher", "gtpv2.mm_context_unc",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mm_context_unc_vals), 0x0f,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_nas_dl_cnt,
          {"NAS Downlink Count", "gtpv2.mm_context_nas_dl_cnt",
           FT_UINT24, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_nas_ul_cnt,
          {"NAS Uplink Count", "gtpv2.mm_context_nas_ul_cnt",
           FT_UINT24, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_kasme,
          {"Kasme", "gtpv2.mm_context_kasme",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_rand,
          {"RAND", "gtpv2.mm_context_rand",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_uci_csg_id,
          {"CSG ID", "gtpv2.cui_csg_id",
           FT_UINT32, BASE_DEC, NULL, 0x07FFFFFF,
           NULL, HFILL}
        },
        {&hf_gtpv2_uci_csg_id_spare,
          {"Spare", "gtpv2.cui_csg_id_spare",
           FT_UINT8, BASE_DEC, NULL, 0xF8,
           NULL, HFILL}
        },
        { &hf_gtpv2_uci_csg_membership,
          { "CSG Membership Indication", "gtpv2.uci_csg_membership",
           FT_UINT8, BASE_DEC, VALS(gtpv2_uci_csg_membership_status), 0x01,
           NULL, HFILL }
        },
        { &hf_gtpv2_uci_access_mode,
          {"Access Mode", "gtpv2.uci_access_mode",
           FT_UINT8, BASE_DEC, VALS(gtpv2_uci_access_mode), 0xC0,
           NULL, HFILL }
        },
        { &hf_gtpv2_uci_lcsg,
          {"Leave CSG", "gtpv2.uci_leave_csg",
           FT_UINT8, BASE_DEC, VALS(gtpv2_uci_leave_csg), 0x02,
           NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_xres_len,
          {"XRES Length", "gtpv2.mm_context_xres_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_xres,
          {"XRES", "gtpv2.mm_context_xres",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_autn_len,
          {"AUTN Length", "gtpv2.mm_context_autn_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_autn,
          {"AUTN", "gtpv2.mm_context_autn",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_drx,
          {"DRX", "gtpv2.mm_context_drx",
           FT_UINT16, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_vdp_length,
          {"VDP and UE's Usage Setting length", "gtpv2.vdp_length",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },

        { &hf_gtpv2_mm_context_ue_net_cap_len,
          {"Length of UE Network Capability", "gtpv2.mm_context_ue_net_cap_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_ms_net_cap_len,
          {"Length of MS Network Capability", "gtpv2.mm_context_ms_net_cap_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_mei_len,
          {"Length of Mobile Equipment Identity (MEI)", "gtpv2.mm_context_mei_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_contex_nhi_old,
        { "Next Hop Indicator for old EPS Security Context", "gtpv2.mm_context_nhi_old",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_old_ksiasme,
        { "old KSIASME", "gtpv2.old_ksiasme",
            FT_UINT8, BASE_DEC, NULL, 0x38,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_old_ncc,
        { "old NCC", "gtpv2.old_ncc",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_old_kasme,
        { "Old Kasme", "gtpv2.mm_context_old_kasme",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_old_nh,{ "Old NH (Old Next Hop)", "gtpv2.mm_context.old_nh", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gtpv2_mm_context_vdp_len,
        { "Length of Voice Domain Preference and UE's Usage Setting", "gtpv2.mm_context.vdp_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_paging_len,
        { "Length of UE Radio Capability for Paging information", "gtpv2.mm_context.paging_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_ex_access_res_data_len,
        { "Length of Extended Access Restriction Data", "gtpv2.mm_context.ex_access_res_data_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_ue_add_sec_cap_len,
        { "Length of UE additional security capability", "gtpv2.mm_context.ue_add_sec_cap_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_ue_nr_sec_cap_len,
        { "Length of UE NR security capability", "gtpv2.mm_context.ue_nr_sec_cap_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_apn_rte_ctrl_sts_len,
        { "Length of APN Rate Control Statuses", "gtpv2.mm_context.apn_rte_ctrl_sts_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_cnr_len,
        { "Length of Core Network Restrictions", "gtpv2.mm_context.cnr_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_ue_radio_cap_len,
        { "Length of UE Radio Capability ID", "gtpv2.mm_context.radio_cap_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtpv2_una,
          { "UTRAN", "gtpv2.mm_context.una",
            FT_BOOLEAN, 8, TFS(&tfs_not_allowed_allowed), 0x01,
            NULL, HFILL }
        },
        { &hf_gtpv2_gena,
          { "GERAN", "gtpv2.mm_context.gena",
            FT_BOOLEAN, 8, TFS(&tfs_not_allowed_allowed), 0x02,
            NULL, HFILL }
        },
        { &hf_gtpv2_gana,
          { "GAN", "gtpv2.mm_context.gana",
            FT_BOOLEAN, 8, TFS(&tfs_not_allowed_allowed), 0x04,
            NULL, HFILL }
        },
        { &hf_gtpv2_ina,
          { "I-HSPA-EVOLUTION", "gtpv2.mm_context.ina",
            FT_BOOLEAN, 8, TFS(&tfs_not_allowed_allowed), 0x08,
            NULL, HFILL }
        },
        { &hf_gtpv2_ena,
          { "E-UTRAN", "gtpv2.mm_context.ena",
            FT_BOOLEAN, 8, TFS(&tfs_not_allowed_allowed), 0x10,
            NULL, HFILL }
        },
        { &hf_gtpv2_hnna,
          { "HO-toNone3GPP-Access", "gtpv2.mm_context.hnna",
            FT_BOOLEAN, 8, TFS(&tfs_not_allowed_allowed), 0x20,
            NULL, HFILL }
        },
        { &hf_gtpv2_hbna,
        { "NB-IoT Not Allowed", "gtpv2.mm_context.hbna",
            FT_BOOLEAN, 8, TFS(&tfs_not_allowed_allowed), 0x40,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_ksi,
          {"KSI", "gtpv2.mm_context_ksi",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_nr_qui,
          {"Number of Quintuplets", "gtpv2.mm_context_nr_qui",
           FT_UINT8, BASE_DEC, NULL, 0xe0,
           NULL, HFILL}
        },

        { &hf_gtpv2_mm_context_nr_qua,
          {"Number of Quadruplet", "gtpv2.mm_context_nr_qua",
           FT_UINT8, BASE_DEC, NULL, 0x1c,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_uamb_ri,
          {"UAMB RI", "gtpv2.mm_context_uamb_ri",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_osci,
          {"OSCI", "gtpv2.mm_context_osci",
           FT_BOOLEAN, 8, NULL, 0x01,
           "Old Security Context Indicator", HFILL}
        },
        { &hf_gtpv2_mm_context_nruna,
        { "NRUNA (NR-U in 5GS Not Allowed)", "gtpv2.mm_context.nruna",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_nrusrna,
        { "NRUSRNA (New Radio Unlicensed as Secondary RAT Not Allowed)", "gtpv2.mm_context.nrusrna",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_nrna,
        { "NRNA(NR in 5GS Not Allowed)", "gtpv2.mm_context.nrna",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_ussrna,
          {"USSRNA", "gtpv2.mm_context_ussrna",
           FT_BOOLEAN, 8, NULL, 0x02,
           "Unlicensed Spectrum in the form of LAA or LWA/LWIP as Secondary RAT Not Allowed", HFILL}
        },
        { &hf_gtpv2_mm_context_nrsrna,
          {"NRSRNA(NR as Secondary RAT Not Allowed)", "gtpv2.mm_context_nrsrna",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_ensct,
          {"ENSCT (EPS NAS Security Context Type)", "gtpv2.mm_context_ensct",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mm_context_eps_nas_security_context_type_vals), 0x03,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_samb_ri,
          {"SAMB RI", "gtpv2.mm_context_samb_ri",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ue_time_zone_dst,
          {"Daylight Saving Time", "gtpv2.ue_time_zone_dst",
           FT_UINT8, BASE_DEC, VALS(gtpv2_ue_time_zone_dst_vals), 0x03,
           NULL, HFILL}
        },
        { &hf_gtpv2_fq_csid_type,
          {"Node-ID Type", "gtpv2.fq_csid_type",
           FT_UINT8, BASE_DEC, NULL, 0xf0,
           NULL, HFILL}
        },
        { &hf_gtpv2_fq_csid_nr,
          {"Number of CSIDs", "gtpv2.fq_csid_nr",
           FT_UINT8, BASE_DEC, NULL, 0x0f,
           NULL, HFILL}
        },
        { &hf_gtpv2_fq_csid_ipv4,
          {"Node-ID (IPv4)", "gtpv2.fq_csid_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_fq_csid_ipv6,
          {"Node-ID (IPv6)", "gtpv2.fq_csid_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_fq_csid_id,
          {"CSID", "gtpv2.fq_csid_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_complete_req_msg_type,
          {"Complete Request Message Type", "gtpv2.complete_req_msg_type",
           FT_UINT8, BASE_DEC, VALS(gtpv2_complete_req_msg_type_vals), 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_mme_grp_id,
         {"MME Group ID", "gtpv2.mme_grp_id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_mme_code,
          {"MME Code", "gtpv2.mme_code",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_m_tmsi,
          {"M-TMSI", "gtpv2.m_tmsi",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_container_type,
          {"Container Type", "gtpv2.container_type",
           FT_UINT8, BASE_DEC, VALS(gtpv2_container_type_vals), 0x0f,
           NULL, HFILL}
        },
        { &hf_gtpv2_cause_type,
          {"Cause Type", "gtpv2.cause_type",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_cause_type_vals_ext, 0x0f,
           NULL, HFILL}
        },
        { &hf_gtpv2_CauseRadioNetwork,
          {"Radio Network Layer Cause", "gtpv2.CauseRadioNetwork",
           FT_UINT8, BASE_DEC, VALS(s1ap_CauseRadioNetwork_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_CauseTransport,
          {"Transport Layer Cause", "gtpv2.CauseTransport",
           FT_UINT8, BASE_DEC, VALS(s1ap_CauseTransport_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_CauseNas,
          {"NAS Cause", "gtpv2.CauseNas",
           FT_UINT8, BASE_DEC, VALS(s1ap_CauseNas_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_CauseMisc,
          {"Miscellaneous Cause", "gtpv2.CauseMisc",
           FT_UINT8, BASE_DEC, VALS(s1ap_CauseMisc_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_target_type,
          {"Target Type", "gtpv2.target_type",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_target_type_vals_ext, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_macro_enodeb_id,
         {"Macro eNodeB ID", "gtpv2.macro_enodeb_id",
          FT_UINT24, BASE_HEX, NULL, 0x0fffff,
          NULL, HFILL}
        },
        {&hf_gtpv2_smenb,
         {"SMeNB", "gtpv2.smenb",
          FT_BOOLEAN, 8, TFS(&gtpv2_smenb), 0x80,
          NULL, HFILL}
        },
        {&hf_gtpv2_ext_macro_enodeb_id,
         {"Extended Macro eNodeB ID", "gtpv2.ext_macro_enodeb_id",
          FT_UINT24, BASE_HEX, NULL, 0x1fffff,
          NULL, HFILL}
        },
        {&hf_gtpv2_ext_macro_ng_enodeb_id,
         {"Extended Macro ng-eNodeB ID", "gtpv2.ext_macro_ng_enodeb_id",
          FT_UINT24, BASE_HEX, NULL, 0x1fffff,
          NULL, HFILL}
        },
        {&hf_gtpv2_cellid,
         {"CellId", "gtpv2.cellid",
          FT_UINT32, BASE_DEC, NULL, 0xFF,
          NULL, HFILL}
        },
        { &hf_gtpv2_enodebid,
         { "eNodeB Id", "gtpv2.enodebid",
          FT_UINT32, BASE_DEC, NULL, 0x0FFFFF00,
          NULL, HFILL }
         },
        { &hf_gtpv2_CauseProtocol,
          {"Protocol Cause", "gtpv2.CauseProtocol",
           FT_UINT8, BASE_DEC, VALS(s1ap_CauseProtocol_vals), 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_apn_rest,
         {"APN Restriction", "gtpv2.apn_rest",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_apn_restriction_vals_ext, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_selec_mode,
         {"Selection Mode", "gtpv2.selec_mode",
          FT_UINT8, BASE_DEC, VALS(gtpv2_selec_mode_vals), 0x03,
          NULL, HFILL}
        },
        { &hf_gtpv2_source_type,
          {"Source Type", "gtpv2.source_type",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_bearer_control_mode,
         {"Bearer Control Mode", "gtpv2.bearer_control_mode",
          FT_UINT8, BASE_DEC, VALS(gtpv2_bearer_control_mode_vals), 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_cng_rep_act,
          {"Change Reporting Action", "gtpv2.cng_rep_act",
           FT_UINT8, BASE_DEC, VALS(gtpv2_cng_rep_act_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_node_type,
          {"Node Type", "gtpv2.node_type",
           FT_UINT8, BASE_DEC, VALS(gtpv2_node_type_vals), 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_fqdn,
         {"FQDN", "gtpv2.fqdn",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_enterprise_id,
          {"Enterprise ID", "gtpv2.enterprise_id",
           FT_UINT16, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ti,
          {"Transaction Identifier", "gtpv2.ti",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_container_phx,
          {"PHX", "gtpv2.bss_cont.phx",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_sapi_flg,
          {"SAPI", "gtpv2.bss_cont.sapi_flg",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_rp_flg,
          {"RP", "gtpv2.bss_cont.rp_flg",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_pfi_flg,
          {"PFI", "gtpv2.bss_cont.pfi_flg",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_pfi,
          {"Packet Flow ID(PFI)", "gtpv2.bss_cont.pfi",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_rp,
          {"Radio Priority(RP)", "gtpv2.bss_cont.rp",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_sapi,
          {"SAPI", "gtpv2.bss_cont.sapi",
           FT_UINT8, BASE_DEC, NULL, 0xf0,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_xid_len,
          {"XiD parameters length", "gtpv2.bss_cont.xid_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_xid,
          {"XiD parameters", "gtpv2.bss_cont.xid",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_home_enodeb_id,
          {"Home eNodeB ID", "gtpv2.home_enodeb_id",
           FT_UINT32, BASE_HEX, NULL, 0x0fffffff,
           NULL, HFILL}
        },
        { &hf_gtpv2_tac,
          {"Tracking Area Code (TAC)", "gtpv2.tac",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_service_area_nr,
          {"Number of MBMS Service Area codes", "gtpv2.mbms_service_area_nr",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_service_area_id,
          {"MBMS Service Area code (Service Area Identity)", "gtpv2.mbms_service_area_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_session_id,
          {"MBMS Session Identifier", "gtpv2.mbms_session_id",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_flow_id,
          {"MBMS Flow Identifier", "gtpv2.mbms_flow_id",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_cteid,
          {"Common Tunnel Endpoint Identifier", "gtpv2.cetid",
           FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ip_addr_type,
          {"IP Address Type", "gtpv2.ip_addr_type",
           FT_UINT8, BASE_DEC, NULL, 0xc0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ip_addr_len,
          {"IP Address Length", "gtpv2.ip_addr_len",
           FT_UINT8, BASE_DEC, NULL, 0x3f,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_ip_mc_dist_addrv4,
          {"MBMS IP Multicast Distribution Address (IPv4)", "gtpv2.mbms_ip_mc_dist_addrv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_ip_mc_dist_addrv6,
          {"MBMS IP Multicast Distribution Address (IPv6)", "gtpv2.mbms_ip_mc_dist_addrv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_ip_mc_src_addrv4,
          {"MBMS IP Multicast Source Address (IPv4)", "gtpv2.mbms_ip_mc_src_addrv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_ip_mc_src_addrv6,
          {"MBMS IP Multicast Source Address (IPv6)", "gtpv2.mbms_ip_mc_src_addrv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_hc_indicator,
          {"MBMS HC Indicator", "gtpv2.mbms_hc_indicator",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mbms_hc_indicator_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_dist_indication,
          {"MBMS Distribution Indication", "gtpv2.mbms_dist_indication",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mbms_dist_indication_vals), 0x03,
           NULL, HFILL}
        },
        { &hf_gtpv2_subscriber_rfsp,
          {"Subscribed RFSP Index", "gtpv2.subscriber_rfsp",
           FT_INT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_rfsp_inuse,
          {"RFSP Index in Use", "gtpv2.rfsp_inuse",
           FT_INT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_service_id,
          {"MBMS Service ID", "gtpv2.mbms_service_id",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_add_flags_for_srvcc_ics,
          {"ICS (IMS Centralized Service)", "gtpv2.add_flags_for_srvcc_ics",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_vsrvcc_flag,
          {"VF (vSRVCC Flag)", "gtpv2.vsrvcc_flag",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_henb_info_report_fti,
          {"FTI", "gtpv2.henb_info_report_fti",
           FT_BOOLEAN, 8, TFS(&gtpv2_henb_info_report_fti_vals), 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_ip4cp_subnet_prefix_len,
          {"Subnet Prefix Length", "gtpv2.ip4cp_subnet_prefix_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ip4cp_ipv4,
          {"IPv4 Default Router Address", "gtpv2.ip4cp_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_change_report_flags_sncr,
          {"SNCR (Service Network Change to Report)", "gtpv2.change_report_flags_sncr",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_change_report_flags_tzcr,
          {"TZCR (Time Zone Change to Report)", "gtpv2.change_report_flags_tzcr",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        {&hf_gtpv2_action_indication_val,
         {"Action Indication", "gtpv2.action_indication_val",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_action_indication_vals_ext, 0x07,
          NULL , HFILL}
        },
        { &hf_gtpv2_uli_timestamp,
        { "ULI Timestamp", "gtpv2.uli_timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
        NULL, HFILL }
        },
        { &hf_gtpv2_abs_time_mbms_data,
        { "Absolute Time of MBMS Data Transfer", "gtpv2.abs_time_mbms_data",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0,
        NULL, HFILL }
        },
        { &hf_gtpv2_mbms_session_duration_days,
          {"MBMS Session Duration (days)", "gtpv2.mbms_session_duration_days",
           FT_UINT24, BASE_DEC, NULL, 0x00007F,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_session_duration_secs,
          {"MBMS Session Duration (seconds)", "gtpv2.mbms_session_duration_secs",
           FT_UINT24, BASE_DEC, NULL, 0xFFFF80,
           NULL, HFILL}
        },
        { &hf_gtpv2_csg_id,
          {"CSG ID", "gtpv2.csg_id",
           FT_UINT32, BASE_HEX, NULL, 0x07ffffff,
           NULL, HFILL}
        },
        { &hf_gtpv2_cmi,
          {"CSG Membership Indication (CMI)", "gtpv2.cmi",
           FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_service_indicator,
          {"Service Indicator", "gtpv2.service_indicator",
           FT_UINT8, BASE_DEC, VALS(gtpv2_service_indicator_vals), 0,
           NULL, HFILL}
        },
        { &hf_gtpv2_detach_type,
          {"Detach Type", "gtpv2.detach_type",
           FT_UINT8, BASE_DEC, VALS(gtpv2_detach_type_vals), 0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ldn,
          {"Local Distinguished Name (LDN)", "gtpv2.ldn",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_gtpv2_node_features_prn,
          {"PGW Restart Notification (PRN)", "gtpv2.node_features_prn",
           FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_node_features_mabr,
          {"Modify Access Bearers Request (MABR)", "gtpv2.node_features_mabr",
           FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_node_features_ntsr,
          {"Network Triggered Service Restoration (NTSR)", "gtpv2.node_features_ntsr",
           FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
           NULL, HFILL}
        },
        { &hf_gtpv2_node_features_ciot,
          {"Cellular Internet Of Things (CIOT)", "gtpv2.node_features_ciot",
           FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
           NULL, HFILL}
        },
        { &hf_gtpv2_node_features_s1un,
          {"S1-U path failure notification feature (S1UN)", "gtpv2.node_features_s1un",
           FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10,
           NULL, HFILL}
        },
        { &hf_gtpv2_node_features_eth,
          {"Ethernet PDN type (ETH)", "gtpv2.node_features_eth",
           FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
           NULL, HFILL}
        },
        { &hf_gtpv2_node_features_mtedt,
          {"Support of MT-EDT (MTEDT)", "gtpv2.node_features_mtedt",
           FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40,
           NULL, HFILL}
        },
        { &hf_gtpv2_node_features_psset,
          {"Support of PGW-C/SMF Set (PSSET)", "gtpv2.node_features_psset",
           FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
           NULL, HFILL}
        },
        { &hf_gtpv2_time_to_data_xfer,
          {"MBMS Time to Data Transfer", "gtpv2.time_to_data_xfer",
           FT_STRING, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        { &hf_gtpv2_arp_pvi,
          {"Pre-emption Vulnerability (PVI)", "gtpv2.arp_pvi",
           FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled), 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_arp_pl,
          {"Priority Level", "gtpv2.arp_pl",
           FT_UINT8, BASE_DEC, NULL, 0x3c,
           NULL, HFILL}
        },
        { &hf_gtpv2_arp_pci,
          {"Pre-emption Capability (PCI)", "gtpv2.arp_pci",
           FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled), 0x40,
           NULL, HFILL}
        },
        { &hf_gtpv2_timer_unit,
          {"Timer unit", "gtpv2.timer_unit",
           FT_UINT8, BASE_DEC, VALS(gtpv2_timer_unit_vals), 0xe0,
           NULL, HFILL}
        },
        { &hf_gtpv2_throttling_delay_unit,
          {"Throttling Delay unit", "gtpv2.throttling_delay_unit",
           FT_UINT8, BASE_DEC, VALS(gtpv2_throttling_delay_unit_vals), 0xe0,
           NULL, HFILL }
        },
        { &hf_gtpv2_timer_value,
          {"Timer value", "gtpv2.timer_value",
           FT_UINT8, BASE_DEC, NULL, 0x1f,
           NULL, HFILL}
        },
        { &hf_gtpv2_throttling_delay_value,
          {"Throttling Delay value", "gtpv2.throttling_delay_value",
           FT_UINT8, BASE_DEC, NULL, 0x1f,
           NULL, HFILL }
        },
        { &hf_gtpv2_lapi,
          {"LAPI (Low Access Priority Indication)", "gtpv2.lapi",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_higher_br_16mb_flg_len,
          {"Length of Higher bitrates than 16 Mbps flag", "gtpv2.mm_context_higher_br_16mb_flg_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_higher_br_16mb_flg,
          {"Higher bitrates than 16 Mbps flag", "gtpv2.mm_context_higher_br_16mb_flg",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mm_context_higher_br_16mb_flg_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mmbr_ul,
          {"Max MBR/APN-AMBR for uplink", "gtpv2.mmbr_ul",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mmbr_dl,
          {"Max MBR/APN-AMBR for downlink", "gtpv2.mmbr_dl",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_act_inapra,
          {"INAPRA", "gtpv2.pres_rep_area_action.inapra",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_action,
          {"Action", "gtpv2.pres_rep_area_action.action",
           FT_UINT8, BASE_DEC, VALS(gtpv2_pres_rep_area_action_vals), 0x03,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_id,
          {"Presence Reporting Area Identifier", "gtpv2.pres_rep_area_action.pres_rep_area_id",
           FT_UINT24, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_act_no_tai,
          {"Number of TAI", "gtpv2.pres_rep_area_action.no_tai",
           FT_UINT8, BASE_DEC, NULL, 0xf0,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_act_no_rai,
          {"Number of RAI", "gtpv2.pres_rep_area_action.no_rai",
           FT_UINT8, BASE_DEC, NULL, 0x0f,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_act_no_m_enodeb,
          {"Number of Macro eNodeB", "gtpv2.pres_rep_area_action.no_m_enodeb",
           FT_UINT8, BASE_DEC, NULL, 0x3f,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_act_no_h_enodeb,
          {"Number of Home eNodeB", "gtpv2.pres_rep_area_action.no_h_enodeb",
           FT_UINT8, BASE_DEC, NULL, 0x3f,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_act_no_ecgi,
          {"Number of ECGI", "gtpv2.pres_rep_area_action.no_ecgi",
           FT_UINT8, BASE_DEC, NULL, 0x3f,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_act_no_sai,
          {"Number of SAI", "gtpv2.pres_rep_area_action.no_sai",
           FT_UINT8, BASE_DEC, NULL, 0x3f,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_act_no_cgi,
          {"Number of CGI", "gtpv2.pres_rep_area_action.no_cgi",
           FT_UINT8, BASE_DEC, NULL, 0x3f,
           NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_act_no_ext_m_enodeb,
          {"Number of Extended Macro eNodeB", "gtpv2.pres_rep_area_action.no_ext_m_enodeb",
           FT_UINT8, BASE_DEC, NULL, 0x3f,
           NULL, HFILL}
        },
        { &hf_gtpv2_ksi_ps,
            { "KSI'ps", "gtpv2.ksi_ps",
            FT_UINT8, BASE_HEX, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_gtpv2_ck_ps,
        { "CK'ps", "gtpv2.ck_ps",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_gtpv2_ik_ps,
        { "IK'ps", "gtpv2.ik_ps",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_gtpv2_kc_ps,
        { "KC'ps", "gtpv2.kc_ps",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_gtpv2_cksn_ps,
        { "CKSN'ps", "gtpv2.cksn_ps",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtpv2_pres_rep_area_info_id,
          {"Presence Reporting Area Identifier", "gtpv2.pres_rep_area_info_id",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_info_additional_id,
          {"Additional Presence Reporting Area Identifier", "gtpv2.pres_rep_area_info_additional_id",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_info_flags,
          {"Flags", "gtpv2.pres_rep_area_info_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_info_flags_no_inapra,
          {"Flags", "gtpv2.pres_rep_area_info_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_info_flags_b0_ipra,
          {"Inside Presence Reporting Area(IPRA)", "gtpv2.pres_rep_area_info_flag_ipra",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_info_flags_b1_opra,
          {"Outside Presence Reporting Area(OPRA)", "gtpv2.pres_rep_area_info_flag_opra",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_info_flags_b2_apra,
          {"Additional Presence Reporting Area(APRA)", "gtpv2.pres_rep_area_info_flag_apra",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_info_flags_b3_inapra,
          {"Inactive Presence Reporting Area(INAPRA)", "gtpv2.pres_rep_area_info_flag_inapra",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_info_flags_b3_b7_spare,
          {"Spare", "gtpv2.pres_rep_area_info_spare",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
             NULL, HFILL}
        },
        { &hf_gtpv2_pres_rep_area_info_flags_b4_b7_spare,
          {"Spare", "gtpv2.pres_rep_area_info_spare",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
             NULL, HFILL}
        },
        { &hf_gtpv2_ppi_value,
            {"Paging and Policy Information Value", "gtpv2.ppi_value",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
            &dscp_vals_ext, GTPV2_PPI_VAL_MASK, NULL, HFILL}
        },
        { &hf_gtpv2_ppi_flag,
            {"Paging Policy Indication", "gtpv2.ppi_flag",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtpv2_session,
            { "Session", "gtpv2.session",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_gtpv2_transparent_container, { "Transparent Container", "gtpv2.transparent_container", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_cksrvcc, { "CKsrvcc", "gtpv2.cksrvcc", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_iksrvcc, { "IKsrvcc", "gtpv2.iksrvcc", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_mobile_station_classmark2, { "Mobile Station Classmark2", "gtpv2.mobile_station_classmark2", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_mobile_station_classmark3, { "Mobile Station Classmark3", "gtpv2.mobile_station_classmark3", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_supported_codec_list, { "Supported Codec List", "gtpv2.supported_codec_list", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_utran_srvcc_ck_cs, { "CK'cs", "gtpv2.utran_srvcc.ck_cs", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_utran_srvcc_ik_cs, { "IK'cs", "gtpv2.utran_srvcc.ik_cs", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_utran_srvcc_kc, { "Kc'", "gtpv2.utran_srvcc.kc", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_teid_c_spare, { "Spare", "gtpv2.teid_c.spare", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_geographic_location, { "Geographic Location", "gtpv2.geographic_location", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_tmsi_bytes, { "TMSI", "gtpv2.tmsi_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_cn_id, { "CN-Id", "gtpv2.cn_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_eps_bearer_id_number, { "EPS Bearer ID Number", "gtpv2.eps_bearer_id_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_serving_gw_address_length, { "Serving GW Address Length", "gtpv2.serving_gw_address_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_charging_characteristic_remaining_octets, { "Remaining octets", "gtpv2.charging_characteristic.remaining_octets", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_trace_id, { "Trace ID", "gtpv2.trace_id", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_drx_parameter, { "DRX parameter", "gtpv2.drx_parameter", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_mm_context_sres, { "SRES'", "gtpv2.mm_context_sres", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_mm_context_kc, { "Kc'", "gtpv2.mm_context_kc", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_uplink_subscribed_ue_ambr, { "Uplink Subscribed UE AMBR", "gtpv2.uplink_subscribed_ue_ambr", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0, NULL, HFILL }},
      { &hf_gtpv2_downlink_subscribed_ue_ambr, { "Downlink Subscribed UE AMBR", "gtpv2.downlink_subscribed_ue_ambr", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0, NULL, HFILL }},
      { &hf_gtpv2_uplink_used_ue_ambr, { "Uplink Used UE AMBR", "gtpv2.uplink_used_ue_ambr", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0, NULL, HFILL }},
      { &hf_gtpv2_downlink_used_ue_ambr, { "Downlink Used UE AMBR", "gtpv2.downlink_used_ue_ambr", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0, NULL, HFILL }},
      { &hf_gtpv2_voice_domain_and_ue_usage_setting, { "Voice Domain Preference and UE's Usage Setting", "gtpv2.voice_domain_and_ue_usage_setting", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_ue_radio_capability_for_paging_information,{ "UE Radio Capability for Paging information", "gtpv2.UE_Radio_Capability_for_Paging_information", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_authentication_quadruplets, { "Authentication Quadruplets", "gtpv2.authentication_quadruplets", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_authentication_quintuplets, { "Authentication Quintuplets", "gtpv2.authentication_quintuplets", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_mm_context_nh, { "NH (Next Hop)", "gtpv2.mm_context_nh", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_mm_context_ncc, { "NCC (Next Hop Chaining Count)", "gtpv2.mm_context_ncc", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_gtpv2_nsapi08, { "NSAPI", "gtpv2.nsapi", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL }},
      { &hf_gtpv2_dl_gtp_u_sequence_number, { "DL GTP-U Sequence Number", "gtpv2.dl_gtp_u_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_ul_gtp_u_sequence_number, { "UL GTP-U Sequence Number", "gtpv2.ul_gtp_u_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_send_n_pdu_number, { "Send N-PDU Number", "gtpv2.send_n_pdu_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_receive_n_pdu_number, { "Receive N-PDU Number", "gtpv2.receive_n_pdu_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_hop_counter, { "Hop Counter", "gtpv2.hop_counter", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_packet_flow_id, { "Packet Flow ID", "gtpv2.packet_flow_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_rrc_container, { "RRC Container", "gtpv2.rrc_container", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_port_number, { "Port Number", "gtpv2.port_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_proprietary_value, { "Proprietary value", "gtpv2.proprietary_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_spare_bytes, { "Spare", "gtpv2.spare_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_dl_pdcp_sequence_number, { "DL PDCP Sequence Number", "gtpv2.dl_pdcp_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_ul_pdcp_sequence_number, { "UL PDCP Sequence Number", "gtpv2.ul_pdcp_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtpv2_fq_csid_node_id, { "Node-ID", "gtpv2.fq_csid_node_id", FT_UINT32, BASE_DEC, NULL, 0x00000FFF, NULL, HFILL }},
      { &hf_gtpv2_fq_csid_mcc_mnc, { "MCC+MNC", "gtpv2.fq_csid_mcc_mnc", FT_UINT32, BASE_DEC, NULL, 0xFFFFF000, NULL, HFILL }},

      { &hf_gtpv2_twan_id_ts, { "TWAN Identifier Timestamp", "gtpv2.twan.id_ts", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0, NULL, HFILL } },
      { &hf_gtpv2_twan_flags,{ "Flags", "gtpv2.twan_id.flags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_bssidi,{ "BSSIDI", "gtpv2.twan_id.bssidi", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01, NULL, HFILL } },
      { &hf_gtpv2_twan_civai,{ "CIVAI", "gtpv2.twan_id.civai", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02, NULL, HFILL } },
      { &hf_gtpv2_twan_plmni,{ "PLMNI", "gtpv2.twan_id.plmni", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04, NULL, HFILL } },
      { &hf_gtpv2_twan_opnai,{ "OPNAI", "gtpv2.twan_id.opnai", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08, NULL, HFILL } },
      { &hf_gtpv2_twan_laii,{ "LAII", "gtpv2.twan_id.laii", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x10, NULL, HFILL } },
      { &hf_gtpv2_twan_ssid_len,{ "SSID Length", "gtpv2.twan_id.ssid_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_ssid,{ "SSID", "gtpv2.twan_id.ssid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_bssid,{ "BSSID", "gtpv2.twan_id.bssid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_civa_len,{ "Civic Address Length", "gtpv2.twan_id.civa_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_civa,{ "Civic Address Information", "gtpv2.twan_id.civa", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_plmnid,{ "TWAN PLMN-ID", "gtpv2.twan_id.plmnid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_op_name_len,{ "TWAN Operator Name Length", "gtpv2.twan_id.op_name_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_op_name,{ "TWAN Operator Name", "gtpv2.twan_id.op_name", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_relay_id_type,{ "Relay Identity Type", "gtpv2.twan_id.relay_id_type", FT_UINT8, BASE_DEC, VALS(gtpv2_twan_relay_id_type_vals), 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_relay_id_len,{ "Relay Identity Type Length", "gtpv2.twan_id.relay_id_type_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_relay_id,{ "Relay Identity", "gtpv2.twan_id.relay_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_relay_id_ipv4,{ "Relay Identity", "gtpv2.twan_id.relay_id_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_relay_id_ipv6,{ "Relay Identity", "gtpv2.twan_id.relay_id_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_circuit_id_len,{ "Relay Identity Type Length", "gtpv2.twan_id.relay_id_type_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_twan_circuit_id,{ "Circuit-ID", "gtpv2.twan_id.circuit_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_integer_number_val,{ "Value", "gtpv2.integer_number_val", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_maximum_wait_time,{ "Maximum Wait Time", "gtpv2.maximum_wait_time", FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0, NULL, HFILL } },
      { &hf_gtpv2_dl_buf_sug_pkt_cnt,{ "DL Buffering Suggested Packet Count", "gtpv2.dl_buf_sug_pkt_cnt", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_ue_usage_type,{ "UE Usage Type", "gtpv2.ue_usage_type", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_rem_run_serv_gap_t,{ "Remaining Running Service Gap Timer", "gtpv2.rem_run_serv_gap_t", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_ran_nas_protocol_type, {"RAN/NAS Protocol Type", "gtpv2.ran_nas.protocol_type", FT_UINT8, BASE_DEC, VALS(ran_nas_prot_type_vals), 0xF0, NULL, HFILL} },
      { &hf_gtpv2_ran_nas_cause_type, {"RAN/NAS S1AP Cause Type", "gtpv2.ran_nas.s1ap_type", FT_UINT8, BASE_DEC, VALS(s1ap_Cause_vals), 0x0F, NULL, HFILL} },
      { &hf_gtpv2_ran_nas_cause_value, {"RAN/NAS Cause Value", "gtpv2.ran_nas.cause_value", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL} },
      { &hf_gtpv2_emm_cause, {"EMM Cause Value", "gtpv2.ran_nas.emm_cause", FT_UINT8, BASE_DEC, VALS(nas_eps_emm_cause_values), 0x0, NULL, HFILL} },
      { &hf_gtpv2_esm_cause, {"ESM Cause Value", "gtpv2.ran_nas.esm_cause", FT_UINT8, BASE_DEC, VALS(nas_eps_esm_cause_vals), 0x0, NULL, HFILL} },
      { &hf_gtpv2_diameter_cause, {"Diameter Cause Value", "gtpv2.ran_nas.diameter_cause", FT_UINT16, BASE_DEC, VALS(diameter_3gpp_termination_cause_vals), 0x0, NULL, HFILL} },
      { &hf_gtpv2_ikev2_cause, {"IKEv2 Cause Value", "gtpv2.ran_nas.ikev2_cause", FT_UINT16, BASE_DEC, VALS(diameter_3gpp_IKEv2_error_type_vals), 0x0, NULL, HFILL} },
      { &hf_gtpv2_ciot_support_ind,{ "CIoT Optimizations Support Indication", "gtpv2.ciot_support_ind", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_gtpv2_ciot_support_ind_spare_bits,
          { "Spare", "gtpv2.ciot_support_ind.spare_bits",
          FT_UINT8, BASE_HEX, NULL, 0xF0,
          NULL, HFILL }
      },
      { &hf_gtpv2_ciot_support_ind_bit4,
          { "IHCSI (IP Header Compression Support)", "gtpv2.ciot_support_ind.ihcsi",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ciot_support_ind_bit3,
          { "AWOPDN (Attach without PDN Support)", "gtpv2.ciot_support_ind.awopdn",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ciot_support_ind_bit2,
          { "SCNIPDN (SCEF Non-IP PDN Support)", "gtpv2.ciot_support_ind.scnipdn",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ciot_support_ind_bit1,
          { "SGNIPDN (SGi Non-IP PDN Support)", "gtpv2.ciot_support_ind.sgnipdn",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_length_of_node_name,
          { "Length of Node Name", "gtpv2.length_of_node_name",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_length_of_node_realm,
          { "Length of Node Realm", "gtpv2.length_of_node_realm",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_node_name,
          { "Node Name", "gtpv2.node_name",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_node_realm,
      { "Node Realm", "gtpv2.node_realm",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_ms_ts,
      { "Millisecond Time Stamp", "gtpv2.ms_ts",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_origination_ts,
      { "Origination Time Stamp", "gtpv2.origination_ts",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_inf_nsur,
      { "NSUR (Notify SCEF when UE becomes Reachable)", "gtpv2.mon_event_inf.nsur",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_inf_nsui,
      { "NSUI (Notify SCEF when UE becomes Idle)", "gtpv2.mon_event_inf.nsui",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x20,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_inf_nscf,
      { "NSCF (Notify SCEF about Communication Failure events)", "gtpv2.mon_event_inf.nscf",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x40,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_inf_srie,
      { "SRIE (SCEF Reference Id Extension)", "gtpv2.mon_event_ext_inf.srie",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_inf_scef_reference_id,
          { "SCEF Reference ID", "gtpv2.mon_event_inf.scef_reference_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_inf_scef_reference_id_ext,
          { "SCEF Reference ID Ext", "gtpv2.mon_event_inf.scef_reference_id_ext",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_inf_scef_id_length,
          { "SCEF ID length", "gtpv2.mon_event_inf.scef_id_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_inf_scef_id,
          { "SCEF ID", "gtpv2.mon_event_inf.scef_id",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_inf_remaining_number_of_reports,
          { "Remaining Number of Reports", "gtpv2.mon_event_inf.remaining_number_of_reports",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_ext_inf_lrtp,
      { "LRTP (Remaining Minimum Periodic Location Reporting Time Present)", "gtpv2.mon_event_ext_inf.lrtp",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_ext_inf_srie,
      { "SRIE (SCEF Reference Id Extension)", "gtpv2.mon_event_ext_inf.srie",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_ext_inf_scef_reference_id,
          { "SCEF Reference ID", "gtpv2.mon_event_ext_inf.scef_reference_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_ext_inf_scef_id_length,
          { "SCEF ID length", "gtpv2.mon_event_ext_inf.scef_id_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_ext_inf_scef_id,
          { "SCEF ID", "gtpv2.mon_event_ext_inf.scef_id",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_ext_inf_remain_min_period_loc_report_type,
          { "Remaining Minimum Periodic Location Reporting Time", "gtpv2.mon_event_ext_inf.remain_min_period_loc_report_type",
          FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_seconds), 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mon_event_ext_inf_scef_reference_id_ext,
          { "SCEF Reference ID Ext", "gtpv2.mon_event_ext_inf.scef_reference_id_ext",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_rohc_profile_flags,
      { "ROHC Profiles flags", "gtpv2.rohc_profile_flags",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_rohc_profiles_bit0,
      { "Profile Identifier: 0x0002, UDP/IP", "gtpv2.rohc_profiles.b0",
          FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_rohc_profiles_bit1,
      { "Profile Identifier: 0x0003, ESP/IP", "gtpv2.rohc_profiles.b1",
          FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_rohc_profiles_bit2,
      { "Profile Identifier: 0x0004, IP", "gtpv2.rohc_profiles.b2",
          FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_rohc_profiles_bit3,
      { "Profile Identifier: 0x0006, TCP/IP", "gtpv2.rohc_profiles.b3",
          FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_rohc_profiles_bit4,
      { "Profile Identifier: 0x0102, UDP/IP", "gtpv2.rohc_profiles.b4",
          FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_rohc_profiles_bit5,
      { "Profile Identifier: 0x0103, ESP/IP", "gtpv2.rohc_profiles.b5",
          FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x20,
          NULL, HFILL }
      },
      { &hf_gtpv2_rohc_profiles_bit6,
      { "Profile Identifier: 0x0104, IP", "gtpv2.rohc_profiles.b6",
          FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x40,
          NULL, HFILL }
      },
      { &hf_gtpv2_rohc_profiles_bit7,
      { "Spare", "gtpv2.rohc_profiles.b7",
          FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL }
      },
      { &hf_gtpv2_max_cid,
      { "MAX_CID", "gtpv2.max_cid",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_uplink_rate_limit,
      { "Uplink Rate Limit", "gtpv2.uplink_rate_limit",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_downlink_rate_limit,
      { "Downlink Rate Limit", "gtpv2.downlink_rate_limit",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_timestamp_value,
      { "Timestamp value", "gtpv2.timestamp_value",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_counter_value,
      { "Counter value", "gtpv2.counter_value",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mapped_ue_usage_type,
      { "Mapped UE usage type", "gtpv2.mapped_ue_usage_type",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_uli_flags,
      { "ULI Flags", "gtpv2.uli_flags",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_dcnr,
      { "DCNR (Dual connectivity with NR)", "gtpv2.dcnr",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report,
          { "Secondary RAT Usage Data Report", "gtpv2.secondary_rat_usage_data_report",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_spare_bits,
          { "Spare", "gtpv2.secondary_rat_usage_data_report.spare_bits",
          FT_UINT8, BASE_HEX, NULL, 0xF8,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_bit3,
          { "SRUDN  (Secondary RAT Usage Report from NG-RAN)", "gtpv2.secondary_rat_usage_data_report.srudn",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_bit2,
          { "IRSGW  (Intended Receiver SGW)", "gtpv2.secondary_rat_usage_data_report.irsgw",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_bit1,
          { "IRPGW (Intended Receiver PGW)", "gtpv2.secondary_rat_usage_data_report.irpgw",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_rat_type,
          {"RAT Type", "gtpv2.secondary_rat_usage_data_report.rat_type",
          FT_UINT8, BASE_DEC, VALS(gtpv2_secondary_rat_type_vals), 0x0,
          NULL, HFILL}
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_start_timestamp,
      { "Start timestamp", "gtpv2.secondary_rat_usage_data_report.start_timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_end_timestamp,
      { "End timestamp", "gtpv2.secondary_rat_usage_data_report.end_timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_usage_data_dl,
      { "Usage Data DL", "gtpv2.secondary_rat_usage_data_report.usage_data_dl",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_usage_data_ul,
      { "Usage Data UL", "gtpv2.secondary_rat_usage_data_report.usage_data_ul",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_srudn_length,
          { "SRUDN length", "gtpv2.mon_event_inf.srudn_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_secondary_rat_usage_data_report_srudn_value,
          { "SecondaryRATDataUsageReportTransfer", "gtpv2.mon_event_inf.srudn_value",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_csg_info_rep_action_b0,
      { "UCICSG", "gtpv2.csg_info_rep_action.ucicsg",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_csg_info_rep_action_b1,
      { "UCISHC", "gtpv2.csg_info_rep_action.ucishc",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_csg_info_rep_action_b2,
      { "UCIUHC", "gtpv2.csg_info_rep_action.uciuhc",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_gnodeb_id_len,
          {"gNodeB ID Length", "gtpv2.gnodeb_id_len",
          FT_UINT8, BASE_DEC, NULL, 0x3f,
          NULL, HFILL}
      },
      { &hf_gtpv2_gnodeb_id,
      { "gNodeB ID", "gtpv2.gnodeb_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_macro_ng_enodeb_id,
      { "Macro ng-eNodeB ID", "gtpv2.ng_enodeb_id",
          FT_UINT24, BASE_DEC, NULL, 0x0fffff,
          NULL, HFILL }
      },
      { &hf_gtpv2_5gs_tac,
      { "5GS Tracking Area Code (TAC)", "gtpv2.5gs_tac",
          FT_UINT24, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_en_gnb_id_len,
          {"en-gNB ID Length", "gtpv2.en_gnb_id_len",
          FT_UINT8, BASE_DEC, NULL, 0x3f,
          NULL, HFILL}
      },
      { &hf_gtpv2_5tac,
      { "5TAC", "gtpv2.5tac",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80,
          NULL, HFILL }
      },
      { &hf_gtpv2_etac,
      { "ETAC", "gtpv2.etac",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x40,
          NULL, HFILL }
      },
      { &hf_gtpv2_en_gnb_id,
      { "gNodeB ID", "gtpv2.en_gnb_id",
          FT_UINT32, BASE_DEC, NULL,0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_trig_event_len,
      { "Length of Triggering Events", "gtpv2.trig_event_len",
          FT_UINT8, BASE_DEC, NULL,0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_ne_list_len,
      { "Length of List of NE Types", "gtpv2.ne_list_len",
          FT_UINT8, BASE_DEC, NULL,0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_ses_trs_depth,
      { "Session Trace Depth", "gtpv2.ses_trs_dept",
          FT_UINT8, BASE_DEC, NULL,0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_list_of_if_len,
      { "Length of List of Interfaces", "gtpv2.list_of_if_len",
          FT_UINT8, BASE_DEC, NULL,0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_trs_coll_ip_addr_len,
      { "Length of IP Address of Trace Collection Entity", "gtpv2.trs_coll_ip_addr_len",
          FT_UINT8, BASE_DEC, NULL,0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_trs_coll_ipv4_addr,
        {"IP Address of Trace Collection Entity", "gtpv2.trs_coll_ipv4_addr",
         FT_IPv4, BASE_NONE, NULL, 0x0,
         NULL, HFILL}
      },
      { &hf_gtpv2_trs_coll_ipv6_addr,
        {"IP Address of Trace Collection Entity", "gtpv2.trs_coll_ipv6_addr",
         FT_IPv6, BASE_NONE, NULL, 0x0,
         NULL, HFILL}
      },
      { &hf_gtpv2_ext_tra_info_loi_mscs_cap,
      { "CAP", "gtpv2.ext_tra_info_loi.mscs.cap",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mscs_map_f,
      { "MAP-F", "gtpv2.ext_tra_info_loi.mscs.map_f",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mscs_map_e,
      { "MAP-E", "gtpv2.ext_tra_info_loi.mscs.map_e",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mscs_map_b,
      { "MAP-B", "gtpv2.ext_tra_info_loi.mscs.map_b",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mscs_map_g,
      { "MAP-G", "gtpv2.ext_tra_info_loi.mscs.map_g",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mscs_mc,
      { "Mc", "gtpv2.ext_tra_info_loi.mscs.mc",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mscs_iu,
      { "Iu", "gtpv2.ext_tra_info_loi.mscs.iu",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mscs_a,
      { "A","gtpv2.ext_tra_info_loi.mscs.a",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mscs_map_c,
      { "MAP-C", "gtpv2.ext_tra_info_loi.mscs.map_c",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mscs_map_d,
      { "MAP-D", "gtpv2.ext_tra_info_loi.mscs.map_d",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mgw_iuup,
      { "Iu-UP", "gtpv2.ext_tra_info_loi.mgw.iuup",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mgw_nbup,
      { "Nb-UP", "gtpv2.ext_tra_info_loi.mgw.nbup",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mgw_mc,
      { "Mc", "gtpv2.ext_tra_info_loi.mgw.mc",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_ge,
      { "Ge", "gtpv2.ext_tra_info_loi.sgsn.ge",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_gs,
      { "Gs", "gtpv2.ext_tra_info_loi.sgsn.gs",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_map_gf,
      { "MAP-Gf", "gtpv2.ext_tra_info_loi.sgsn.map_gf",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_map_gd,
      { "MAP-Gd", "gtpv2.ext_tra_info_loi.sgsn.map_gd",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_map_gr,
      { "MAP-Gr", "gtpv2.ext_tra_info_loi.sgsn.map_gr",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_gn,
      { "Gn", "gtpv2.ext_tra_info_loi.sgsn.gn",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_iu,
      { "Iu", "gtpv2.ext_tra_info_loi.sgsn.iu",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_gb,
      { "Gb", "gtpv2.ext_tra_info_loi.sgsn.gb",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_s13,
      { "S13", "gtpv2.ext_tra_info_loi.sgsn.s13",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_s3,
      { "S3", "gtpv2.ext_tra_info_loi.sgsn.s3",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_s4,
      { "S4", "gtpv2.ext_tra_info_loi.sgsn.s4",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgsn_s6d,
      { "S6d", "gtpv2.ext_tra_info_loi.sgsn.s6d",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_ggsn_gmb,
      { "Gmb", "gtpv2.ext_tra_info_loi.ggsn.gmb",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_ggsn_gi,
      { "Gi", "gtpv2.ext_tra_info_loi.ggsn.gi",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_ggsn_gn,
      { "Gn", "gtpv2.ext_tra_info_loi.ggsn.gn",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_rnc_uu,
      { "Uu", "gtpv2.ext_tra_info_loi.rrc.uu",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_rnc_iub,
      { "Iub", "gtpv2.ext_tra_info_loi.rrc.iub",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_rnc_iur,
      { "Iur", "gtpv2.ext_tra_info_loi.rrc.iur",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_rnc_iu,
      { "Iu", "gtpv2.ext_tra_info_loi.rrc.iu",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_bm_sc_gmb,
      { "Gmb", "gtpv2.ext_tra_info_loi.bm_sc.gmb",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mme_s13,
      { "S13", "gtpv2.ext_tra_info_loi.mme.s13",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mme_s11,
      { "S11", "gtpv2.ext_tra_info_loi.mme.s11",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mme_s10,
      { "S10", "gtpv2.ext_tra_info_loi.mme.s10",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mme_s6a,
      { "S6a", "gtpv2.ext_tra_info_loi.mme.s6a",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mme_s3,
      { "S3", "gtpv2.ext_tra_info_loi.mme.s3",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_mme_s1_mme,
      { "S1-mme", "gtpv2.ext_tra_info_loi.mme.s1_mme",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgw_gxc,
      { "Gxc", "gtpv2.ext_tra_info_loi.sgw.gxc",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgw_s11,
      { "S11", "gtpv2.ext_tra_info_loi.sgw.s11",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgw_s8b,
      { "S8b", "gtpv2.ext_tra_info_loi.sgw.s8b",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgw_s5,
      { "S5", "gtpv2.ext_tra_info_loi.sgw.s5",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_sgw_s4,
      { "S4", "gtpv2.ext_tra_info_loi.sgw.s4",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pdn_gw_sgi,
      { "Sgi", "gtpv2.ext_tra_info_loi.pdn_gw.sgi",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pdn_gw_s8b,
      { "S8b", "gtpv2.ext_tra_info_loi.pdn_gw.s8b",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pdn_gw_gx,
      { "Gx", "gtpv2.ext_tra_info_loi.pdn_gw.gx",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pdn_gw_s6b,
      { "S6b", "gtpv2.ext_tra_info_loi.pdn_gw.s6b",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pdn_gw_s5,
      { "S5", "gtpv2.ext_tra_info_loi.pdn_gw.s5",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pdn_gw_s2c,
      { "S2c", "gtpv2.ext_tra_info_loi.pdn_gw.s2c",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pdn_gw_s2b,
      { "S2b", "gtpv2.ext_tra_info_loi.pdn_gw.s2b",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pdn_gw_s2a,
      { "S2a", "gtpv2.ext_tra_info_loi.pdn_gw.s2a",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_enb_uu,
      { "Uu", "gtpv2.ext_tra_info_loi.enb.uu",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_enb_x2,
      { "X2", "gtpv2.ext_tra_info_loi.enb.x2",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_enb_s1_mme,
      { "S1-MME", "gtpv2.ext_tra_info_loi.enb.s1_mme",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_hss_sh,
      { "Sh", "gtpv2.ext_tra_info_loi.hss.Sh",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_hss_s6a,
      { "S6a", "gtpv2.ext_tra_info_loi.hss.S6a",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_hss_s6d,
      { "S6d", "gtpv2.ext_tra_info_loi.hss.S6d",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_hss_cx,
      { "Cx", "gtpv2.ext_tra_info_loi.hss.cx",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_hss_map_gr,
      { "MAP-Gr", "gtpv2.ext_tra_info_loi.hss.map_gr",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_hss_map_gc,
      { "MAP-Gc", "gtpv2.ext_tra_info_loi.hss.map_gc",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_hss_map_d,
      { "MAP-D", "gtpv2.ext_tra_info_loi.hss.map_d",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_hss_map_c,
      { "MAP-C", "gtpv2.ext_tra_info_loi.hss.map_c",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_eir_map_gf,
      { "MAP-Gf", "gtpv2.ext_tra_info_loi.eir.map_gf",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_eir_s13p,
      { "S13'", "gtpv2.ext_tra_info_loi.eir.s13p",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_eir_s13,
      { "S13", "gtpv2.ext_tra_info_loi.eir.s13",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_eir_map_f,
      { "MAP-F", "gtpv2.ext_tra_info_loi.eir.map_f",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_amf_n20,
      { "N20", "gtpv2.ext_tra_info_loi.amf.n20",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_amf_n15,
      { "N15", "gtpv2.ext_tra_info_loi.amf.n15",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_amf_n14,
      { "N14", "gtpv2.ext_tra_info_loi.amf.n14",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_amf_n12,
      { "N12", "gtpv2.ext_tra_info_loi.amf.n12",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_amf_n11,
      { "N11", "gtpv2.ext_tra_info_loi.amf.n11",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_amf_n8,
      { "N8", "gtpv2.ext_tra_info_loi.amf.n8",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_amf_n2,
      { "N2", "gtpv2.ext_tra_info_loi.amf.n2",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_amf_n1,
      { "N1", "gtpv2.ext_tra_info_loi.amf.n1",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_amf_n22,
      { "N22", "gtpv2.ext_tra_info_loi.amf.n22",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_amf_n26,
      { "N26", "gtpv2.ext_tra_info_loi.amf.n26",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pcf_n15,
      { "N15", "gtpv2.ext_tra_info_loi.pcf.n15",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pcf_n7,
      { "N7", "gtpv2.ext_tra_info_loi.pcf.n7",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_pcf_n5,
      { "N5", "gtpv2.ext_tra_info_loi.pcf.n5",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_smf_s5_c,
      { "S5-C", "gtpv2.ext_tra_info_loi.smf.s5_c",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_smf_n11,
      { "N11", "gtpv2.ext_tra_info_loi.smf.n11",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_smf_n10,
      { "N10", "gtpv2.ext_tra_info_loi.smf.n10",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_smf_n7,
      { "N7", "gtpv2.ext_tra_info_loi.smf.n7",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_smf_n4,
      { "N4", "gtpv2.ext_tra_info_loi.smf.n4",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_upf_n4,
      { "N4", "gtpv2.ext_tra_info_loi.upf.n4",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_ng_ran_node_e1_c,
      { "E1-C", "gtpv2.ext_tra_info_loi.ng_ran_node.e1_c",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_ng_ran_node_f1_c,
      { "F1-C", "gtpv2.ext_tra_info_loi.ng_ran_node.f1_c",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_ng_ran_node_Uu,
      { "Uu", "gtpv2.ext_tra_info_loi.ng_ran_node.uu",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_ng_ran_node_xn_c,
      { "Xn-C", "gtpv2.ext_tra_info_loi.ng_ran_node.xn_c",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_ext_tra_info_loi_ng_ran_node_ng_c,
      { "NG-C", "gtpv2.ext_tra_info_loi.ng_ran_node.ng_c",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_nr_add_exception_rpts,
      { "Number of additional exception reports", "gtpv2.r_add_exception_rpts",
          FT_UINT32, BASE_DEC, NULL,0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_nr_ul_pkts_all,
      { "Number of Uplink packets allowed", "gtpv2.nr_ul_pkts_all",
          FT_UINT32, BASE_DEC, NULL,0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_nr_dl_pkts_all,
      { "Number of Downlink packets allowed", "gtpv2.nr_dl_pkts_all",
          FT_UINT32, BASE_DEC, NULL,0x0,
          NULL, HFILL }
      },
      { &hf_apn_rte_cntrl_status_val_time,
      { "APN Rate Control Status validity Time", "gtpv2.pn_rte_cntrl_status_val_time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_max_pkt_loss_rte_ul_flg,
      { "UL", "gtpv2.max_pkt_loss_rte_ul_flg",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
          NULL, HFILL }
      },
      { &hf_gtpv2_max_pkt_loss_rte_dl_flg,
      { "DL", "gtpv2.max_pkt_loss_rte_dl_flg",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
          NULL, HFILL }
      },
      { &hf_gtpv2_max_pkt_loss_rte_ul,
      { "Maximum Packet Loss Rate UL", "gtpv2.max_pkt_loss_rte_ul",
          FT_UINT16, BASE_CUSTOM, CF_FUNC(value_in_tenth_of_percent_fmt), 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_max_pkt_loss_rte_dl,
      { "Maximum Packet Loss Rate DL", "gtpv2.max_pkt_loss_rte_dl",
          FT_UINT16, BASE_CUSTOM, CF_FUNC(value_in_tenth_of_percent_fmt), 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mm_context_iov_updates_counter,
      { "IOV_updates counter", "gtpv2.mm_context.iov_updates_counter",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_mm_context_ear_len,
      { "Length of Extended Access Restriction Data", "gtpv2.mm_context.ear_len",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_node_number_len,
      { "Length", "gtpv2.node_number.len",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_additional_rrm_policy_index,
      { "Additional RRM Policy Index", "gtpv2.additional_rrm_policy_index",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_group_id,
      { "Group ID", "gtpv2.group_id",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
      },
      { &hf_gtpv2_ie_up_security_policy_up_ip_policy,
          { "UP IP Policy", "gtpv2.ie_up_security_policy.up_ip_policy",
          FT_UINT8, BASE_DEC, VALS(gtpv2_up_ip_policy_vals), 0x3,
          NULL, HFILL }
      },
      { &hf_gtpv2_ie_pscell_id_spare,
          { "Spare", "gtpv2.pscell_id.spare",
          FT_UINT40, BASE_DEC, NULL, 0xF000000000,
          NULL, HFILL }
      },
      { &hf_gtpv2_ie_pscell_id_nr_cgi,
          { "NR CGI", "gtpv2.pscell_id.nr_cgi",
          FT_UINT40, BASE_HEX, NULL, 0x0FFFFFFFFF,
          NULL, HFILL }
      },
      { &hf_gtpv2_ie_up_security_policy_spare,
          { "Spare", "gtpv2.up_security_policy.spare",
          FT_UINT8, BASE_DEC, NULL, 0xFC,
          NULL, HFILL }
      },
      { &hf_gtpv2_nf_instance_id_nf_instance_id,
      { "NF Instance ID", "gtpv2.nf_instance_id_nf_instance_id",
          FT_GUID, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
      },
      { &hf_gtpv2_nf_timer_in_seconds_timer_value,
      { "Timer in Seconds", "gtpv2.timer_in_seconds_timer_value",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
      },
    };

    /* Setup protocol subtree array */
#define GTPV2_NUM_INDIVIDUAL_ELEMS    85
    static int *ett_gtpv2_array[GTPV2_NUM_INDIVIDUAL_ELEMS + NUM_GTPV2_IES];

    ett_gtpv2_array[0] = &ett_gtpv2;
    ett_gtpv2_array[1] = &ett_gtpv2_flags;
    ett_gtpv2_array[2] = &ett_gtpv2_uli_flags;
    ett_gtpv2_array[3] = &ett_gtpv2_uli_field;
    ett_gtpv2_array[4] = &ett_gtpv2_bearer_ctx;
    ett_gtpv2_array[5] = &ett_gtpv2_PDN_conn;
    ett_gtpv2_array[6] = &ett_gtpv2_overload_control_information;
    ett_gtpv2_array[7] = &ett_gtpv2_mm_context_flag;
    ett_gtpv2_array[8] = &ett_gtpv2_pdn_numbers_nsapi;
    ett_gtpv2_array[9] = &ett_gtpv2_tra_info_trigg;
    ett_gtpv2_array[10] = &ett_gtpv2_tra_info_trigg_msc_server;
    ett_gtpv2_array[11] = &ett_gtpv2_tra_info_trigg_mgw;
    ett_gtpv2_array[12] = &ett_gtpv2_tra_info_trigg_sgsn;
    ett_gtpv2_array[13] = &ett_gtpv2_tra_info_trigg_ggsn;
    ett_gtpv2_array[14] = &ett_gtpv2_tra_info_trigg_bm_sc;
    ett_gtpv2_array[15] = &ett_gtpv2_tra_info_trigg_sgw_mme;
    ett_gtpv2_array[16] = &ett_gtpv2_tra_info_trigg_sgw;
    ett_gtpv2_array[17] = &ett_gtpv2_tra_info_trigg_pgw;
    ett_gtpv2_array[18] = &ett_gtpv2_tra_info_interfaces;
    ett_gtpv2_array[19] = &ett_gtpv2_tra_info_interfaces_imsc_server;
    ett_gtpv2_array[20] = &ett_gtpv2_tra_info_interfaces_lmgw;
    ett_gtpv2_array[21] = &ett_gtpv2_tra_info_interfaces_lsgsn;
    ett_gtpv2_array[22] = &ett_gtpv2_tra_info_interfaces_lggsn;
    ett_gtpv2_array[23] = &ett_gtpv2_tra_info_interfaces_lrnc;
    ett_gtpv2_array[24] = &ett_gtpv2_tra_info_interfaces_lbm_sc;
    ett_gtpv2_array[25] = &ett_gtpv2_tra_info_interfaces_lmme;
    ett_gtpv2_array[26] = &ett_gtpv2_tra_info_interfaces_lsgw;
    ett_gtpv2_array[27] = &ett_gtpv2_tra_info_interfaces_lpdn_gw;
    ett_gtpv2_array[28] = &ett_gtpv2_tra_info_interfaces_lpdn_lenb;
    ett_gtpv2_array[29] = &ett_gtpv2_tra_info_ne_types;
    ett_gtpv2_array[30] = &ett_gtpv2_rai;
    ett_gtpv2_array[31] = &ett_gtpv2_stn_sr;
    ett_gtpv2_array[32] = &ett_gtpv2_ms_mark;
    ett_gtpv2_array[33] = &ett_gtpv2_supp_codec_list;
    ett_gtpv2_array[34] = &ett_gtpv2_bss_con;
    ett_gtpv2_array[35] = &ett_gtpv2_utran_con;
    ett_gtpv2_array[36] = &ett_gtpv2_eutran_con;
    ett_gtpv2_array[37] = &ett_gtpv2_son_con;
    ett_gtpv2_array[38] = &ett_gtpv2_endc_son_con;
    ett_gtpv2_array[39] = &ett_gtpv2_intersys_son_con;
    ett_gtpv2_array[40] = &ett_gtpv2_mm_context_auth_qua;
    ett_gtpv2_array[41] = &ett_gtpv2_mm_context_auth_qui;
    ett_gtpv2_array[42] = &ett_gtpv2_mm_context_auth_tri;
    ett_gtpv2_array[43] = &ett_gtpv2_mm_context_net_cap;
    ett_gtpv2_array[44] = &ett_gtpv2_ms_network_capability;
    ett_gtpv2_array[45] = &ett_gtpv2_mm_context_sc;
    ett_gtpv2_array[46] = &ett_gtpv2_vd_pref;
    ett_gtpv2_array[47] = &ett_gtpv2_access_rest_data;
    ett_gtpv2_array[48] = &ett_gtpv2_qua;
    ett_gtpv2_array[49] = &ett_gtpv2_qui;
    ett_gtpv2_array[50] = &ett_gtpv2_preaa_tais;
    ett_gtpv2_array[51] = &ett_gtpv2_preaa_menbs;
    ett_gtpv2_array[52] = &ett_gtpv2_preaa_henbs;
    ett_gtpv2_array[53] = &ett_gtpv2_preaa_ecgis;
    ett_gtpv2_array[54] = &ett_gtpv2_preaa_rais;
    ett_gtpv2_array[55] = &ett_gtpv2_preaa_sais;
    ett_gtpv2_array[56] = &ett_gtpv2_preaa_cgis;
    ett_gtpv2_array[57] = &ett_gtpv2_load_control_inf;
    ett_gtpv2_array[58] = &ett_gtpv2_eci;
    ett_gtpv2_array[59] = &ett_gtpv2_twan_flags;
    ett_gtpv2_array[60] = &ett_gtpv2_ciot_support_ind;
    ett_gtpv2_array[61] = &ett_gtpv2_rohc_profile_flags;
    ett_gtpv2_array[62] = &ett_gtpv2_secondary_rat_usage_data_report;
    ett_gtpv2_array[63] = &ett_gtpv2_pres_rep_area_info;
    ett_gtpv2_array[64] = &ett_gtpv2_preaa_ext_menbs;
    ett_gtpv2_array[65] = &ett_gtpv2_ue_nr_sec_cap_len;
    ett_gtpv2_array[66] = &ett_gtpv2_apn_rte_ctrl_sts_len;
    ett_gtpv2_array[67] = &ett_gtpv2_if_mgcs;
    ett_gtpv2_array[68] = &ett_gtpv2_if_mgw;
    ett_gtpv2_array[69] = &ett_gtpv2_if_sgsn;
    ett_gtpv2_array[70] = &ett_gtpv2_if_ggsn;
    ett_gtpv2_array[71] = &ett_gtpv2_if_rnc;
    ett_gtpv2_array[72] = &ett_gtpv2_if_bm_sc;
    ett_gtpv2_array[73] = &ett_gtpv2_if_mme;
    ett_gtpv2_array[74] = &ett_gtpv2_if_sgw;
    ett_gtpv2_array[75] = &ett_gtpv2_if_pdn_gw;
    ett_gtpv2_array[76] = &ett_gtpv2_if_enb;
    ett_gtpv2_array[77] = &ett_gtpv2_if_hss;
    ett_gtpv2_array[78] = &ett_gtpv2_if_eir;
    ett_gtpv2_array[79] = &ett_gtpv2_if_amf;
    ett_gtpv2_array[80] = &ett_gtpv2_if_pcf;
    ett_gtpv2_array[81] = &ett_gtpv2_if_smf;
    ett_gtpv2_array[82] = &ett_gtpv2_if_upf;
    ett_gtpv2_array[83] = &ett_gtpv2_if_ng_ran_node;
    ett_gtpv2_array[84] = &ett_gtpv2_PGW_change_info;
    last_offset = GTPV2_NUM_INDIVIDUAL_ELEMS;

    for (i=0; i < NUM_GTPV2_IES; i++, last_offset++)
    {
        ett_gtpv2_array[last_offset] = &ett_gtpv2_ies[i];
    }

    static ei_register_info ei[] = {
        { &ei_gtpv2_ie_data_not_dissected, { "gtpv2.ie_data_not_dissected", PI_UNDECODED, PI_NOTE, "IE data not dissected yet", EXPFILL }},
        { &ei_gtpv2_ie_len_invalid, { "gtpv2.ie_len_invalid", PI_PROTOCOL, PI_ERROR, "Wrong length", EXPFILL }},
        { &ei_gtpv2_source_type_unknown, { "gtpv2.source_type.unknown",  PI_PROTOCOL, PI_ERROR, "Unknown source type", EXPFILL }},
        { &ei_gtpv2_fq_csid_type_bad, { "gtpv2.fq_csid_type.unknown", PI_PROTOCOL, PI_ERROR, "Wrong Node-ID Type", EXPFILL }},
        { &ei_gtpv2_mbms_session_duration_days, { "gtpv2.mbms_session_duration_days.invalid", PI_PROTOCOL, PI_WARN, "Days out of allowed range", EXPFILL }},
        { &ei_gtpv2_mbms_session_duration_secs, { "gtpv2.mbms_session_duration_secs.unknown", PI_PROTOCOL, PI_WARN, "Seconds out of allowed range", EXPFILL }},
        { &ei_gtpv2_ie, { "gtpv2.ie_type.reserved", PI_PROTOCOL, PI_WARN, "IE type Zero is Reserved and should not be used", EXPFILL }},
        { &ei_gtpv2_int_size_not_handled, { "gtpv2.ie_type.int_size_not_handled", PI_PROTOCOL, PI_WARN, "Integer size not handled yet", EXPFILL } },
        { &ei_gtpv2_apn_too_long, { "gtpv2.apn_too_long", PI_PROTOCOL, PI_WARN, "APN encoding has more than 100 octets", EXPFILL } },
    };

    expert_module_t* expert_gtpv2;
    module_t *gtpv2_module;

    static const enum_val_t decode_srvcc_ps_to_cs_trans_cont_vals[] = {
        {"no", "Don't decode", PREF_DECODE_SRVCC_P2C_TRANS_CONT_NO},
        {"utran", "Assume UTRAN target", PREF_DECODE_SRVCC_P2C_TRANS_CONT_TARGET_UTRAN},
        {NULL, NULL, -1}
    };

    proto_gtpv2 = proto_register_protocol("GPRS Tunneling Protocol V2", "GTPv2", "gtpv2");

    gtpv2_module = prefs_register_protocol(proto_gtpv2, NULL);
    prefs_register_enum_preference(gtpv2_module, "decode_srvcc_p2c_trans_cont_target",
        "Decode SRVCC PS-to-CS Transparent Containers",
        "Use this setting to decode the Transparent Containers in the SRVCC PS-to-CS messages.\n"
        "This is needed until there's a reliable way to determine the contents of the transparent containers.",
        &pref_decode_srvcc_p2c_trans_cont, decode_srvcc_ps_to_cs_trans_cont_vals, false);

    prefs_register_uint_preference(gtpv2_module, "pair_max_interval", "Max interval allowed in pair matching", "Request/reply pair matches only if their timestamps are closer than that value, in ms (default 0, i.e. don't use timestamps)", 10, &pref_pair_matching_max_interval_ms);

    proto_register_field_array(proto_gtpv2, hf_gtpv2, array_length(hf_gtpv2));
    proto_register_subtree_array(ett_gtpv2_array, array_length(ett_gtpv2_array));
    expert_gtpv2 = expert_register_protocol(proto_gtpv2);
    expert_register_field_array(expert_gtpv2, ei, array_length(ei));

    register_dissector("gtpv2", dissect_gtpv2, proto_gtpv2);
    /* Dissector table for private extensions */
    gtpv2_priv_ext_dissector_table = register_dissector_table("gtpv2.priv_ext", "GTPv2 Private Extension", proto_gtpv2, FT_UINT16, BASE_DEC);

    gtpv2_tap = register_tap("gtpv2");

    register_srt_table(proto_gtpv2, NULL, 1, gtpv2_stat_packet, gtpv2_stat_init, NULL);
}

void
proto_reg_handoff_gtpv2(void)
{
    //static bool               Initialized = false;

    nas_eps_handle = find_dissector_add_dependency("nas-eps", proto_gtpv2);

    radius_register_avp_dissector(VENDOR_THE3GPP, 22, dissect_radius_user_loc);

    /* AVP Code: 22 3GPP-User-Location-Info */
    dissector_add_uint("diameter.3gpp", 22, create_dissector_handle(dissect_diameter_3gpp_uli, proto_gtpv2));

    /* AVP Code: 2820 Presence-Reporting-Area-Elements-List */
    dissector_add_uint("diameter.3gpp", 2820, create_dissector_handle(dissect_diameter_3gpp_presence_reporting_area_elements_list, proto_gtpv2));

}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
