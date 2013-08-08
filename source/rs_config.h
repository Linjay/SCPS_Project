#ifndef rs_config_h
#define rs_config_h
#ifdef GATEWAY
/********************************************************
 * 
 *                             NOTICE
 *  
 * "This software was produced for the U.S. Government under
 * Contract No's. DAAB07-97-C-E601, F19628-94-C-0001,
 * NAS5-32607, and JPL contract 752939 and is subject 
 * to the Rights in Noncommercial Computer Software and 
 * Noncommercial Computer Software Documentation Clause 
 * at (DFARS) 252.227-7014 (JUN 95), and the Rights in 
 * Technical Data and Computer Software Clause at (DFARS) 
 * 252.227-7013 (OCT 88) with Alternate II (APR 93),  
 * FAR 52.227-14 Rights in Data General, and Article GP-51,
 * Rights in Data - General, respectively.
 *
 *        (c) 1999 The MITRE Corporation
 *
 * MITRE PROVIDES THIS SOFTWARE "AS IS" AND MAKES NO 
 * WARRANTY, EXPRESS OR IMPLIED, AS TO THE ACCURACY, 
 * CAPABILITY, EFFICIENCY, OR FUNCTIONING OF THE PRODUCT. 
 * IN NO EVENT WILL MITRE BE LIABLE FOR ANY GENERAL, 
 * CONSEQUENTIAL, INDIRECT, INCIDENTAL, EXEMPLARY, OR 
 * SPECIAL DAMAGES, EVEN IF MITRE HAS BEEN ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGES.
 *
 * You accept this software on the condition that you 
 * indemnify and hold harmless MITRE, its Board of 
 * Trustees, officers, agents and employees, from any and 
 * all liability or damages to third parties, including 
 * attorneys' fees, court costs, and other related costs 
 * and expenses, arising our of your use of the Product 
 * irrespective of the cause of said liability, except 
 * for liability arising from claims of US patent 
 * infringements.
 *
 * The export from the United States or the subsequent 
 * reexport of this software is subject to compliance 
 * with United States export control and munitions 
 * control restrictions.  You agree that in the event you 
 * seek to export this software you assume full 
 * responsibility for obtaining all necessary export 
 * licenses and approvals and for assuring compliance 
 * with applicable reexport restrictions.
 *
 ********************************************************/


/*****************************************************************
**  rsc_file.c 
**
**    Reads in resource file specified in rsc_file define below.
**      File currently contains gateway interface and IPFW info,
**      but may be modified as needed. Interface information is
**      stored in the structure GW_ifs. 
**       
**    Re-reads this file upon receipt of SIGHUP. A simple way to
**      do this in testing is to type "kill -1 PID#" at the
**      command line, where PID# is the process id. 
**     
**      The GW_ifs struct is overwritten with the new information
**      in the resource file when it's re-read. 
**
******************************************************************/
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sgtty.h>
#include <fcntl.h>
#include <unistd.h>

#include "scps.h"

#ifdef IPFW
#undef IPFW
#endif /* IPFW */

#define MAX_NUM_IF	3
#define MAX_ADDRS   4
#define MAX_MPF_ADDRS   4
#define MAX_NAME_LEN	80
#define DIVERT_START_RULE	10000	/* flush ipfw rules from here to +9 */
#define DEF_A_PORT	53000	/* Default divert port number for interface A */
#define DEF_B_PORT	53001	/* Default divert port number for i/f B */
#define DEF_C_PORT      53002	/* Default common divert port */


#define GATEWAY_LAN_SIDE	1
#define GATEWAY_WAN_SIDE	2

typedef char sect[3];
typedef struct
  {
    sect sects[4];
  }
sectaddr;

typedef char addrstr[17];
/* NOTE: since other ways of obtaining IF addrs, I've removed it
   from resource file */
typedef struct
  {
    char aif_name[MAX_NAME_LEN];
    uint32_t aif_addr[MAX_ADDRS];
    addrstr aif_addrstr[MAX_ADDRS];
    uint32_t aif_mask[MAX_ADDRS];
    addrstr aif_maskstr[MAX_ADDRS];
    char aif_tun_name[MAX_NAME_LEN];
    char aif_tap_name[MAX_NAME_LEN];
    int32_t aif_buf;
    int32_t aif_rbuf;
    int32_t aif_rate;
    int32_t aif_min_rate;
    int32_t aif_cc;
    int32_t aif_divport;
    int aif_mtu;
    int aif_smtu;
    int aif_ts;
    int aif_snack;
    int aif_nodelay;
    int aif_snack_delay;
    int aif_ack_behave;
    int aif_ack_delay;
    int aif_tcponly;
    addrstr aif_next_hop_ipstr;
    int aif_next_hop;
    int32_t aif_irto;
    int aif_vegas_alpha;
    int aif_vegas_beta;
    int aif_vegas_gamma;
    int aif_vegas_ss;
    int aif_flow_control_cap;
    int aif_tap_no_phy;
    int32_t aif_scps_security;
    int32_t aif_layering;
    int32_t aif_overhead;
    int32_t aif_mss_ff;
    addrstr aif_local_ipstr;
    addrstr aif_remote_ipstr;
    uint32_t aif_local_ipaddr;
    uint32_t aif_remote_ipaddr;
    int aif_nl;
    int aif_gateway_lan_or_wan;
    uint32_t aif_minrto;
    uint32_t aif_maxrto; 
    uint32_t aif_maxrto_ctr;
    uint32_t aif_maxpersist_ctr;
    uint32_t aif_rtopersist_max;
    uint32_t aif_rto_to_persist_ctr;
    uint32_t aif_embargo_fast_rxmit_ctr;
    int aif_2msltimeout;
    int aif_tp_compress;
    int aif_div_addr;
    int aif_div_port;
    int aif_mpf;
    int aif_encrypt_ipsec_downstream;
    uint32_t aif_encrypt_pre_overhead;
    uint32_t aif_encrypt_block_size;
    uint32_t aif_encrypt_post_overhead;
    uint32_t aif_mpf_src [MAX_MPF_ADDRS];
    uint32_t aif_mpf_dst [MAX_MPF_ADDRS]; 
    addrstr aif_mpf_src_ipstr [MAX_MPF_ADDRS];
    addrstr aif_mpf_dst_ipstr [MAX_MPF_ADDRS];
    int aif_mpf_src_cnt;
    int aif_mpf_dst_cnt;
    int aif_mpf_xmit_delay;
    uint32_t aif_ecbs1;
    char aif_ecbs1_value [MAX_ECBS_VALUE];
    uint32_t aif_ecbs1_len;
    uint32_t aif_ecbs2;
    char aif_ecbs2_value [MAX_ECBS_VALUE];
    uint32_t aif_ecbs2_len;

    char bif_name[MAX_NAME_LEN];
    uint32_t bif_addr[MAX_ADDRS];
    addrstr bif_addrstr[MAX_ADDRS];
    uint32_t bif_mask[MAX_ADDRS];
    addrstr bif_maskstr[MAX_ADDRS];
    char bif_tun_name[MAX_NAME_LEN];
    char bif_tap_name[MAX_NAME_LEN];
    int32_t bif_buf;
    int32_t bif_rbuf;
    int32_t bif_rate;
    int32_t bif_min_rate;
    int32_t bif_cc;
    int32_t bif_divport;
    int bif_mtu;
    int bif_smtu;
    int bif_ts;
    int bif_snack;
    int bif_nodelay;
    int bif_snack_delay;
    int bif_ack_behave;
    int bif_ack_delay;
    int bif_tcponly;
    addrstr bif_next_hop_ipstr;
    int bif_next_hop;
    int32_t bif_irto;
    int bif_vegas_alpha;
    int bif_vegas_beta;
    int bif_vegas_gamma;
    int bif_vegas_ss;
    int bif_flow_control_cap;
    int bif_tap_no_phy;
    int32_t bif_scps_security;
    int32_t bif_layering;
    int32_t bif_overhead;
    int32_t bif_mss_ff;
    addrstr bif_local_ipstr;
    addrstr bif_remote_ipstr;
    uint32_t bif_local_ipaddr;
    uint32_t bif_remote_ipaddr;
    int bif_nl; 
    int bif_gateway_lan_or_wan;
    uint32_t bif_minrto;
    uint32_t bif_maxrto;
    uint32_t bif_maxrto_ctr;
    uint32_t bif_maxpersist_ctr;
    uint32_t bif_rtopersist_max;
    uint32_t bif_rto_to_persist_ctr;
    uint32_t bif_embargo_fast_rxmit_ctr;
    int bif_2msltimeout;
    int bif_tp_compress;
    int bif_div_addr;
    int bif_div_port;
    int bif_mpf;
    int bif_encrypt_ipsec_downstream;
    uint32_t bif_encrypt_pre_overhead;
    uint32_t bif_encrypt_block_size;
    uint32_t bif_encrypt_post_overhead;
    uint32_t bif_mpf_src [MAX_MPF_ADDRS];
    uint32_t bif_mpf_dst [MAX_MPF_ADDRS];
    addrstr bif_mpf_src_ipstr [MAX_MPF_ADDRS];
    addrstr bif_mpf_dst_ipstr [MAX_MPF_ADDRS];
    int bif_mpf_src_cnt;
    int bif_mpf_dst_cnt;
    int bif_mpf_xmit_delay;
    uint32_t bif_ecbs1;
    char bif_ecbs1_value [MAX_ECBS_VALUE];
    uint32_t bif_ecbs1_len;
    uint32_t bif_ecbs2;
    char bif_ecbs2_value [MAX_ECBS_VALUE];
    uint32_t bif_ecbs2_len;

    char c_tun_name[MAX_NAME_LEN];
    int32_t c_divport;
    int  c_netstat_interval;
    int  c_scps_local_udp_port;
    int  c_scps_remote_udp_port;
    int  c_divert_start_rule;
    int  c_divert_insert_rule;
    char c_clust_filename [MAX_NAME_LEN];
    int32_t c_clust_thresh;
    char c_pkt_io_filename [MAX_NAME_LEN];
    int  c_other_proto_qlen;
    int  c_other_proto_xrate_drop;
    int  c_other_proto_non_ip;
    int  c_other_proto_ipv6;
    int  c_tap_remote_access;

    /* put other stuff as needed here..... */
  }
GW_ifs;

short gateway_Init ();
int rs_init ();
void ShowGW_ifs ();
int32_t ddtol ();
int gateway_ipfw ();
int hup_hndlr ();
void init_sighup_mask ();
void gateway_tun_cleanup ();
void gateway_tap_cleanup ();

#endif /* GATEWAY */
#endif /* rs_config_h */
