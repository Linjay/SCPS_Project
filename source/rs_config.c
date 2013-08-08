char rsc_file [32];

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

#include "rs_config.h"
#include "ll.h"
#include "route.h"
#include "other_proto_handler.h"

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif /* min */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: rs_config.c,v $ -- $Revision: 1.55 $\n";
#endif

#ifdef EXTERNAL_RULE_GENERATION
#define SYSTEM(A)
#else /* EXTERNAL_RULE_GENERATION */
#define SYSTEM(A) system(A)
#endif /* EXTERNAL_RULE_GENERATION */

extern int scps_udp_port;
extern int scps_udp_port1;
extern int nl_default;

#ifdef GATEWAY_DUAL_INTERFACE
extern int special_port_number;
#endif /* GATEWAY_DUAL_INTERFACE */

int divert_start_rule = DIVERT_START_RULE;
int divert_insert_rule = DIVERT_START_RULE + 8;

GW_ifs gw_ifs;
short readctr = 0;		/* for testing only */

int
rs_init ()
{
  int readOK = 0;

  init_sighup_mask ();
  readOK = gateway_Init ();
  ShowGW_ifs ();
#ifdef TUN_INTERFACE
#else /* TUN_INTERFACE */
#ifdef TAP_INTERFACE
#else /* TAP_INTERFACE */
  readOK = gateway_ipfw ();
#endif /* TAP_INTERFACE */
#endif /* TUN_INTERFACE */

  if (!readOK)
    exit (-1);
  else
    return (readOK);
}


int
hup_hndlr ()
{
  int read_OK;

  /* the GW can now update any stats it's been keeping.
     This file can either call an external function for the GW
     or it can try to access the GW's stats and log them itself */

  /* re-read the resource file; everything old gets wiped out */
  read_OK = gateway_Init ();

  /* for testing only */
  if (read_OK)
    {
      ShowGW_ifs ();
#ifdef TUN_INTERFACE
#else  /* TUN_INTERFACE */
#ifdef TAP_INTERFACE
#else  /* TAP_INTERFACE */
      read_OK = gateway_ipfw ();
#endif/* TAP_INTERFACE */
#endif/* TUN_INTERFACE */
    }

  fflush (stdout);
  return (read_OK);
}

void
int_hndlr ()
{
  /* remove the ipfw rules. */
#ifndef TUN_INTERFACE
#ifndef TAP_INTERFACE
  int i;
  char ipfw_cmd [100];
#endif /* TAP_INTERFACE */
#endif /* TUN_INTERFACE */

#ifdef __FreeBSD__
#ifdef TUN_INTERFACE
    gateway_tun_cleanup ();
#else /* TUN_INTERFACE */
#ifdef TAP_INTERFACE
    gateway_tap_cleanup (1);
#else /* TAP_INTERFACE */
  for (i = divert_start_rule; i <= divert_start_rule + 8; i++)
    { 
      sprintf (ipfw_cmd, "ipfw delete %d 2> /dev/null ", i);
#ifndef EXTERNAL_RULE_GENERATION
      while (!system (ipfw_cmd));       /* I ain't got no body */
#endif /* EXTERNAL_RULE_GENERATION */
    }
#endif /* TAP_INTERFACE */
#endif /* TUN_INTERFACE */
#endif /* __FreeBSD__ */

#ifdef LINUX
#ifdef TUN_INTERFACE
    gateway_tun_cleanup ();
#else /* TUN_INTERFACE */
#ifdef TAP_INTERFACE
    gateway_tap_cleanup (1);
#else /* TAP_INTERFACE */
	i = 0;
	sprintf(ipfw_cmd, "ipchains -F >& /dev/null");
	SYSTEM(ipfw_cmd);
#endif /* TAP_INTERFACE */
#endif /* TUN_INTERFACE */
#endif /* LINUX */

#ifdef __NetBSD__
#ifdef TUN_INTERFACE
    gateway_tun_cleanup ();
#else /* TUN_INTERFACE */
#ifdef TAP_INTERFACE
    gateway_tap_cleanup (1);
#endif /* TAP_INTERFACE */
#endif /* TUN_INTERFACE */
#endif /* __NetBSD__ */
  exit (-1);
}


void
init_sighup_mask ()
{
  signal (SIGHUP, (void *) hup_hndlr);
  signal (SIGINT, (void *) int_hndlr);
  signal (SIGTERM, (void *) int_hndlr);
  signal (SIGQUIT, (void *) int_hndlr);
}

short
gateway_Init ()
{
  FILE *fp;
  char parname[32];		/* parameter name - read as string */
  char c, pardata[32];		/* parameter data - read as string */
  int temp_sd = 0;
  int retval = 0;
  struct ifreq if_str;
  /* struct sockaddr_in saddr; */

  int i = 0, comment = 0, readOK = 1;
  short cnt_aif_addrs = 0, cnt_bif_addrs = 0;
  short cnt_aif_masks = 0, cnt_bif_masks = 0;

  gw_ifs.aif_buf = gw_ifs.aif_rate = gw_ifs.aif_cc = gw_ifs.aif_mtu = 0x0;
  gw_ifs.aif_min_rate = gw_ifs.bif_min_rate = 0;
  gw_ifs.aif_ack_delay = gw_ifs.bif_ack_delay = 0x0;
  gw_ifs.aif_ack_behave = gw_ifs.bif_ack_behave = -1;
  gw_ifs.aif_rbuf = gw_ifs.bif_rbuf = 0x0;
  gw_ifs.aif_smtu = gw_ifs.bif_smtu = 0x0;
  gw_ifs.aif_ts = gw_ifs.bif_ts = 0x1;
  gw_ifs.aif_snack = gw_ifs.bif_snack = 0x1;
  gw_ifs.aif_nodelay = gw_ifs.bif_nodelay = 0x0;
  gw_ifs.aif_snack_delay = gw_ifs.bif_snack_delay = 0x0;
  gw_ifs.aif_tcponly = gw_ifs.bif_tcponly = 0x0;
  gw_ifs.aif_next_hop = gw_ifs.bif_next_hop = 0x0;
  gw_ifs.aif_encrypt_ipsec_downstream = gw_ifs.bif_encrypt_ipsec_downstream = 0x0;
  gw_ifs.aif_tap_no_phy = gw_ifs.bif_tap_no_phy = 0x0;
  gw_ifs.aif_encrypt_pre_overhead = gw_ifs.bif_encrypt_pre_overhead = DEFAULT_ENCRYPT_PRE_OVERHEAD;
  gw_ifs.aif_encrypt_block_size = gw_ifs.bif_encrypt_block_size = DEFAULT_ENCRYPT_BLOCK_SIZE;
  gw_ifs.aif_encrypt_post_overhead = gw_ifs.bif_encrypt_post_overhead = DEFAULT_ENCRYPT_POST_OVERHEAD;
  gw_ifs.aif_divport = DEF_A_PORT;
  gw_ifs.bif_divport = DEF_B_PORT;
  gw_ifs.c_divport = DEF_C_PORT;
  gw_ifs.c_netstat_interval = 0;
  gw_ifs.c_scps_local_udp_port = SCPS_UDP_PORT;
  gw_ifs.c_scps_remote_udp_port = Other_SCPS_UDP_PORT;
  gw_ifs.c_divert_start_rule = 0;
  gw_ifs.c_divert_insert_rule = 0;
  gw_ifs.c_clust_thresh = 0;
  gw_ifs.c_other_proto_qlen = OTHER_PROTO_QLEN_DEFAULT;
  gw_ifs.c_other_proto_xrate_drop = 0;
  gw_ifs.c_other_proto_non_ip = 0;
  gw_ifs.c_other_proto_ipv6 = 0;
  gw_ifs.c_tap_remote_access = 0;
  gw_ifs.aif_irto = gw_ifs.bif_irto = 0x0;
  gw_ifs.aif_scps_security = gw_ifs.bif_scps_security = 0x0;
  gw_ifs.aif_layering = gw_ifs.bif_layering = 0;
  gw_ifs.aif_overhead = gw_ifs.bif_overhead = 0;
  gw_ifs.aif_local_ipaddr = gw_ifs.aif_remote_ipaddr = 0;
  gw_ifs.bif_local_ipaddr = gw_ifs.bif_remote_ipaddr = 0;
  gw_ifs.aif_mss_ff = gw_ifs.bif_mss_ff = -1;
  gw_ifs.aif_nl = gw_ifs.bif_nl = nl_default;
  gw_ifs.aif_minrto = gw_ifs.bif_minrto = tp_RTOMIN;
  gw_ifs.aif_maxrto = gw_ifs.bif_maxrto = tp_RTOMAX;
  gw_ifs.aif_maxrto_ctr = gw_ifs.bif_maxrto_ctr = tp_TIMEOUT;
  gw_ifs.aif_maxpersist_ctr = gw_ifs.bif_maxpersist_ctr = tp_MAXPERSIST_CTR;
  gw_ifs.aif_rtopersist_max = gw_ifs.bif_rtopersist_max = tp_RTOPERSIST_MAX;
  gw_ifs.aif_rto_to_persist_ctr = gw_ifs.bif_rto_to_persist_ctr = 0;
  gw_ifs.aif_embargo_fast_rxmit_ctr = gw_ifs.bif_embargo_fast_rxmit_ctr = 4;
  
  gw_ifs.aif_2msltimeout = gw_ifs.bif_2msltimeout = 0;
  gw_ifs.aif_tp_compress = gw_ifs.bif_tp_compress = 0;
  gw_ifs.aif_mpf = gw_ifs.bif_mpf = 0;
  gw_ifs.aif_mpf_xmit_delay = gw_ifs.bif_mpf_xmit_delay = 0;
  gw_ifs.aif_mpf_src_cnt = gw_ifs.bif_mpf_src_cnt = 0;
  gw_ifs.aif_mpf_dst_cnt = gw_ifs.bif_mpf_dst_cnt = 0;
  gw_ifs.aif_ecbs1 = gw_ifs.bif_ecbs1 = 0x0;
  gw_ifs.aif_ecbs2 = gw_ifs.bif_ecbs2 = 0x0;
  gw_ifs.aif_ecbs1_len = gw_ifs.bif_ecbs1_len = 0x0;
  gw_ifs.aif_ecbs2_len = gw_ifs.bif_ecbs2_len = 0x0;
  for (i = 0; i < MAX_ECBS_VALUE; i++) {
    gw_ifs.aif_ecbs1_value [i] = 0x0;
    gw_ifs.bif_ecbs1_value [i] = 0x0;
    gw_ifs.aif_ecbs2_value [i] = 0x0;
    gw_ifs.bif_ecbs2_value [i] = 0x0;
  }

  for (i = 0; i < MAX_ADDRS; i++)
    {
      gw_ifs.aif_addr[i] = gw_ifs.bif_addr[i] = 0x0;
      gw_ifs.aif_mask[i] = gw_ifs.bif_mask[i] = 0x0;
      gw_ifs.aif_local_ipstr[i] = gw_ifs.bif_local_ipstr[i] = 0x0;
      gw_ifs.aif_remote_ipstr[i] = gw_ifs.bif_remote_ipstr[i] = 0x0;
      gw_ifs.aif_next_hop_ipstr[i] = gw_ifs.bif_next_hop_ipstr[i] = 0x0;
    }
  gw_ifs.aif_name[0] = '\0';
  gw_ifs.bif_name[0] = '\0';
  gw_ifs.aif_tun_name[0] = '\0';
  gw_ifs.bif_tun_name[0] = '\0';
  gw_ifs.c_tun_name[0] = '\0';
  gw_ifs.aif_tap_name[0] = '\0';
  gw_ifs.bif_tap_name[0] = '\0';
  gw_ifs.c_clust_filename[0] = '\0';
  gw_ifs.c_pkt_io_filename[0] = '\0';

  fp = fopen (rsc_file, "r");
  if (fp != NULL)
    {
      temp_sd = socket (PF_INET, SOCK_DGRAM, 0);

      while ((c = getc (fp)) != EOF)
	{
	  /* if blank line, can't be comment anymore */
	  if (c == '\n')
	    comment = 0;
	  else if (c == '#')
	    {
	      comment = 1;
	    }
	  else if (isspace (c) || c == '\t')
	    ;			/* skip over the space */
	  /* if not at start/in the middle of a comment, must be input param */
	  else if (!comment)
	    {
	      ungetc (c, fp);
	      memset (pardata, '0', 32);
	      memset (parname, '0', 32);
	      if (fscanf (fp, "%s %s", parname, pardata) != EOF)
		{

		  /* store the proper format of the parameter data */
		  if (!strcmp (parname, "AIF_ADDR"))
		    {
		      gw_ifs.aif_addr[cnt_aif_addrs] = ddtol ((char *) pardata);
		      strcpy (gw_ifs.aif_addrstr[cnt_aif_addrs++], pardata);
		    }

		  else if (!strcmp (parname, "AIF_MASK"))
		    {
		      gw_ifs.aif_mask[cnt_aif_masks] = ddtol ((char *) pardata);
		      strcpy (gw_ifs.aif_maskstr[cnt_aif_masks++], pardata);
		    }

		  else if (!strcmp (parname, "AIF_NAME"))
		    {
		      strcpy (gw_ifs.aif_name, pardata);

		      /* now make sure it's valid */
		    }
		  else if (!strcmp (parname, "AIF_TUN_NAME"))
		    {
		      strcpy (gw_ifs.aif_tun_name, pardata);

		      /* now make sure it's valid */
		    }
		  else if (!strcmp (parname, "AIF_TAP_NAME"))
		    {
		      strcpy (gw_ifs.aif_tap_name, pardata);

		      /* now make sure it's valid */
		    }
		  else if (!strcmp (parname, "AIF_LOCAL_IP")) {
		      memcpy (&gw_ifs.aif_local_ipstr,pardata, strlen (pardata));
		      gw_ifs.aif_local_ipaddr = ddtol ((char *) pardata);
		  }

		  else if (!strcmp (parname, "AIF_REMOTE_IP")) {
		      gw_ifs.aif_remote_ipaddr = ddtol ((char *) pardata);
		      memcpy (&gw_ifs.aif_remote_ipstr,pardata, strlen (pardata));
		  }

		  else if (!strcmp (parname, "AIF_BUF"))
		    gw_ifs.aif_buf = atoi (pardata);

		  else if (!strcmp (parname, "AIF_RBUF"))
		    gw_ifs.aif_rbuf = atoi (pardata);

		  else if (!strcmp (parname, "AIF_RATE"))
		    gw_ifs.aif_rate = atoi (pardata);

		  else if (!strcmp (parname, "AIF_MIN_RATE"))
		    gw_ifs.aif_min_rate = atoi (pardata);

		  else if (!strcmp (parname, "AIF_CC"))
		    gw_ifs.aif_cc = atoi (pardata);

		  else if (!strcmp (parname, "AIF_VEGAS_ALPHA"))
		    gw_ifs.aif_vegas_alpha = atoi (pardata);

		  else if (!strcmp (parname, "AIF_VEGAS_BETA"))
		    gw_ifs.aif_vegas_beta = atoi (pardata);

		  else if (!strcmp (parname, "AIF_VEGAS_GAMMA"))
		    gw_ifs.aif_vegas_gamma = atoi (pardata);

		  else if (!strcmp (parname, "AIF_VEGAS_SS"))
		    gw_ifs.aif_vegas_ss = atoi (pardata);

		  else if (!strcmp (parname, "AIF_FLOW_CONTROL_CAP"))
		    gw_ifs.aif_flow_control_cap = atoi (pardata);

		  else if (!strcmp (parname, "AIF_TAP_NO_PHY"))
		    gw_ifs.aif_tap_no_phy = atoi (pardata);

		  else if (!strcmp (parname, "AIF_SCPS_SECURITY"))
		    gw_ifs.aif_scps_security = atoi (pardata);

		  else if (!strcmp (parname, "AIF_DIVPORT"))
		    gw_ifs.aif_divport = atoi (pardata);

		  else if (!strcmp (parname, "AIF_LAYERING"))
		    gw_ifs.aif_layering = atoi (pardata);

		  else if (!strcmp (parname, "AIF_OVERHEAD"))
		    gw_ifs.aif_overhead = atoi (pardata);

		  else if (!strcmp (parname, "AIF_MSS_FF"))
		    gw_ifs.aif_mss_ff = atoi (pardata);
                      
		  else if (!strcmp (parname, "AIF_SMTU"))
		    gw_ifs.aif_smtu = atoi (pardata);

		  else if (!strcmp (parname, "AIF_TS"))
		    gw_ifs.aif_ts = atoi (pardata);

		  else if (!strcmp (parname, "AIF_SNACK"))
		    gw_ifs.aif_snack = atoi (pardata);

		  else if (!strcmp (parname, "AIF_NODELAY"))
		    gw_ifs.aif_nodelay = atoi (pardata);

		  else if (!strcmp (parname, "AIF_SNACK_DELAY"))
		    gw_ifs.aif_snack_delay = atoi (pardata);

		  else if (!strcmp (parname, "AIF_ACK_DELAY"))
		    gw_ifs.aif_ack_delay = atoi (pardata);

		  else if (!strcmp (parname, "AIF_ACK_BEHAVE"))
		    gw_ifs.aif_ack_behave = atoi (pardata);

		  else if (!strcmp (parname, "AIF_TCPONLY"))
		    gw_ifs.aif_tcponly = atoi (pardata);

		  else if (!strcmp (parname, "AIF_NEXT_HOP")) {
		      gw_ifs.aif_next_hop = ddtol ((char *) pardata);
		      strcpy (gw_ifs.aif_next_hop_ipstr, pardata);
                    }
		  else if (!strcmp (parname, "AIF_MTU"))
		    {
		      gw_ifs.aif_mtu = atoi (pardata);
#ifdef NOT_DEFINED
		      /* compare the specified MTU to that dictated
		       * in the i/f. Take the minimum of the two. */
		      memset (&if_str, 0, sizeof (struct ifreq));
		      strcpy (if_str.ifr_name, gw_ifs.aif_name);

		      retval = ioctl (temp_sd, SIOCGIFMTU, &if_str);
		      /* for testing */
		      if (retval != 0) {
			printf ("%s %d ERROR: MTU ioctl call returned %d\n", __FILE__, __LINE__, retval);
		      } else {
			printf ("MTU ioctl call returned %d\n", if_str.ifr_mtu);
			gw_ifs.aif_mtu =
			  min ((int) (atoi (pardata)), if_str.ifr_mtu);
                      }
#endif /* NOT_DEFINED */

		    }

		  else if (!strcmp (parname, "AIF_IRTO"))
		    gw_ifs.aif_irto = atoi (pardata);
                  
		  else if (!strcmp (parname, "AIF_MINRTO"))
		    gw_ifs.aif_minrto = atoi (pardata);
                  
		  else if (!strcmp (parname, "AIF_MAXRTO")) 
		    gw_ifs.aif_maxrto = atoi (pardata);
                  
		  else if (!strcmp (parname, "AIF_MAXRTO_CTR")) 
		    gw_ifs.aif_maxrto_ctr = atoi (pardata);
                  
		  else if (!strcmp (parname, "AIF_MAXPERSIST_CTR")) 
		    gw_ifs.aif_maxpersist_ctr = atoi (pardata);
                  
		  else if (!strcmp (parname, "AIF_RTOPERSIST_MAX")) 
		    gw_ifs.aif_rtopersist_max = atoi (pardata);
                  
		  else if (!strcmp (parname, "AIF_RTO_TO_PERSIST_CTR")) 
		    gw_ifs.aif_rto_to_persist_ctr = atoi (pardata);
                  
		  else if (!strcmp (parname, "AIF_EMBARGO_FAST_RXMIT_CTR")) 
		    gw_ifs.aif_embargo_fast_rxmit_ctr = atoi (pardata);
                  
		  else if (!strcmp (parname, "AIF_2MSLTIMEOUT")) 
		    gw_ifs.aif_2msltimeout = atoi (pardata);
                  
		  else if (!strcmp (parname, "AIF_NL"))
		    gw_ifs.aif_nl = atoi (pardata);

		  else if (!strcmp (parname, "AIF_IPSEC_DOWNSTREAM"))
		    gw_ifs.aif_encrypt_ipsec_downstream = atol (pardata);

		  else if (!strcmp (parname, "AIF_ENCRYPT_PRE_OVERHEAD"))
		    gw_ifs.aif_encrypt_pre_overhead = atol (pardata);

		  else if (!strcmp (parname, "AIF_ENCRYPT_BLOCK_SIZE"))
		    gw_ifs.aif_encrypt_block_size = atol (pardata);

		  else if (!strcmp (parname, "AIF_ENCRYPT_POST_OVERHEAD"))
		    gw_ifs.aif_encrypt_post_overhead = atol (pardata);

		  else if (!strcmp (parname, "AIF_LAN_OR_WAN"))
		    gw_ifs.aif_gateway_lan_or_wan = atoi (pardata);

		  else if (!strcmp (parname, "AIF_MPF"))
		    gw_ifs.aif_mpf = atoi (pardata);  
  
		  else if (!strcmp (parname, "AIF_DIV_ADDR"))
		    gw_ifs.aif_div_addr = ddtol ((char *) pardata);

		  else if (!strcmp (parname, "AIF_DIV_PORT"))
		    gw_ifs.aif_div_port = atoi (pardata);

		  else if (!strcmp (parname, "AIF_TP_COMPRESS"))
		    gw_ifs.aif_tp_compress = atoi (pardata);  
  
		  else if (!strcmp (parname, "AIF_MPF_XMIT_DELAY"))
		    gw_ifs.aif_mpf_xmit_delay = atoi (pardata);  
  
		 else if (!strcmp (parname, "AIF_ECBS1"))
		    gw_ifs.aif_ecbs1 = atoi (pardata);  
  
		  else if (!strcmp (parname, "AIF_ECBS1_VALUE"))
		      strcpy (gw_ifs.aif_ecbs1_value, pardata);

		 else if (!strcmp (parname, "AIF_ECBS1_LEN"))
		    gw_ifs.aif_ecbs1_len = atoi (pardata);  
  
		 else if (!strcmp (parname, "AIF_ECBS2"))
		    gw_ifs.aif_ecbs2 = atoi (pardata);  
  
		  else if (!strcmp (parname, "AIF_ECBS2_VALUE"))
		      strcpy (gw_ifs.aif_ecbs2_value, pardata);

		 else if (!strcmp (parname, "AIF_ECBS2_LEN"))
		    gw_ifs.aif_ecbs2_len = atoi (pardata);  
  
		  else if (!strcmp (parname, "AIF_MPF_SRC")) {
                      if (gw_ifs.aif_mpf_src_cnt == MAX_MPF_ADDRS) {
      			printf ("ERROR: Maximum number of Multiple Path Forwarding is %d\n",
			      MAX_MPF_ADDRS);
			      exit (-1);
 		      }

		      memcpy (&gw_ifs.aif_mpf_src_ipstr [gw_ifs.aif_mpf_src_cnt], pardata,
                              strlen (pardata));
		      gw_ifs.aif_mpf_src [gw_ifs.aif_mpf_src_cnt] = ddtol ((char *) pardata);
		      gw_ifs.aif_mpf_src_cnt++;
		  }
  
		  else if (!strcmp (parname, "AIF_MPF_DST")) {
                      if (gw_ifs.aif_mpf_dst_cnt == MAX_MPF_ADDRS) {
      			printf ("ERROR: Maximum number of Multiple Path Forwarding is %d\n",
			      MAX_MPF_ADDRS);
			      exit (-1);
 		      }

		      memcpy (&gw_ifs.aif_mpf_dst_ipstr [gw_ifs.aif_mpf_dst_cnt], pardata,
                              strlen (pardata));
		      gw_ifs.aif_mpf_dst [gw_ifs.aif_mpf_dst_cnt] = ddtol ((char *) pardata);
		      gw_ifs.aif_mpf_dst_cnt++;
		  }

		  else if (!strcmp (parname, "BIF_ADDR"))
		    {
/*
                     gw_ifs.bif_mask[cnt_bif_addrs] = inet_addr(pardata);
*/
		      gw_ifs.bif_addr[cnt_bif_addrs] = ddtol ((char *) pardata);
		      strcpy (gw_ifs.bif_addrstr[cnt_bif_addrs++], pardata);
		    }

		  else if (!strcmp (parname, "BIF_MASK"))
		    {
/*
                     gw_ifs.bif_mask[cnt_bif_masks++] = inet_addr(pardata);
*/
		      gw_ifs.bif_mask[cnt_bif_masks] = ddtol ((char *) pardata);
		      strcpy (gw_ifs.bif_maskstr[cnt_bif_masks++], pardata);
		    }

		  else if (!strcmp (parname, "BIF_LOCAL_IP")) {
		      memcpy (&gw_ifs.bif_local_ipstr,pardata, strlen (pardata));
		      gw_ifs.bif_local_ipaddr = ddtol ((char *) pardata);
		  }

		  else if (!strcmp (parname, "BIF_REMOTE_IP")) {
		      memcpy (&gw_ifs.bif_remote_ipstr,pardata, strlen (pardata));
		      gw_ifs.bif_remote_ipaddr = ddtol ((char *) pardata);
		  }

		  else if (!strcmp (parname, "BIF_NAME"))
		    strcpy (gw_ifs.bif_name, pardata);

		  else if (!strcmp (parname, "BIF_TUN_NAME"))
		    strcpy (gw_ifs.bif_tun_name, pardata);

		  else if (!strcmp (parname, "BIF_TAP_NAME"))
		    strcpy (gw_ifs.bif_tap_name, pardata);

		  else if (!strcmp (parname, "BIF_BUF"))
		    gw_ifs.bif_buf = atoi (pardata);

		  else if (!strcmp (parname, "BIF_RBUF"))
		    gw_ifs.bif_rbuf = atoi (pardata);

		  else if (!strcmp (parname, "BIF_RATE"))
		    gw_ifs.bif_rate = atoi (pardata);

		  else if (!strcmp (parname, "BIF_MIN_RATE"))
		    gw_ifs.bif_min_rate = atoi (pardata);

		  else if (!strcmp (parname, "BIF_CC"))
		    gw_ifs.bif_cc = atoi (pardata);

		  else if (!strcmp (parname, "BIF_VEGAS_ALPHA"))
		    gw_ifs.bif_vegas_alpha = atoi (pardata);

		  else if (!strcmp (parname, "BIF_VEGAS_BETA"))
		    gw_ifs.bif_vegas_beta = atoi (pardata);

		  else if (!strcmp (parname, "BIF_VEGAS_GAMMA"))
		    gw_ifs.bif_vegas_gamma = atoi (pardata);

		  else if (!strcmp (parname, "BIF_VEGAS_SS"))
		    gw_ifs.bif_vegas_ss = atoi (pardata);

		  else if (!strcmp (parname, "BIF_FLOW_CONTROL_CAP"))
		    gw_ifs.bif_flow_control_cap = atoi (pardata);

		  else if (!strcmp (parname, "BIF_TAP_NO_PHY"))
		    gw_ifs.bif_tap_no_phy = atoi (pardata);

		  else if (!strcmp (parname, "BIF_SCPS_SECURITY"))
		    gw_ifs.bif_scps_security = atoi (pardata);

		  else if (!strcmp (parname, "BIF_DIVPORT"))
		    gw_ifs.bif_divport = atoi (pardata);

		  else if (!strcmp (parname, "BIF_LAYERING"))
		    gw_ifs.bif_layering = atoi (pardata);

		  else if (!strcmp (parname, "BIF_OVERHEAD"))
		    gw_ifs.bif_overhead = atoi (pardata);

		  else if (!strcmp (parname, "BIF_MSS_FF"))
		    gw_ifs.bif_mss_ff = atoi (pardata);

		  else if (!strcmp (parname, "BIF_SMTU"))
		    gw_ifs.bif_smtu = atoi (pardata);

		  else if (!strcmp (parname, "BIF_TS"))
		    gw_ifs.bif_ts = atoi (pardata);

		  else if (!strcmp (parname, "BIF_SNACK"))
		    gw_ifs.bif_snack = atoi (pardata);

		  else if (!strcmp (parname, "BIF_NODELAY"))
		    gw_ifs.bif_nodelay = atoi (pardata);

		  else if (!strcmp (parname, "BIF_SNACK_DELAY"))
		    gw_ifs.bif_snack_delay = atoi (pardata);

		  else if (!strcmp (parname, "BIF_ACK_DELAY"))
		    gw_ifs.bif_ack_delay = atoi (pardata);

		  else if (!strcmp (parname, "BIF_ACK_BEHAVE"))
		    gw_ifs.bif_ack_behave = atoi (pardata);

		  else if (!strcmp (parname, "BIF_TCPONLY"))
		    gw_ifs.bif_tcponly = atoi (pardata);

		  else if (!strcmp (parname, "BIF_NEXT_HOP")) {
		      gw_ifs.bif_next_hop = ddtol ((char *) pardata);
		      strcpy (gw_ifs.bif_next_hop_ipstr, pardata);
                    }

		  else if (!strcmp (parname, "BIF_MTU"))
		    {
		      gw_ifs.bif_mtu = atoi (pardata);
#ifdef NOT_DEFINED
		      /* compare the specified MTU to that dictated
		       * in the i/f. Take the minimum of the two. */
		      memset (&if_str, 0, sizeof (struct ifreq));
		      strcpy (if_str.ifr_name, gw_ifs.bif_name);

		      retval = ioctl (temp_sd, SIOCGIFMTU, &if_str);
		      /* for testing */
		      if (retval != 0)
			printf ("%s %d ERROR: MTU ioctl call returned %d\n",__FILE__, __LINE__,  retval);
		      else
			gw_ifs.bif_mtu = min ((int) (atoi (pardata)), if_str.ifr_mtu);
#endif /* NOT_DEFINED */
		    }

		  else if (!strcmp (parname, "BIF_IRTO"))
		    gw_ifs.bif_irto = atoi (pardata);
                    
		  else if (!strcmp (parname, "BIF_MINRTO"))
		    gw_ifs.bif_minrto = atoi (pardata);
                    
		  else if (!strcmp (parname, "BIF_MAXRTO"))
		    gw_ifs.bif_maxrto = atoi (pardata);
                    
		  else if (!strcmp (parname, "BIF_MAXRTO_CTR")) 
		    gw_ifs.bif_maxrto_ctr = atoi (pardata);
                  
		  else if (!strcmp (parname, "BIF_MAXPERSIST_CTR")) 
		    gw_ifs.bif_maxpersist_ctr = atoi (pardata);
                  
		  else if (!strcmp (parname, "BIF_RTOPERSIST_MAX")) 
		    gw_ifs.bif_rtopersist_max = atoi (pardata);
                  
		  else if (!strcmp (parname, "BIF_RTO_TO_PERSIST_CTR")) 
		    gw_ifs.bif_rto_to_persist_ctr = atoi (pardata);
                  
		  else if (!strcmp (parname, "BIF_EMBARGO_FAST_RXMIT_CTR")) 
		    gw_ifs.bif_embargo_fast_rxmit_ctr  = atoi (pardata);
                  
		  else if (!strcmp (parname, "BIF_2MSLTIMEOUT")) 
		    gw_ifs.bif_2msltimeout = atoi (pardata);
                  
		  else if (!strcmp (parname, "BIF_NL"))
		    gw_ifs.bif_nl = atoi (pardata);

		  else if (!strcmp (parname, "BIF_IPSEC_DOWNSTREAM"))
		    gw_ifs.bif_encrypt_ipsec_downstream = atol (pardata);

		  else if (!strcmp (parname, "BIF_ENCRYPT_PRE_OVERHEAD"))
		    gw_ifs.bif_encrypt_pre_overhead = atol (pardata);

		  else if (!strcmp (parname, "BIF_ENCRYPT_BLOCK_SIZE"))
		    gw_ifs.bif_encrypt_block_size = atol (pardata);

		  else if (!strcmp (parname, "BIF_ENCRYPT_POST_OVERHEAD"))
		    gw_ifs.bif_encrypt_post_overhead = atol (pardata);

		  else if (!strcmp (parname, "BIF_LAN_OR_WAN"))
		    gw_ifs.bif_gateway_lan_or_wan = atoi (pardata);

		  else if (!strcmp (parname, "BIF_MPF"))
		    gw_ifs.bif_mpf = atoi (pardata);

		  else if (!strcmp (parname, "BIF_DIV_ADDR"))
		    gw_ifs.bif_div_addr = ddtol ((char *) pardata);

		  else if (!strcmp (parname, "BIF_DIV_PORT"))
		    gw_ifs.bif_div_port = atoi (pardata);

		  else if (!strcmp (parname, "BIF_TP_COMPRESS"))
		    gw_ifs.bif_tp_compress = atoi (pardata);

		  else if (!strcmp (parname, "BIF_MPF_XMIT_DELAY"))
		    gw_ifs.bif_mpf_xmit_delay = atoi (pardata);  
  
		 else if (!strcmp (parname, "BIF_ECBS1"))
		    gw_ifs.bif_ecbs1 = atoi (pardata);  
  
		  else if (!strcmp (parname, "BIF_ECBS1_VALUE"))
		      strcpy (gw_ifs.bif_ecbs1_value, pardata);

		 else if (!strcmp (parname, "BIF_ECBS1_LEN"))
		    gw_ifs.bif_ecbs1_len = atoi (pardata);  
  
		 else if (!strcmp (parname, "BIF_ECBS2"))
		    gw_ifs.bif_ecbs2 = atoi (pardata);  
  
		  else if (!strcmp (parname, "BIF_ECBS2_VALUE"))
		      strcpy (gw_ifs.bif_ecbs2_value, pardata);

		 else if (!strcmp (parname, "BIF_ECBS2_LEN"))
		    gw_ifs.bif_ecbs2_len = atoi (pardata);  
  
		  else if (!strcmp (parname, "BIF_MPF_SRC")) {
                      if (gw_ifs.bif_mpf_src_cnt == MAX_MPF_ADDRS) {
      			printf ("ERROR: Maximum number of Multiple Path Forwarding is %d\n",
			      MAX_MPF_ADDRS);
			      exit (-1);
 		      }

		      memcpy (&gw_ifs.bif_mpf_src_ipstr [gw_ifs.bif_mpf_src_cnt],
                               pardata, strlen (pardata));
		      gw_ifs.bif_mpf_src [gw_ifs.bif_mpf_src_cnt] = ddtol ((char *) pardata);
		      gw_ifs.bif_mpf_src_cnt++;
		  }
  
		  else if (!strcmp (parname, "BIF_MPF_DST")) {
                      if (gw_ifs.bif_mpf_dst_cnt == MAX_MPF_ADDRS) {
      			printf ("ERROR: Maximum number of Multiple Path Forwarding is %d\n",
			      MAX_MPF_ADDRS);
			      exit (-1);
 		      }

		      memcpy (&gw_ifs.bif_mpf_dst_ipstr [gw_ifs.bif_mpf_dst_cnt], pardata,
                              strlen (pardata));
		      gw_ifs.bif_mpf_dst [gw_ifs.bif_mpf_dst_cnt] = ddtol ((char *) pardata);
		      gw_ifs.bif_mpf_dst_cnt++;
		  }
		  else if (!strcmp (parname, "C_DIVPORT"))
		    gw_ifs.c_divport = atoi (pardata);

		  else if (!strcmp (parname, "C_TUN_NAME"))
		    strcpy (gw_ifs.c_tun_name, pardata);

		  else if (!strcmp (parname, "C_NETSTAT_INTERVAL"))
		    gw_ifs.c_netstat_interval = atoi (pardata);

		  else if (!strcmp (parname, "C_LOCAL_UDP_PORT"))
		    gw_ifs.c_scps_local_udp_port = atoi (pardata);

		  else if (!strcmp (parname, "C_REMOTE_UDP_PORT"))
		    gw_ifs.c_scps_remote_udp_port = atoi (pardata);

		  else if (!strcmp (parname, "C_DIVERT_START_RULE"))
		    gw_ifs.c_divert_start_rule = atoi (pardata);

		  else if (!strcmp (parname, "C_DIVERT_INSERT_RULE"))
		    gw_ifs.c_divert_insert_rule = atoi (pardata);

		  else if (!strcmp (parname, "C_CLUST_THRESH"))
		    gw_ifs.c_clust_thresh = atoi (pardata);

		  else if (!strcmp (parname, "C_CLUST_FILENAME"))
		    strcpy (gw_ifs.c_clust_filename, pardata);

		  else if (!strcmp (parname, "C_PKT_IO_FILENAME"))
		    strcpy (gw_ifs.c_pkt_io_filename, pardata);

		  else if (!strcmp (parname, "C_OTHER_PROTO_QLEN"))
		    gw_ifs.c_other_proto_qlen = atoi (pardata);

		  else if (!strcmp (parname, "C_OTHER_PROTO_XRATE_DROP"))
		    gw_ifs.c_other_proto_xrate_drop = atoi (pardata);

                  else if (!strcmp (parname, "C_OTHER_PROTO_NON_IP"))
                    gw_ifs.c_other_proto_non_ip = atoi (pardata);

                  else if (!strcmp (parname, "C_OTHER_PROTO_IPV6"))
                    gw_ifs.c_other_proto_ipv6 = atoi (pardata);

                  else if (!strcmp (parname, "C_TAP_REMOTE_ACCESS"))
                    gw_ifs.c_tap_remote_access = atoi (pardata);
	  	  else

/*
		      SET_ERR(E???);
*/
		    printf
		      ("\n ERROR in reading %s: undefined parameter %s.",
		       rsc_file, parname);
		}		/* if !EOF     */
	    }			/* if !comment */
	}			/* end while   */
      fclose (fp);
    } else {
  /* if couldn't open, unrecoverable error */
/*
      SET_ERR(EFILEOPEN);
*/
      printf ("\n UNRECOVERABLE ERROR opening AAA %s.\n\n", rsc_file);
      readOK = 0;
    }

	if (gw_ifs.aif_min_rate == 0) {
		gw_ifs.aif_min_rate = gw_ifs.aif_rate;
	}

	if (gw_ifs.bif_min_rate == 0) {
		gw_ifs.bif_min_rate = gw_ifs.bif_rate;
	}

   if (gw_ifs.aif_mpf_src_cnt != gw_ifs.aif_mpf_dst_cnt) {
      printf ("ERROR: Interface A Multiple Path Forwarding Enteries for source (%d)\n",
               gw_ifs.aif_mpf_src_cnt);
      printf ("       and destination (%d) do not exist\n",
               gw_ifs.aif_mpf_dst_cnt);
	exit (-1);
   }

   if (gw_ifs.bif_mpf_src_cnt != gw_ifs.bif_mpf_dst_cnt) {
      printf ("ERROR: Interface B Multiple Path Forwarding Enteries for source (%d)\n",
               gw_ifs.bif_mpf_src_cnt);
      printf ("       and destination (%d) do not exist\n",
               gw_ifs.bif_mpf_dst_cnt);
	exit (-1);
   }

  /* Now that entire file has been read, we have interface names
   * (which are required), and file-specified MTUs, if supplied.
   * We need to get the MTUs off of the interfaces, and if either
   * the user didn't specify one or the user specified one that was
   * too big, we need to replace it with the interface's MTU.
   */
  /* PDF: Compare the specified MTU to that MTU specified for that interface. Take the minimum of the two. */

  if (!(gw_ifs.aif_tap_no_phy)) {

	  memset (&if_str, 0, sizeof (struct ifreq));
	  strcpy (if_str.ifr_name, gw_ifs.aif_name);

	  retval = ioctl (temp_sd, SIOCGIFMTU, &if_str);

	  /* for testing */
	  if (retval != 0) {
      		printf ("%s %d ERROR: MTU ioctl call on interface %s returned %d\n", __FILE__, __LINE__,
		      gw_ifs.aif_name, retval);
#ifndef TAP_INTERFACE
  		    exit (-1);
#endif /* TAP_INTERFACE */
 	 } else {
   	 if (!gw_ifs.aif_mtu) {
  	    gw_ifs.aif_mtu = if_str.ifr_mtu;
 	   } else {
   	   gw_ifs.aif_mtu = min (gw_ifs.aif_mtu, if_str.ifr_mtu);
 	   }
	
  	  if ((!(gw_ifs.aif_mtu)) || (gw_ifs.aif_mtu > if_str.ifr_mtu)) {
    	  gw_ifs.aif_mtu = if_str.ifr_mtu;
  	  }
 	 } 

  }

  if (!(gw_ifs.aif_tap_no_phy)) {
	  memset (&if_str, 0, sizeof (struct ifreq));
	  strcpy (if_str.ifr_name, gw_ifs.bif_name);
	
 	 retval = ioctl (temp_sd, SIOCGIFMTU, &if_str);
 	 /* for testing */
	  if (retval != 0) {
  	    printf ("%s %d ERROR: MTU ioctl call on interface %s returned %d\n", __FILE__, __LINE__,
	      gw_ifs.bif_name, retval);
	#ifndef TAP_INTERFACE
   	   exit (-1);
	#endif /* TAP_INTERFACE */
	  } else {
	    if (!gw_ifs.bif_mtu) {
	      gw_ifs.bif_mtu = if_str.ifr_mtu;
	    } else {
	      gw_ifs.bif_mtu = min (gw_ifs.bif_mtu, if_str.ifr_mtu);
   	 }
		
  	  if ((!(gw_ifs.bif_mtu)) || (gw_ifs.bif_mtu > if_str.ifr_mtu)) {
    	  gw_ifs.bif_mtu = if_str.ifr_mtu;
    	}
  	}
   }

  if (!(gw_ifs.aif_smtu)) {
    gw_ifs.aif_smtu = gw_ifs.aif_mtu;
  }
                       
  if (!(gw_ifs.bif_smtu)) {
    gw_ifs.bif_smtu = gw_ifs.bif_mtu; 
  }   

  if (!(gw_ifs.aif_gateway_lan_or_wan)) {
    gw_ifs.aif_gateway_lan_or_wan = GATEWAY_LAN_SIDE;
  }

  if (!(gw_ifs.bif_gateway_lan_or_wan)) {
    gw_ifs.bif_gateway_lan_or_wan = GATEWAY_WAN_SIDE;
  }

  return (1);
}

int32_t
ddtol (dots)
     char *dots;
{
  char c;
  int i, j, char_ctr, next_section;
  sect convertsect;
  sectaddr ipaddr;
  char *zerostr = "000";
  int32_t lnum = 0, csect;


  for (i = 0; i < 4; i++)
    memcpy ((ipaddr.sects)[i], zerostr, 3);

  char_ctr = strlen (dots) - 1;
  for (i = 3; i >= 0; i--)
    {
      next_section = 0;
      for (j = 2; j >= 0 && char_ctr >= 0 && !next_section; j--)
	{
	  c = dots[char_ctr];
	  if (c != '.')
	    {
	      (ipaddr.sects)[i][j] = c;
	    }
	  else
	    {
	      next_section = 1;
	    }
	  char_ctr--;
	  if (j == 0 && dots[char_ctr] == '.')
	    char_ctr--;
	}
    }
  for (i = 0; i < 4; i++)
    {
      lnum = (lnum << 8);
      memset (convertsect, '0', sizeof (convertsect));
      memcpy ((char *) convertsect, (char *) ((ipaddr.sects)[i]), 3);
      csect = atoi (convertsect);
      lnum = lnum | csect;
    }

  return (lnum);
}

/* function for testing only; displays contents of gw_ifs */
void
ShowGW_ifs ()
{
  short i;
  printf ("\nREAD RSC FILE #%d", readctr++);
  printf ("\n-----------------");
  if (gw_ifs.aif_name)
    printf ("\n A-Interface %s: ", gw_ifs.aif_name);
  for (i = 0; i < MAX_ADDRS && gw_ifs.aif_addr[i]; i++)
    {
      printf ("\n   Addr %s (%x) ", gw_ifs.aif_addrstr[i],
	      gw_ifs.aif_addr[i]);
      printf ("\n   Mask %s (%x) ", gw_ifs.aif_maskstr[i],
	      gw_ifs.aif_mask[i]);
    }
  if (gw_ifs.aif_buf)
    printf ("\n   Buf size is %d.", gw_ifs.aif_buf);
  if (gw_ifs.aif_buf)
    printf ("\n   Receive buf size is %d.", gw_ifs.aif_rbuf);
  if (gw_ifs.aif_rate)
    printf ("\n   Rate is %d.", gw_ifs.aif_rate);
  if (gw_ifs.aif_min_rate)
    printf ("\n   Minimum Rate is %d.", gw_ifs.aif_min_rate);
  if (gw_ifs.aif_cc)
    printf ("\n   Congestion control is %d.", gw_ifs.aif_cc);
  if (gw_ifs.aif_cc == 2) {
     if (gw_ifs.aif_vegas_alpha)
         printf ("\n   Vegas's Congestion control: alpha  is %d.", gw_ifs.aif_vegas_alpha);
     if (gw_ifs.aif_vegas_beta)
         printf ("\n   Vegas's Congestion control: beta  is %d.", gw_ifs.aif_vegas_beta);
     if (gw_ifs.aif_vegas_gamma)
         printf ("\n   Vegas's Congestion control: gamma  is %d.", gw_ifs.aif_vegas_gamma);
     printf ("\n   Vegas's slow start stategy is %d.", gw_ifs.aif_vegas_ss);
     }

  if (gw_ifs.aif_flow_control_cap) {
    printf ("\n   Flow control cap (bytes) is  %d.", gw_ifs.aif_flow_control_cap);
  }

  if (gw_ifs.aif_tap_no_phy) {
    printf ("\n   No Physical interface associated with the AIF interface\n");
  }

  if (gw_ifs.aif_divport)
    printf ("\n   Divert port is %d.", gw_ifs.aif_divport);
  if (gw_ifs.aif_mtu)
    printf ("\n   MTU is %d.", gw_ifs.aif_mtu);
  if (gw_ifs.aif_smtu)
    printf ("\n   Sending MTU is %d.", gw_ifs.aif_smtu);
  if (gw_ifs.aif_irto)
    printf ("\n   Initial RTO is %d.", gw_ifs.aif_irto);
  if (gw_ifs.aif_minrto)
    printf ("\n   Minimum RTO is %d.", gw_ifs.aif_minrto);
  if (gw_ifs.aif_maxrto)
    printf ("\n   Maximum RTO is %d.", gw_ifs.aif_maxrto);
  if (gw_ifs.aif_scps_security)
    printf ("\n   SCPS Security is %d.", gw_ifs.aif_scps_security);
  printf ("\n   Protocol Layering is %d.", gw_ifs.aif_layering);
  if (gw_ifs.aif_overhead)
    printf ("\n   Additional Layering overhead is %d.", gw_ifs.aif_overhead);
  if (gw_ifs.aif_mss_ff == -1) {
    gw_ifs.aif_mss_ff = gw_ifs.aif_overhead;
  }
  if (gw_ifs.aif_mss_ff)
    printf ("\n   MSS adjustment %d.", gw_ifs.aif_mss_ff);
  
  if (gw_ifs.aif_nl)
    printf ("\n   Default network layer is %d.", gw_ifs.aif_nl);
              
  if (gw_ifs.aif_mpf) {
        int a;
        for (a = 0; a < gw_ifs.aif_mpf_src_cnt; a++) {
                printf ("\n   MPF %d src (%s) dst (%s)", a, gw_ifs.aif_mpf_src_ipstr [a], gw_ifs.aif_mpf_dst_ipstr [a]);
        }         
  } 

  if (gw_ifs.aif_mpf_xmit_delay) {
    printf ("\n   MPF retransmission delay (is msec) is %d.", gw_ifs.aif_mpf_xmit_delay);
  }

  if (gw_ifs.aif_ts == 1) {
    printf ("\n   Timestamps is %d.", gw_ifs.aif_ts);
  }           

  if (gw_ifs.aif_snack == 1) {
    printf ("\n   SNACKS is %d.", gw_ifs.aif_snack);
  }           

  if (gw_ifs.aif_nodelay == 0) {
    printf ("\n   nodelay is is %d.", gw_ifs.aif_nodelay);
  }           

  if (gw_ifs.aif_snack_delay != 0) {
    printf ("\n   Snack Delay is %d.", gw_ifs.aif_snack_delay);
  }           

  if (gw_ifs.aif_ack_behave != -1) {
    printf ("\n   The acknowledgement behavior is %d.", gw_ifs.aif_ack_behave);
  }

  if (gw_ifs.aif_ack_delay) {
    printf ("\n   The delay acknowledgement timer is %d.", gw_ifs.aif_ack_delay);
  }

  if (gw_ifs.aif_tcponly == 1) {
    printf ("\n   Only offer TCP is %d.", gw_ifs.aif_tcponly);
  }           

  if (gw_ifs.bif_name)
    printf ("\n B-Interface %s: ", gw_ifs.bif_name);
  for (i = 0; i < MAX_ADDRS && gw_ifs.bif_mask[i]; i++)
    {
      printf ("\n   Addr %s (%x) ", gw_ifs.bif_addrstr[i],
	      gw_ifs.bif_addr[i]);
      printf ("\n   Mask %s (%x) ", gw_ifs.bif_maskstr[i],
	      gw_ifs.bif_mask[i]);
    }
  if (gw_ifs.bif_buf)
    printf ("\n   Buf size is %d.", gw_ifs.bif_buf);
  if (gw_ifs.bif_buf)
    printf ("\n   Receive buf size is %d.", gw_ifs.bif_rbuf);
  if (gw_ifs.bif_rate)
    printf ("\n   Rate is %d.", gw_ifs.bif_rate);
  if (gw_ifs.bif_min_rate)
    printf ("\n   Minimum Rate is %d.", gw_ifs.bif_min_rate);
  if (gw_ifs.bif_cc)
    printf ("\n   Congestion control is %d.", gw_ifs.bif_cc);
  if (gw_ifs.bif_cc == 2) {
     if (gw_ifs.bif_vegas_alpha)
         printf ("\n   Vegas's Congestion control: alpha  is %d.", gw_ifs.bif_vegas_alpha);
     if (gw_ifs.bif_vegas_beta)
         printf ("\n   Vegas's Congestion control: beta  is %d.", gw_ifs.bif_vegas_beta);
     if (gw_ifs.bif_vegas_gamma)
         printf ("\n   Vegas's Congestion control: gamma  is %d.", gw_ifs.bif_vegas_gamma);
     printf ("\n   Vegas's slow start stategy is %d.", gw_ifs.bif_vegas_ss);
     }

  if (gw_ifs.bif_flow_control_cap) {
    printf ("\n   Flow control cap (bytes) is  %d.", gw_ifs.bif_flow_control_cap);
  }

  if (gw_ifs.bif_tap_no_phy) {
    printf ("\n   No Physical interface associated with the BIF interface\n");
  }

  if (gw_ifs.bif_divport)
    printf ("\n   Divert port is %d.", gw_ifs.bif_divport);
  if (gw_ifs.bif_mtu)
    printf ("\n   MTU is %d.", gw_ifs.bif_mtu);
  if (gw_ifs.bif_smtu)  
    printf ("\n   Sending MTU is %d.", gw_ifs.bif_smtu);
  if (gw_ifs.bif_irto)
    printf ("\n   Initial RTO is %d.", gw_ifs.bif_irto);
  if (gw_ifs.bif_minrto) 
    printf ("\n   Minimum RTO is %d.", gw_ifs.bif_minrto);
  if (gw_ifs.bif_maxrto)
    printf ("\n   Maximum RTO is %d.", gw_ifs.bif_maxrto);
  if (gw_ifs.bif_scps_security)
    printf ("\n   SCPS Security is %d.", gw_ifs.bif_scps_security);
  printf ("\n   Protocol Layering is %d.", gw_ifs.bif_layering);
  if (gw_ifs.bif_overhead)
    printf ("\n   Additional Layering overhead is %d.", gw_ifs.bif_overhead);
  if (gw_ifs.bif_mss_ff == -1) {
    gw_ifs.bif_mss_ff = gw_ifs.bif_overhead;
  }           
  if (gw_ifs.bif_mss_ff)
    printf ("\n   MSS adjustment %d.", gw_ifs.bif_mss_ff);
  
  if (gw_ifs.bif_nl)
    printf ("\n   Default network layer is %d.", gw_ifs.bif_nl);

  if (gw_ifs.bif_mpf) {
        int a;
        for (a = 0; a < gw_ifs.bif_mpf_src_cnt; a++) {
                printf ("\n   MPF %d src (%s) dst (%s)", a, gw_ifs.bif_mpf_src_ipstr [a], gw_ifs.bif_mpf_dst_ipstr [a]);
        }         
  }
  if (gw_ifs.bif_mpf_xmit_delay) {
    printf ("\n   MPF retransmission delay (is msec) is %d.", gw_ifs.bif_mpf_xmit_delay);
  }

  if (gw_ifs.bif_ts == 1) {
    printf ("\n   Timestamps is %d.", gw_ifs.bif_ts);
  }           

  if (gw_ifs.bif_snack == 1) {
    printf ("\n   SNACKS is %d.", gw_ifs.bif_snack);
  }           

  if (gw_ifs.bif_nodelay == 0) {
    printf ("\n   nodelay is is %d.", gw_ifs.bif_nodelay);
  }           

  if (gw_ifs.bif_snack_delay != 0) {
    printf ("\n   Snack delay is %d.", gw_ifs.bif_snack_delay);
  }           

  if (gw_ifs.bif_ack_behave != -1) {
    printf ("\n   The acknowledgement behavior is %d.", gw_ifs.bif_ack_behave);
  }           

  if (gw_ifs.bif_ack_delay) {
    printf ("\n   The delay acknowledgement timer is %d.", gw_ifs.bif_ack_delay);
  }

  if (gw_ifs.bif_tcponly == 1) {
    printf ("\n   Only offer TCP is %d.", gw_ifs.bif_tcponly);
  }           
  
  if (gw_ifs.c_divport)
    printf ("\nPort C is %d.", gw_ifs.c_divport);

  if (gw_ifs.c_scps_local_udp_port)
    printf ("\n   SCPS local UDP port is %d.",gw_ifs.c_scps_local_udp_port);
  scps_udp_port = gw_ifs.c_scps_local_udp_port;
  if (gw_ifs.c_scps_remote_udp_port)
    printf ("\n   SCPS remote UDP port is %d.",gw_ifs.c_scps_remote_udp_port);
  scps_udp_port1 = gw_ifs.c_scps_remote_udp_port;

#ifdef GATEWAY_DUAL_INTERFACE
  special_port_number = scps_udp_port1;
#endif /* GATEWAY_DUAL_INTERFACE */

  printf ("\n\n");
  return;
}

int
gateway_ipfw ()
{
  int temp_sd, i, basenum;
#ifdef MPF
  int j;
#endif /* MPF */
  int retval = 0;
  struct ifreq if_str;
  struct sockaddr_in saddr;

  char aif_addr_string[256];
  char bif_addr_string[256];
  char ipfw_cmd[256];

  /* get the local addrs for both A and B interfaces */
  temp_sd = socket (PF_INET, SOCK_DGRAM, 0);

  memset (&if_str, 0, sizeof (struct ifreq));
  strcpy (if_str.ifr_name, gw_ifs.aif_name);

  retval = ioctl (temp_sd, SIOCGIFADDR, &if_str);
  /* for testing */
  if (retval != 0)
    {
      printf ("FATAL ERROR: ioctl returned %d for specified AIF_NAME %s. \n",
	      retval, gw_ifs.aif_name);
      printf ("             Re-enter AIF_NAME into resource file.\n");
      printf
	("             Choose valid AIF_NAME from among the following: \n");
      system ("netstat -i");
      printf ("\n");
      printf ("GATEWAY ABORTING........\n\n");
      exit (-1);
    }
  memcpy (&(saddr), &(if_str.ifr_addr), sizeof (struct sockaddr));
  strcpy (aif_addr_string, inet_ntoa (saddr.sin_addr));

  memset (&if_str, 0, sizeof (struct ifreq));
  strcpy (if_str.ifr_name, gw_ifs.bif_name);

  retval = ioctl (temp_sd, SIOCGIFADDR, &if_str);
  /* for testing */
  if (retval != 0)
    printf ("ioctl returned %d, \n", retval);
  memcpy (&(saddr), &(if_str.ifr_addr), sizeof (struct sockaddr));
  strcpy (bif_addr_string, inet_ntoa (saddr.sin_addr));

  /* for testing */
  printf ("Got %s interface address:  %s\n", gw_ifs.aif_name, aif_addr_string);
  printf ("Got %s interface address:  %s\n", gw_ifs.bif_name, bif_addr_string);

  if (gw_ifs.c_divert_start_rule) {
	divert_start_rule = gw_ifs.c_divert_start_rule;
  }

  if (gw_ifs.c_divert_insert_rule) {
	divert_insert_rule = gw_ifs.c_divert_insert_rule;
  }

  /* clear out the previous ipfw rules */
#ifdef LINUX
    sprintf(ipfw_cmd, "ipchains -F >& /dev/null");
    SYSTEM(ipfw_cmd);
#endif /* LINUX */
#ifdef __FreeBSD__
  for (i = divert_start_rule; i <= divert_start_rule + 8; i++)
    {
      sprintf (ipfw_cmd, "ipfw delete %d 2> /dev/null ", i);
#ifdef EXTERNAL_RULE_GENERATION
      while (!system (ipfw_cmd));	/* I ain't got no body */
#endif /* EXTERNAL_RULE_GENERATION */
    }
#endif /* __FreeBSD__ */

  /* Set up the IP Firewall rules to divert the packets */

  /* this uses the local interface addresses for A, then B */
  /* Permit inbound and outbound traffic that is to/from the
     interface addresses. */

  i = divert_start_rule+2;
#ifdef __FreeBSD__
  sprintf (ipfw_cmd, "ipfw add %d allow all from any to %s",
	   i++, aif_addr_string);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd, "ipfw add %d allow all from any to %s",
	   i++, bif_addr_string);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd, "ipfw add %d allow all from %s to any",
	   i++, aif_addr_string);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd, "ipfw add %d allow all from %s to any",
	   i++, bif_addr_string);
  SYSTEM (ipfw_cmd);
#endif /* __FreeBSD__ */
#ifdef LINUX
  sprintf (ipfw_cmd, "ipchains -A input --destination %s --jump ACCEPT", aif_addr_string);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd, "ipchains -A input --destination %s --jump ACCEPT", bif_addr_string);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd, "ipchains -A output --source %s --jump ACCEPT", aif_addr_string);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd, "ipchains -A output --source %s --jump ACCEPT", bif_addr_string);
  SYSTEM (ipfw_cmd);
#endif /* LINUX */

  /* Divert all TCP setup traffic received on interface A to divert port A */
  basenum = divert_start_rule + 6;

#ifdef UDP_GATEWAY
#ifdef __FreeBSD__
    sprintf (ipfw_cmd,
	   "ipfw add %d divert %d %d from any to any via %s in",
	   basenum, gw_ifs.aif_divport, 17, gw_ifs.aif_name);
#endif /* __FreeBSD__ */
#ifdef LINUX
    sprintf (ipfw_cmd,
	"ipchains -A input --protocol %d --interface %s --jump DIVERT %d",
	   17, gw_ifs.aif_name, gw_ifs.aif_divport);
#endif /* LINUX */
    SYSTEM (ipfw_cmd);
#endif /* UDP_GATEWAY */

#ifdef SECURE_GATEWAY
  if (gw_ifs.aif_scps_security >= 1) {
#ifdef __FreeBSD__
    sprintf (ipfw_cmd,
	   "ipfw add %d divert %d %d from any to any via %s in",
	   basenum, gw_ifs.aif_divport, SP, gw_ifs.aif_name);
#endif /* __FreeBSD__ */
#ifdef LINUX
    sprintf (ipfw_cmd,
	"ipchains -A input --protocol %d --interface %s --jump DIVERT %d",
	   SP, gw_ifs.aif_name, gw_ifs.aif_divport);
#endif /* LINUX */
    SYSTEM (ipfw_cmd);
  }
  if (gw_ifs.aif_scps_security <= 1) {
#ifdef __FreeBSD__
    sprintf (ipfw_cmd,
	   "ipfw add %d divert %d tcp from any to any via %s setup in",
	   basenum, gw_ifs.aif_divport, gw_ifs.aif_name);
#endif /* __FreeBSD__ */
#ifdef LINUX
    sprintf (ipfw_cmd,
	   "ipchains -A input --protocol tcp --syn --interface %s --jump DIVERT %d",
	   gw_ifs.aif_name, gw_ifs.aif_divport);
#endif /* LINUX */
     SYSTEM (ipfw_cmd);
  }
#else /* SECURE_GATEWAY */
#ifdef __FreeBSD__
  sprintf (ipfw_cmd,
	   "ipfw add %d divert %d tcp from any to any via %s setup in",
	   basenum, gw_ifs.aif_divport, gw_ifs.aif_name);
#endif /* __FreeBSD__ */
#ifdef LINUX
  sprintf (ipfw_cmd,
	   "ipchains -A input --protocol tcp --syn --interface %s --jump DIVERT %d",
	   gw_ifs.aif_name, gw_ifs.aif_divport);
#endif /* LINUX */
  SYSTEM (ipfw_cmd);
#endif /* SECURE_GATEWAY */

#ifdef GATEWAY_DUAL_INTERFACE
#ifdef __FreeBSD__
  sprintf (ipfw_cmd,
	   "ipfw add %d divert %d udp from any to any %d via %s in",
	   divert_start_rule, gw_ifs.aif_divport, 7168, gw_ifs.aif_name);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd,
           "ipfw add %d divert %d icmp from any to any via %s in",
           divert_start_rule, gw_ifs.aif_divport, gw_ifs.aif_name); 
  SYSTEM (ipfw_cmd);
#endif /* __FreeBSD__ */
#ifdef LINUX
  sprintf (ipfw_cmd,
	   "ipchains -A input --protocol udp --port %d --interface %s -j DIVERT %d",
	   7168, gw_ifs.aif_name, gw_ifs.aif_divport);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd,
	   "ipchains -A input --protocol icmp --interface %s -j DIVERT %d",
	   gw_ifs.aif_name, gw_ifs.aif_divport);
  SYSTEM (ipfw_cmd);
#endif /* LINUX */
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef MPF
 if (gw_ifs.aif_mpf == 1) {
   for (j = 0; j < gw_ifs.aif_mpf_src_cnt; j++) {
#ifdef __FreeBSD__
     sprintf (ipfw_cmd,
   	      "ipfw add %d divert %d 4 from %s to %s via %s in",
	      divert_start_rule, gw_ifs.aif_divport, gw_ifs.aif_mpf_src_ipstr [j], gw_ifs.aif_mpf_dst_ipstr [j], gw_ifs.aif_name);
     SYSTEM (ipfw_cmd);
     sprintf (ipfw_cmd,
              "ipfw add %d divert %d 4 from %s to %s via %s in",
	      divert_start_rule, gw_ifs.aif_divport, gw_ifs.aif_mpf_dst_ipstr [j], gw_ifs.aif_mpf_src_ipstr [j], gw_ifs.aif_name);
     SYSTEM (ipfw_cmd);
#endif /* __FreeBSD__ */
#ifdef LINUX
     sprintf (ipfw_cmd,
      	      "ipchains -A input --source %s --destination --protocol 4 --interface %s -j DIVERT %d",
	      gw_ifs.aif_mpf_src_ipstr [j], gw_ifs.aif_mpf_dst_ipstr [j], gw_ifs.aif_name, gw_ifs.aif_divport);
     SYSTEM (ipfw_cmd);
     sprintf (ipfw_cmd,
	      "ipchains -A input --source %s --destination --protocol 4 --interface %s -j DIVERT %d",
	      gw_ifs.aif_mpf_dst_ipstr [j], gw_ifs.aif_mpf_src_ipstr [j], gw_ifs.aif_name, gw_ifs.aif_divport);
     SYSTEM (ipfw_cmd);
#endif /* LINUX */

   }
 }
#endif /* MPF */


  /* Do the same thing, but for interface B and port B */
  basenum = divert_start_rule + 7;

#ifdef UDP_GATEWAY
#ifdef __FreeBSD__
    sprintf (ipfw_cmd,
	   "ipfw add %d divert %d %d from any to any via %s in",
	   basenum, gw_ifs.bif_divport, 17, gw_ifs.bif_name);
#endif /* __FreeBSD__ */
#ifdef LINUX
    sprintf (ipfw_cmd,
	"ipchains -A input --protocol %d --interface %s --jump DIVERT %d",
	   17, gw_ifs.bif_name, gw_ifs.bif_divport);
#endif /* LINUX */
    SYSTEM (ipfw_cmd);
#endif /* UDP_GATEWAY */

#ifdef SECURE_GATEWAY
  if (gw_ifs.bif_scps_security >= 1) {
#ifdef __FreeBSD__
    sprintf (ipfw_cmd,
	   "ipfw add %d divert %d %d from any to any via %s in",
	   basenum, gw_ifs.bif_divport, SP, gw_ifs.bif_name);
#endif /* __FreeBSD__ */
#ifdef LINUX
    sprintf (ipfw_cmd,
	   "ipchains -A input --protocol %d --interface %s -j DIVERT %d add %d divert %d %d from any to any via %s in",
	   SP, gw_ifs.bif_name, gw_ifs.bif_divport);
#endif /* LINUX */
    SYSTEM (ipfw_cmd);
  } 

  if (gw_ifs.bif_scps_security <= 1) {
#ifdef __FreeBSD__
    sprintf (ipfw_cmd,
	   "ipfw add %d divert %d tcp from any to any via %s setup in",
	   basenum, gw_ifs.bif_divport, gw_ifs.bif_name);
#endif /* __FreeBSD__ */
#ifdef LINUX
    sprintf (ipfw_cmd,
	   "ipchains -A input --protocol tcp --syn --interface %s --jump DIVERT %d",
	   gw_ifs.bif_name, gw_ifs.bif_divport);
#endif /* __FreeBSD__ */
    SYSTEM (ipfw_cmd);
  }
#else /* SECURE_GATEWAY */
#ifdef __FreeBSD__
  sprintf (ipfw_cmd,
	   "ipfw add %d divert %d tcp from any to any via %s setup in",
	   basenum, gw_ifs.bif_divport, gw_ifs.bif_name);
#endif /* FREEBSD */
#ifdef LINUX
    sprintf (ipfw_cmd,
	   "ipchains -A input --protocol tcp --syn --interface %s --jump DIVERT %d",
	   gw_ifs.bif_name, gw_ifs.bif_divport);
#endif /* LINUX */
  SYSTEM (ipfw_cmd);
#endif /* SECURE_GATEWAY */

#ifdef GATEWAY_DUAL_INTERFACE
#ifdef __FreeBSD__
  sprintf (ipfw_cmd,
	   "ipfw add %d divert %d udp from any to any %d via %s in",
	   divert_start_rule, gw_ifs.bif_divport, 7168, gw_ifs.bif_name);
  SYSTEM (ipfw_cmd);

  sprintf (ipfw_cmd,
           "ipfw add %d divert %d icmp from any to any via %s in",
           divert_start_rule, gw_ifs.bif_divport, gw_ifs.bif_name); 
  SYSTEM (ipfw_cmd);
#endif /* __FreeBSD__ */
#ifdef LINUX
  sprintf (ipfw_cmd,
	   "ipchains -A input --protocol udp --port %d --interface %s -j DIVERT %d",
	   7168, gw_ifs.bif_name, gw_ifs.bif_divport);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd,
	   "ipchains -A input --protocol icmp --interface %s -j DIVERT %d",
	   gw_ifs.bif_name, gw_ifs.bif_divport);
  SYSTEM (ipfw_cmd);
#endif /* LINUX */

#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef MPF
 if (gw_ifs.bif_mpf == 1) {
   for (j = 0; j < gw_ifs.bif_mpf_src_cnt; j++) {
#ifdef __FreeBSD__
     sprintf (ipfw_cmd,
   	      "ipfw add %d divert %d 4 from %s to %s via %s in",
	      divert_start_rule, gw_ifs.bif_divport, gw_ifs.bif_mpf_src_ipstr [j], gw_ifs.bif_mpf_dst_ipstr [j], gw_ifs.bif_name);
     SYSTEM (ipfw_cmd);
     sprintf (ipfw_cmd,
              "ipfw add %d divert %d 4 from %s to %s via %s in",
	      divert_start_rule, gw_ifs.bif_divport, gw_ifs.bif_mpf_dst_ipstr [j], gw_ifs.bif_mpf_src_ipstr [j], gw_ifs.bif_name);
     SYSTEM (ipfw_cmd);
#endif /* __FreeBSD__ */
#ifdef LINUX
     sprintf (ipfw_cmd,
      	      "ipchains -A input --source %s --destination --protocol 4 --interface %s -j DIVERT %d",
	      gw_ifs.bif_mpf_src_ipstr [j], gw_ifs.bif_mpf_dst_ipstr [j], gw_ifs.bif_name, gw_ifs.bif_divport);
     SYSTEM (ipfw_cmd);
     sprintf (ipfw_cmd,
	      "ipchains -A input --source %s --destination --protocol 4 --interface %s -j DIVERT %d",
	      gw_ifs.bif_mpf_dst_ipstr [j], gw_ifs.bif_mpf_src_ipstr [j], gw_ifs.bif_name, gw_ifs.bif_divport);
     SYSTEM (ipfw_cmd);
#endif /* LINUX */

   }
 }
#endif /* MPF */

  /* Divert all TCP non-setup traffic to Divert port C */
  basenum = divert_start_rule + 8;
  /* It's important for rule # of this to be HIGHER than "via" rules */
#ifdef __FreeBSD__
  sprintf (ipfw_cmd, "ipfw add %d divert %d tcp from any to any in via %s",
	   basenum, gw_ifs.c_divport, gw_ifs.aif_name);
  SYSTEM (ipfw_cmd);

  sprintf (ipfw_cmd, "ipfw add %d divert %d tcp from any to any in via %s",
	   basenum, gw_ifs.c_divport, gw_ifs.bif_name);
  SYSTEM (ipfw_cmd);

  sprintf (ipfw_cmd, "ipfw add %d divert %d 105 from any to any in via %s",
	   basenum, gw_ifs.c_divport, gw_ifs.aif_name);
  SYSTEM (ipfw_cmd);

  sprintf (ipfw_cmd, "ipfw add %d divert %d 105 from any to any in via %s",
	   basenum, gw_ifs.c_divport, gw_ifs.bif_name);
  SYSTEM (ipfw_cmd);
#endif /* __FreeBSD__ */

#ifdef LINUX
  sprintf (ipfw_cmd, "ipchains -A input --protocol tcp  --interface %s -j DIVERT %d",gw_ifs.aif_name, gw_ifs.c_divport);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd, "ipchains -A input --protocol tcp  --interface %s -j DIVERT %d",gw_ifs.bif_name, gw_ifs.c_divport);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd, "ipchains -A input --protocol 105  --interface %s -j DIVERT %d",gw_ifs.aif_name, gw_ifs.c_divport);
  SYSTEM (ipfw_cmd);
  sprintf (ipfw_cmd, "ipchains -A input --protocol 105  --interface %s -j DIVERT %d",gw_ifs.bif_name, gw_ifs.c_divport);
  SYSTEM (ipfw_cmd);
#endif /* LINUX */

  return (1);
}
#endif /* GATEWAY */
