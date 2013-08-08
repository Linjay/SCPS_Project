#ifdef GATEWAY
#ifdef TUN_INTERFACE
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

#include <stdarg.h>
#include "rs_config.h"
#include "ll.h"
#include "route.h"
void gateway_tun_rules (void);
int32_t ddtol (char *dots);

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif /* min */

extern int scps_udp_port;
extern int scps_udp_port1;
extern int nl_default;

#ifdef GATEWAY_DUAL_INTERFACE
extern int special_port_number;
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef EXTERNAL_RULE_GENERATION
#define SYSTEM(A)
#else /* EXTERNAL_RULE_GENERATION */
#define SYSTEM(A) system(A)
#endif /* EXTERNAL_RULE_GENERATION */


extern GW_ifs gw_ifs;


#define ORIG_TABLES "/tmp/saved.tbl"
void gateway_tun_cleanup(void){
    sigset_t sigset;
    sigset_t oldset;
    sigfillset(&sigset);
    sigprocmask(SIG_BLOCK,&sigset,&oldset);
    SYSTEM("iptables-restore <" ORIG_TABLES);
    SYSTEM("ip rule del fwmark 1");
    SYSTEM("ip rule del fwmark 2");
    SYSTEM("ip rule del fwmark 3");
    SYSTEM("ip route flush table 200");
    SYSTEM("ip route flush table 201");
    SYSTEM("ip route flush table 201");
    sigprocmask(SIG_SETMASK,&oldset,0);
}


void
gateway_tun_rules ()

{
  int temp_sd;
#ifdef MPF
  int j;
#endif /* MPF */
  int retval = 0;
  struct ifreq if_str;
  struct sockaddr_in saddr;

  char aif_addr_string[256];
  char bif_addr_string[256];
  char iptables_cmd[256];

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


  /* clear out the previous ipfw rules */

   SYSTEM("iptables -F -t mangle");
   SYSTEM("ip rule del fwmark 1");
   SYSTEM("ip rule del fwmark 2");
   SYSTEM("ip rule del fwmark 3");
   SYSTEM("ip route flush table 200");
   SYSTEM("ip route flush table 201");
   SYSTEM("ip route flush table 201");

  /* this uses the local interface addresses for A, then B */
  /* Permit inbound and outbound traffic that is to/from the
     interface addresses. */

  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle -s %s -j ACCEPT", aif_addr_string);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle -d %s -j ACCEPT", aif_addr_string);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle -s %s -j ACCEPT", bif_addr_string);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle -d %s -j ACCEPT", bif_addr_string);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);


  /* Divert all TCP setup traffic received on interface A to divert port A */

#ifdef SECURE_GATEWAY
  if (gw_ifs.aif_scps_security >= 1) {
    sprintf (iptables_cmd,
	"iptables -A PREROUTING -t mangle --protocol %ld -i %s -j MARK --set-mark 1",
	   SP, gw_ifs.aif_name);
    printf("iptables:: %s\n", iptables_cmd);
    SYSTEM (iptables_cmd);

  if (gw_ifs.aif_scps_security >= 1) {
    sprintf (iptables_cmd,
	"iptables -A PREROUTING -t mangle --protocol %ld -i %s -j ACCEPT",
	   SP, gw_ifs.aif_name);
    printf("iptables:: %s\n", iptables_cmd);
  }

  if (gw_ifs.aif_scps_security <= 1) {
    sprintf (iptables_cmd,
	   "iptables -A PREROUTING -t mangle --protocol tcp --syn -i %s -j MARK --set-mark 1",
	   gw_ifs.aif_name);
    printf("iptables:: %s\n", iptables_cmd);
    SYSTEM (iptables_cmd);

    sprintf (iptables_cmd,
	   "iptables -A PREROUTING -t mangle --protocol tcp --syn -i %s -j ACCEPT",
	   gw_ifs.aif_name);
    printf("iptables:: %s\n", iptables_cmd);
    SYSTEM (iptables_cmd);
  }

#else /* SECURE_GATEWAY */

  sprintf (iptables_cmd,
	   "iptables -A PREROUTING -t mangle --protocol tcp --syn -i %s -j MARK --set-mark 1",
	   gw_ifs.aif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd,
	   "iptables -A PREROUTING -t mangle --protocol tcp --syn -i %s -j ACCEPT",
	   gw_ifs.aif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

#endif /* SECURE_GATEWAY */

#ifdef GATEWAY_DUAL_INTERFACE
  sprintf (iptables_cmd,
	   "iptables -I PREROUTING 1 -t mangle --protocol udp --destination-port %d -i %s -j MARK --set-mark 1",
	   7168, gw_ifs.aif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd,
	   "iptables -I PREROUTING 2 -t mangle --protocol udp --destination-port %d -i %s -j ACCEPT",
	   7168, gw_ifs.aif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd,
	   "iptables -I PREROUTING 3 -t mangle --protocol icmp -i %s -j MARK --set-mark 1",
	   gw_ifs.aif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd,
	   "iptables -I PREROUTING 4 -t mangle --protocol icmp -i %s -j ACCEPT",
	   gw_ifs.aif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
#endif /* GATEWAY_DUAL_INTERFACE */


#ifdef MPF
 if (gw_ifs.aif_mpf == 1) {
   for (j = 0; j < gw_ifs.aif_mpf_src_cnt; j++) {
#ifdef FREEBSD
     sprintf (ipfw_cmd,
   	      "ipfw add %d divert %ld 4 from %s to %s via %s in",
	      LOW_RULE, gw_ifs.aif_divport, gw_ifs.aif_mpf_src_ipstr [j], gw_ifs.aif_mpf_dst_ipstr [j], gw_ifs.aif_name);
     SYSTEM (ipfw_cmd);
     sprintf (ipfw_cmd,
              "ipfw add %d divert %ld 4 from %s to %s via %s in",
	      LOW_RULE, gw_ifs.aif_divport, gw_ifs.aif_mpf_dst_ipstr [j], gw_ifs.aif_mpf_src_ipstr [j], gw_ifs.aif_name);
     SYSTEM (ipfw_cmd);
#endif /* FREEBSD */
#ifdef LINUX
     sprintf (ipfw_cmd,
      	      "ipchains -A input --source %s --destination --protocol 4 --interface %s -j DIVERT %ld",
	      gw_ifs.aif_mpf_src_ipstr [j], gw_ifs.aif_mpf_dst_ipstr [j], gw_ifs.aif_name, gw_ifs.aif_divport);
     printf("ipchains:: %s\n", ipfw_cmd);
     SYSTEM (ipfw_cmd);
     sprintf (ipfw_cmd,
	      "ipchains -A input --source %s --destination --protocol 4 --interface %s -j DIVERT %ld",
	      gw_ifs.aif_mpf_dst_ipstr [j], gw_ifs.aif_mpf_src_ipstr [j], gw_ifs.aif_name, gw_ifs.aif_divport);
     printf("ipchains:: %s\n", ipfw_cmd);
     SYSTEM (ipfw_cmd);
#endif /* LINUX */

   }
 }
#endif /* MPF */


  /* Do the same thing, but for interface B and port B */


  /* Divert all TCP setup traffic received on interface A to divert port B */

#ifdef SECURE_GATEWAY
  if (gw_ifs.bif_scps_security >= 1) {
    sprintf (iptables_cmd,
	"iptables -A PREROUTING -t mangle --protocol %ld -i %s -j MARK --set-mark 2",
	   SP, gw_ifs.bif_name);
    printf("iptables:: %s\n", iptables_cmd);
    SYSTEM (iptables_cmd);

    sprintf (iptables_cmd,
	"iptables -A PREROUTING -t mangle --protocol %ld -i %s -j ACCEPT",
	   SP, gw_ifs.bif_name);
    printf("iptables:: %s\n", iptables_cmd);
    SYSTEM (iptables_cmd);
  }

  if (gw_ifs.bif_scps_security <= 1) {
    sprintf (iptables_cmd,
	   "iptables -A PREROUTING -t mangle --protocol tcp --syn -i %s -j MARK --set-mark 2",
	   gw_ifs.bif_name);
    printf("iptables:: %s\n", iptables_cmd);
    SYSTEM (iptables_cmd);

    sprintf (iptables_cmd,
	   "iptables -A PREROUTING -t mangle --protocol tcp --syn -i %s -j ACCEPT",
	   gw_ifs.bif_name);
    printf("iptables:: %s\n", iptables_cmd);
    SYSTEM (iptables_cmd);
  }

#else /* SECURE_GATEWAY */

  sprintf (iptables_cmd,
	   "iptables -A PREROUTING -t mangle --protocol tcp --syn -i %s -j MARK --set-mark 2",
	   gw_ifs.bif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd,
	   "iptables -A PREROUTING -t mangle --protocol tcp --syn -i %s -j ACCEPT",
	   gw_ifs.bif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

#endif /* SECURE_GATEWAY */

#ifdef GATEWAY_DUAL_INTERFACE
  sprintf (iptables_cmd,
	   "iptables -I PREROUTING 1 -t mangle --protocol udp --destination-port %d -i %s -j MARK --set-mark 2",
	   7168, gw_ifs.bif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd,
	   "iptables -I PREROUTING 2 -t mangle --protocol udp --destination-port %d -i %s -j ACCEPT",
	   7168, gw_ifs.bif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd,
	   "iptables -I PREROUTING 3 -t mangle --protocol icmp -i %s -j MARK --set-mark 2",
	   gw_ifs.bif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd,
	   "iptables -I PREROUTING 4 -t mangle --protocol icmp -i %s -j ACCEPT",
	   gw_ifs.bif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
#endif /* GATEWAY_DUAL_INTERFACE */



#ifdef MPF
 if (gw_ifs.bif_mpf == 1) {
   for (j = 0; j < gw_ifs.bif_mpf_src_cnt; j++) {
#ifdef FREEBSD
     sprintf (ipfw_cmd,
   	      "ipfw add %d divert %ld 4 from %s to %s via %s in",
	      LOW_RULE, gw_ifs.bif_divport, gw_ifs.bif_mpf_src_ipstr [j], gw_ifs.bif_mpf_dst_ipstr [j], gw_ifs.bif_name);
     SYSTEM (ipfw_cmd);
     sprintf (ipfw_cmd,
              "ipfw add %d divert %ld 4 from %s to %s via %s in",
	      LOW_RULE, gw_ifs.bif_divport, gw_ifs.bif_mpf_dst_ipstr [j], gw_ifs.bif_mpf_src_ipstr [j], gw_ifs.bif_name);
     SYSTEM (ipfw_cmd);
#endif /* FREEBSD */
#ifdef LINUX
     sprintf (ipfw_cmd,
      	      "ipchains -A input --source %s --destination --protocol 4 --interface %s -j DIVERT %ld",
	      gw_ifs.bif_mpf_src_ipstr [j], gw_ifs.bif_mpf_dst_ipstr [j], gw_ifs.bif_name, gw_ifs.bif_divport);
     printf("ipchains:: %s\n", ipfw_cmd);
     SYSTEM (ipfw_cmd);
     sprintf (ipfw_cmd,
	      "ipchains -A input --source %s --destination --protocol 4 --interface %s -j DIVERT %ld",
	      gw_ifs.bif_mpf_dst_ipstr [j], gw_ifs.bif_mpf_src_ipstr [j], gw_ifs.bif_name, gw_ifs.bif_divport);
     printf("ipchains:: %s\n", ipfw_cmd);
     SYSTEM (ipfw_cmd);
#endif /* LINUX */

   }
 }
#endif /* MPF */

  /* Divert all TCP non-setup traffic to Divert port C */
  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle --protocol tcp  -i %s -j MARK --set-mark 3",gw_ifs.aif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle --protocol tcp  -i %s -j ACCEPT",gw_ifs.aif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle --protocol tcp  -i %s -j MARK --set-mark 3",gw_ifs.bif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle --protocol tcp  -i %s -j ACCEPT",gw_ifs.bif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle --protocol 105  -i %s -j MARK --set-mark 3",gw_ifs.aif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle --protocol 105  -i %s -j ACCEPT",gw_ifs.aif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle --protocol 105  -i %s -j MARK --set-mark 3",gw_ifs.bif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "iptables -A PREROUTING -t mangle --protocol 105  -i %s -j ACCEPT",gw_ifs.bif_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "ip rule add fwmark 1 table 200");
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "ip rule add fwmark 2 table 201");
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "ip rule add fwmark 3 table 202");
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "ip addr add 10.99.99.1 peer 10.99.99.2 dev %s", gw_ifs.aif_tun_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "ip addr add 10.99.98.1 peer 10.99.98.2 dev %s" ,gw_ifs.bif_tun_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "ip addr add 10.99.97.1 peer 10.99.97.2 dev %s" ,gw_ifs.c_tun_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "ip link set dev %s up", gw_ifs.aif_tun_name);
  printf ("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "ip link set dev %s up", gw_ifs.bif_tun_name);
  printf ("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "ip link set dev %s up", gw_ifs.c_tun_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);

  sprintf (iptables_cmd, "ip route add default dev %s table 200", gw_ifs.aif_tun_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "ip route add default dev %s table 201", gw_ifs.bif_tun_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);
  sprintf (iptables_cmd, "ip route add default dev %s table 202", gw_ifs.c_tun_name);
  printf("iptables:: %s\n", iptables_cmd);
  SYSTEM (iptables_cmd);


}

#endif /* TUN_INTERFACE */
#endif /* GATEWAY */
