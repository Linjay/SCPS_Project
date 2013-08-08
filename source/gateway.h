#ifndef __GATEWAY_H__
#define __GATEWAY_H__

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

#ifdef GATEWAY_SELECT
#define ADD_WRITE(z) \
        { \
          if (!(z->write_parent)) \
             { \
                 ((tp_Socket *) z)->write_next = ((tp_Socket *)(z->thread->write_socks)); \
                if (z->write_next) \
                  ((tp_Socket *) z)->write_next->write_prev = (tp_Socket *) z; \
                ((tp_Socket *) z)->write_prev = (tp_Socket *) 0x0; \
                ((tp_Socket *) z)->thread->write_socks = (tp_Socket *) z; \
                ((tp_Socket *) z)->write_parent = (caddr_t *)&(z->thread->write_socks);\
             } \
        }

#define ADD_READ(z) \
        { \
          if (!(z->read_parent)) \
             { \
                ((tp_Socket *) z)->read_next = ((tp_Socket *)(z->thread->read_socks)); \
                if (z->read_next) \
                  ((tp_Socket *) z)->read_next->read_prev = (tp_Socket *) z; \
                ((tp_Socket *) z)->read_prev = (tp_Socket *) (0x0); \
                ((tp_Socket *) z)->thread->read_socks = ((tp_Socket *) z); \
                ((tp_Socket *) z)->read_parent = (caddr_t *)&(z->thread->read_socks);\
             } \
        }

#define REMOVE_READ(z) \
        { \
          if (z->read_parent) \
           { \
              if (z->read_prev) \
               {\
                  ((tp_Socket *) z)->read_prev->read_next = ((tp_Socket *)z)->read_next; \
               }\
              if (z->read_next) \
                { \
                    ((tp_Socket *) z)->read_next->read_prev = (tp_Socket *)z->read_prev; \
                }\
              if ( ((tp_Socket *) z)->thread->read_socks == (tp_Socket *)z) \
                 { \
                   ((tp_Socket *) z)->thread->read_socks = (tp_Socket *)z->read_next; \
                 } \
               ((tp_Socket *) z)->read_prev = (tp_Socket *) (0x0); \
               ((tp_Socket *) z)->read_next = (tp_Socket *) (0x0); \
               ((tp_Socket *) z)->read_parent = (tp_Socket *)0x0; \
           } \
        }

#define REMOVE_WRITE(z) \
        { \
          if (z->write_parent) \
           { \
              if (z->write_prev) \
               {\
                  ((tp_Socket *) z)->write_prev->write_next = ((tp_Socket *) z)->write_next; \
               }\
              if (z->write_next) \
                { \
                    ((tp_Socket *) z)->write_next->write_prev = ((tp_Socket *) z)->write_prev; \
                }\
              if (((tp_Socket *) z)->thread->write_socks == (tp_Socket *)z) \
                 { \
                   ((tp_Socket *) z)->thread->write_socks = (tp_Socket *)(z->write_next); \
                 } \
              ((tp_Socket *) z)->write_next =  (tp_Socket *)0x0; \
              ((tp_Socket *) z)->write_prev = (tp_Socket *)0x0; \
              ((tp_Socket *) z)->write_parent = (tp_Socket *)0x0; \
           } \
        }
#endif /* GATEWAY_SELECT */

#endif /* __GATEWAY_H__ */
