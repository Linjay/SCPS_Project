#include "scpstp.h"
#include "scpsnp_protos.h"
#include "scps_ip.h"

#ifdef NL_DEFAULT_IPV4
int nl_default = NL_PROTOCOL_IPV4;
#endif /* NL_DEFAULT_IPV4 */

#ifdef NL_DEFAULT_IPV6
int nl_default = NL_PROTOCOL_IPV6;
#endif /* NL_DEFAULT_IPV6 */

#ifdef NL_DEFAULT_NP
int nl_default = NL_PROTOCOL_NP;
#endif /* NL_DEFAULT_NP */

int
nl_ind (rqts_in, max_mtu, offset)
scps_np_rqts *rqts_in;
int max_mtu;
int *offset;

{
    int cc;

    cc = ip_ind (rqts_in, MAX_MTU, offset);

#ifdef IPV6
    if (cc == NL_TRY_IPV6) {
        cc = ipv6_ind (rqts_in, MAX_MTU, offset);
    }
#endif /* IPV6 */

    if (cc == NL_TRY_NP) {
    	cc = scps_np_ind (rqts_in, MAX_MTU, offset);
    }

    return (cc);

}


