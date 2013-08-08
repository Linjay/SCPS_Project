BEGIN {
   seen_gateway = 0;
   seen_gateway_select = 0;
   seen_debug_gateway = 0;
   seen_udp_gateway = 0;
   seen_fairer_gateway = 0;
   seen_select = 0;
   seen_select_debug = 0;

# 0 -- Null
# 1 -- #ifdef
# 2 -- #else (from ifdef)
# 3 -- #ifndef
# 4 -- #else (from ifndef)
# 5 -- #endif 
}

{

	print_line = 1;
	
# First look for #ifdef GATEWAY and remove them

	if ($1 == "#ifdef" && $2 == "GATEWAY" && seen_gateway == 0) {
		print_line = 0;
		seen_gateway = 1
	}
	
	if ($1 == "#else" && seen_gateway == 1 && $3 == "GATEWAY") {
		print_line = 0;
		seen_gateway = 2
	}
	
	if ($1 == "#ifndef" && $2 == "GATEWAY" && seen_gateway == 0) {
		print_line = 0;
		seen_gateway = 3
	}

	if ($1 == "#else" && seen_gateway == 3 && $3 == "GATEWAY") {
		print_line = 0;
		seen_gateway = 4
	}

	if ($1 == "#endif" && $3 == "GATEWAY" && seen_gateway > 0) {
		print_line = 0;
		seen_gateway = 0
	}
	
# First look for #ifdef GATEWAY_SELECT and remove them

	if ($1 == "#ifdef" && $2 == "GATEWAY_SELECT" && seen_gateway_select == 0) {
		print_line = 0;
		seen_gateway_select = 1
	}
	
	if ($1 == "#else" && seen_gateway_select == 1 && $3 == "GATEWAY_SELECT") {
		print_line = 0;
		seen_gateway_select = 2
	}
	
	if ($1 == "#ifndef" && $2 == "GATEWAY_SELECT" && seen_gateway_select == 0) {
		print_line = 0;
		seen_gateway_select = 3
	}

	if ($1 == "#else" && seen_gateway_select == 3 && $3 == "GATEWAY_SELECT") {
		print_line = 0;
		seen_gateway_select = 4
	}

	if ($1 == "#endif" && $3 == "GATEWAY_SELECT" && seen_gateway_select > 0) {
		print_line = 0;
		seen_gateway_select = 0
        }

# First look for #ifdef DEBUG_GATEWAY and remove them

	if ($1 == "#ifdef" && $2 == "DEBUG_GATEWAY" && seen_debug_gateway == 0) {
		print_line = 0;
		seen_debug_gateway = 1
	}
	
	if ($1 == "#else" && seen_debug_gateway == 1 && $3 == "DEBUG_GATEWAY") {
		print_line = 0;
		seen_debug_gateway = 2
	}
	
	if ($1 == "#ifndef" && $2 == "DEBUG_GATEWAY" && seen_debug_gateway == 0) {
		print_line = 0;
		seen_debug_gateway = 3
	}

	if ($1 == "#else" && seen_debug_gateway == 3 && $3 == "DEBUG_GATEWAY") {
		print_line = 0;
		seen_debug_gateway = 4
	}

	if ($1 == "#endif" && $3 == "DEBUG_GATEWAY" && seen_debug_gateway > 0) {
		print_line = 0;
		seen_debug_gateway = 0
        }

# First look for #ifdef ENCAP_DIVERT and remove them

	if ($1 == "#ifdef" && $2 == "ENCAP_DIVERT" && seen_encap_divert == 0) {
		print_line = 0;
		seen_encap_divert = 1
	}
	
	if ($1 == "#else" && seen_encap_divert == 1 && $3 == "ENCAP_DIVERT") {
		print_line = 0;
		seen_encap_divert = 2
	}
	
	if ($1 == "#ifndef" && $2 == "ENCAP_DIVERT" && seen_encap_divert == 0) {
		print_line = 0;
		seen_encap_divert = 3
	}

	if ($1 == "#else" && seen_encap_divert == 3 && $3 == "ENCAP_DIVERT") {
		print_line = 0;
		seen_encap_divert = 4
	}

	if ($1 == "#endif" && $3 == "ENCAP_DIVERT" && seen_encap_divert > 0) {
		print_line = 0;
		seen_encap_divert = 0
        }

# First look for #ifdef ENCAP_DIVERT_DEBUG and remove them

	if ($1 == "#ifdef" && $2 == "ENCAP_DIVERT_DEBUG" && seen_encap_divert_debug == 0) {
		print_line = 0;
		seen_encap_divert_debug = 1
	}
	
	if ($1 == "#else" && seen_encap_divert_debug == 1 && $3 == "ENCAP_DIVERT_DEBUG") {
		print_line = 0;
		seen_encap_divert_debug = 2
	}
	
	if ($1 == "#ifndef" && $2 == "ENCAP_DIVERT_DEBUG" && seen_encap_divert_debug == 0) {
		print_line = 0;
		seen_encap_divert_debug = 3
	}

	if ($1 == "#else" && seen_encap_divert_debug == 3 && $3 == "ENCAP_DIVERT_DEBUG") {
		print_line = 0;
		seen_encap_divert_debug = 4
	}

	if ($1 == "#endif" && $3 == "ENCAP_DIVERT_DEBUG" && seen_encap_divert_debug > 0) {
		print_line = 0;
		seen_encap_divert_debug = 0
        }

# First look for #ifdef UDP_GATEWAY and remove them

	if ($1 == "#ifdef" && $2 == "UDP_GATEWAY" && seen_udp_gateway == 0) {
		print_line = 0;
		seen_udp_gateway = 1
	}
	
	if ($1 == "#else" && seen_udp_gateway == 1 && $3 == "UDP_GATEWAY") {
		print_line = 0;
		seen_udp_gateway = 2
	}
	
	if ($1 == "#ifndef" && $2 == "UDP_GATEWAY" && seen_udp_gateway == 0) {
		print_line = 0;
		seen_udp_gateway = 3
	}

	if ($1 == "#else" && seen_udp_gateway == 3 && $3 == "UDP_GATEWAY") {
		print_line = 0;
		seen_udp_gateway = 4
	}

	if ($1 == "#endif" && $3 == "UDP_GATEWAY" && seen_udp_gateway > 0) {
		print_line = 0;
		seen_udp_gateway = 0
        }

# First look for #ifdef FAIRER_GATEWAY and remove them

	if ($1 == "#ifdef" && $2 == "FAIRER_GATEWAY" && sceen_fairer_gateway == 0) {
		print_line = 0;
		sceen_fairer_gateway = 1
	}
	
	if ($1 == "#else" && sceen_fairer_gateway == 1 && $3 == "FAIRER_GATEWAY") {
		print_line = 0;
		sceen_fairer_gateway = 2
	}
	
	if ($1 == "#ifndef" && $2 == "FAIRER_GATEWAY" && sceen_fairer_gateway == 0) {
		print_line = 0;
		sceen_fairer_gateway = 3
	}

	if ($1 == "#else" && sceen_fairer_gateway == 3 && $3 == "FAIRER_GATEWAY") {
		print_line = 0;
		sceen_fairer_gateway = 4
	}

	if ($1 == "#endif" && $3 == "FAIRER_GATEWAY" && sceen_fairer_gateway > 0) {
		print_line = 0;
		sceen_fairer_gateway = 0
        }

	if (print_line == 0 || ( (seen_gateway == 1 || seen_gateway == 4) ||
            (seen_gateway_select == 1 || seen_gateway_select == 4) || 
            (seen_debug_gateway == 1 || seen_debug_gateway == 4 ) ||
            (seen_encap_divert == 1 || seen_encap_divert == 4 ) || 
            (seen_udp_gateway == 1 || seen_udp_gateway == 4 ) || 
            (seen_fairer_gateway == 1 || seen_fairer_gateway == 4 ) || 
            (seen_encap_divert_debug == 1 || seen_encap_divert_debug == 4) ) ) {
		do_nothing = 1
	} else {
		print $0
	}

}

END {
   a = 1
}
