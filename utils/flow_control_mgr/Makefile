# This makefile is for the TM driver for the STRV1d Tests

# Debug
SYMTAB = -g -Wall -DLINUX

DEBUG= -DDEBUG 
DEBUG=

all:  flow_control_mgr

flow_control_mgr: flow_control_mgr.o socket_udp.o version.o
	cc flow_control_mgr.o socket_udp.o version.o -o flow_control_mgr


flow_control_mgr.o: flow_control_mgr.c flow_control_mgr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c flow_control_mgr.c -I../../source/ -I../../include/

socket_udp.o: socket_udp.c flow_control_mgr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c socket_udp.c -I../../source/ -I../../include/

version.o: version.c flow_control_mgr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c version.c -I../../source/ -I../../include/

clean:
	rm -rf *.o *.core gw_route_cmdr
