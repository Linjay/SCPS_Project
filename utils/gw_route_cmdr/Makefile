# This makefile is for the TM driver for the STRV1d Tests

# Debug
SYMTAB = -g -Wall -DLINUX

DEBUG= -DDEBUG 
DEBUG=

all:  gw_route_cmdr

gw_route_cmdr: gw_route_cmdr.o gw_route_add.o gw_route_delete.o gw_route_list.o gw_route_get.o gw_route_modify.o gw_route_link_avail.o gw_route_link_unavail.o gw_route_show.o
	cc gw_route_cmdr.o gw_route_add.o gw_route_delete.o gw_route_list.o gw_route_get.o gw_route_modify.o gw_route_link_avail.o gw_route_link_unavail.o gw_route_show.o -o gw_route_cmdr

gw_route_cmdr.o: gw_route_cmdr.c gw_route_cmdr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c gw_route_cmdr.c -I../../source/ -I../../include/

gw_route_add.o: gw_route_add.c gw_route_cmdr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c gw_route_add.c -I../../source/ -I../../include/

gw_route_delete.o: gw_route_delete.c gw_route_cmdr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c gw_route_delete.c -I../../source/ -I../../include/

gw_route_list.o: gw_route_list.c gw_route_cmdr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c gw_route_list.c -I../../source/ -I../../include/

gw_route_get.o: gw_route_get.c gw_route_cmdr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c gw_route_get.c -I../../source/ -I../../include/

gw_route_show.o: gw_route_show.c gw_route_cmdr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c gw_route_show.c -I../../source/ -I../../include/

gw_route_link_avail.o: gw_route_link_avail.c gw_route_cmdr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c gw_route_link_avail.c -I../../source/ -I../../include/

gw_route_link_unavail.o: gw_route_link_unavail.c gw_route_cmdr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c gw_route_link_unavail.c -I../../source/ -I../../include/

gw_route_modify.o: gw_route_modify.c gw_route_cmdr.h Makefile ../../include/route.h
	cc $(SYMTAB) $(DEBUG) -c gw_route_modify.c -I../../source/ -I../../include/

clean:
	rm -rf *.o *.core gw_route_cmdr
