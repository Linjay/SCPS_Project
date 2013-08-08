#
# ppp_current_tx_len makefile
# $Id: Makefile,v 1.1 2005/10/21 18:41:30 feighery Exp $
#

PPPSTATSRCS = ppp_current_tx_len.c
PPPSTATOBJS = ppp_current_tx_len.o

#CC = gcc
COPTS = -O -g  -Wall
COMPILE_FLAGS = -I../include
LIBS =

INSTALL= install -o root -g daemon

CFLAGS = $(COPTS) $(COMPILE_FLAGS)

all: ppp_current_tx_len

install: ppp_current_tx_len
	-mkdir -p $(MANDIR)/man8
	$(INSTALL) -s -c ppp_current_tx_len $(BINDIR)/ppp_current_tx_len
#	$(INSTALL) -c -m 444 pppstats.8 $(MANDIR)/man8/pppstats.8

ppp_current_tx_len: $(PPPSTATSRCS)
	$(CC) $(CFLAGS) -o ppp_current_tx_len ppp_current_tx_len.c $(LIBS)

clean:
	rm -f ppp_current_tx_len *~ #* core

depend:
	cpp -M $(CFLAGS) $(PPPSTATSRCS) >.depend
#	makedepend $(CFLAGS) $(PPPSTATSRCS)
