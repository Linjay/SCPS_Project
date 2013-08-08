#
#  Top-level Make file
#
SHELL=/bin/sh
BUILDDIRS=source apps FP bin lib

all clean distclean:: FRC
	list='$(BUILDDIRS)';for dir in $$list; do \
	  (cd $$dir; pwd; \
	    eval "make -k $@";); \
	  done

status:
	cvs status -v . | egrep Status | egrep -v "Up-to-date"

crcchk scpsdiff:: FRC
	cd FP; pwd; eval "make $@";

sfp server:: FRC
	cd source; pwd; eval "make"; \
	cd ../FP; pwd; eval "make $@";

scps_ttcp scps_init scps_resp:: FRC
	cd source; pwd; eval "make"; \
	cd ../apps; pwd; eval "make $@";


FRC:
