INSTALL_LOCATION= $(DYANAMO)
PATH_TO_EXECUTABLE= simple_c_example/out.o


DYNAMORIO_HOME= $(INSTALL_LOCATION)
DYNAMORIO_INCLUDE= $(INSTALL_LOCATION)/include
DYNAMORIO_INCLUDE2= $(INSTALL_LOCATION)/ext/include
DYNAMORIO_INCLUDE3= $(INSTALL_LOCATION)/tools/include
DYNAMORIO_INCLUDE4= $(INSTALL_LOCATION)/samples/include
DYNAMORIO_BIN= $(INSTALL_LOCATION)/bin64
DRREG=$(INSTALL_LOCATION)/ext/lib64/release/libdrreg.so $(INSTALL_LOCATION)/ext/lib64/release/libdrreg_static.a $(INSTALL_LOCATION)/ext/lib64/release/libdrreg.so.debug
DRMGR=$(INSTALL_LOCATION)/ext/lib64/release/libdrmgr.so $(INSTALL_LOCATION)/ext/lib64/release/libdrmgr_static.a $(INSTALL_LOCATION)/ext/lib64/release/libdrmgr.so.debug
DRWRAP=$(INSTALL_LOCATION)/ext/lib64/release/libdrwrap.so $(INSTALL_LOCATION)/ext/lib64/release/libdrwrap_static.a $(INSTALL_LOCATION)/ext/lib64/release/libdrwrap.so.debug
DRUTILS=$(INSTALL_LOCATION)/ext/lib64/release/libdrutil.so $(INSTALL_LOCATION)/ext/lib64/release/libdrutil_static.a $(INSTALL_LOCATION)/ext/lib64/release/libdrutil.so.debug
DRUTILS=$(INSTALL_LOCATION)/ext/lib64/release/libdrutil.so $(INSTALL_LOCATION)/ext/lib64/release/libdrutil_static.a $(INSTALL_LOCATION)/ext/lib64/release/libdrutil.so.debug

NSS_INCLUDE310=$(INSTALL_LOCATION)/tutorials/software/nss-3.10/include
NSS_INCLUDE=/usr/include/nss
NSPR_INCLUDE= /usr/include/nspr
TEST_LIB_INCLUDE=simple_c_example/

all:
	g++ -fpermissive -fPIC -shared -lgcc -w -DLINUX -DX86_64 -I$(DYNAMORIO_INCLUDE) -I$(DYNAMORIO_INCLUDE2) -I$(DYNAMORIO_INCLUDE3) -I$(DYNAMORIO_INCLUDE4) -I$(NSPR_INCLUDE) -I$(NSS_INCLUDE) -I$(TEST_LIB_INCLUDE) -o a.out simple_example.c $(DRREG) $(DRMGR) $(DRWRAP) $(DRUTILS) 
run:
	$(DYNAMORIO_HOME)/bin64/drrun -nocheck -verbose -c64 a.out -- $(PATH_TO_EXECUTABLE)