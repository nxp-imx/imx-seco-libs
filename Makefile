CFLAGS ?= -O1 -Werror -fPIC
ARFLAGS ?= rcs
DESTDIR ?= export
BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib
INCLUDEDIR ?= /usr/include
TARGET_FLAVOR ?= linux

ifdef COVERAGE
GCOV_FLAGS=-fprofile-arcs -ftest-coverage
endif
ifeq ($(TARGET_FLAVOR), linux)
LIBS = -lpthread -lz
else ifeq ($(TARGET_FLAVOR), qnx)
LIBS = -lz
else ifeq ($(TARGET_FLAVOR), ghs)
LIBS = -lposix -lzlib -lz
else
$(error Type of OS defined by TARGET_FLAVOR variable is not supported)
endif

# Do not build tests for GHS
ifneq ($(TARGET_FLAVOR), ghs)
all: she_test hsm_test v2x_test she_lib.a seco_nvm_manager.a hsm_lib.a
else
all: she_lib.a seco_nvm_manager.a hsm_lib.a
endif

%.o: src/%.c
	$(CC) $^  -c -o $@ -I include -I include/hsm $(CFLAGS) $(GCOV_FLAGS)

# SHE lib
she_lib.a: she_lib.o seco_utils.o seco_sab_messaging.o seco_os_abs_$(TARGET_FLAVOR).o
	$(AR) $(ARFLAGS) -o $@ $^

# HSM lib
hsm_lib.a: hsm_lib.o seco_utils.o seco_sab_messaging.o seco_os_abs_$(TARGET_FLAVOR).o
	$(AR) $(ARFLAGS) -o $@ $^

# NVM manager lib
seco_nvm_manager.a: seco_nvm_manager.o
	$(AR) $(ARFLAGS) -o $@ $^

#SHE test components
ifdef DEBUG
DEFINES=-DDEBUG
endif
HSM_TEST_OBJ=$(wildcard test/hsm/*.c)
hsm_test: $(HSM_TEST_OBJ) hsm_lib.a seco_nvm_manager.a
	$(CC) $^  -o $@ -I include -I include/hsm $(CFLAGS) $(LIBS) $(DEFINES) $(GCOV_FLAGS)

SHE_TEST_OBJ=$(wildcard test/she/src/*.c)
#SHE test app
she_test: $(SHE_TEST_OBJ) she_lib.a seco_nvm_manager.a
	$(CC) $^  -o $@ -I include $(CFLAGS) $(LIBS) $(DEFINES) $(GCOV_FLAGS)

V2X_TEST_OBJ=$(wildcard test/v2x/*.c)
v2x_test: $(V2X_TEST_OBJ) hsm_lib.a
	$(CC) $^  -o $@ -I include -I include/hsm $(CFLAGS) $(LIBS) $(DEFINES) $(GCOV_FLAGS)

clean:
	rm -rf she_test *.o *.gcno *.a hsm_test v2x_test $(TEST_OBJ) $(DESTDIR)

she_doc: include/she_api.h include/seco_nvm.h
	rm -rf doc/latex/
	doxygen doc/she/Doxyfile
	make -C ./doc/latex pdf
	cp doc/latex/refman.pdf doc/she_api_manual.pdf
	rm -rf doc/latex/

hsm_doc: include/hsm/hsm_api.h
	rm -rf doc/latex/
	doxygen doc/hsm/Doxyfile
	make -C ./doc/latex pdf
	cp doc/latex/refman.pdf doc/hsm_api_document.pdf
	rm -rf doc/latex/

install: hsm_test she_test she_lib.a seco_nvm_manager.a hsm_lib.a
	mkdir -p $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	cp -a seco_nvm_manager.a hsm_lib.a she_lib.a $(DESTDIR)$(LIBDIR)
	cp hsm_test she_test $(DESTDIR)$(BINDIR)
	cp -a include/* $(DESTDIR)$(INCLUDEDIR)

