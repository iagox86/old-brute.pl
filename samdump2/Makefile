# Made by Tristan Willy <twilly@ucsc.edu>

CC=gcc
CPP=g++
COPTS=-O2 -fomit-framepointer
CPPOPTS=-O2 -fomit-framepointer
LIBS=-lssl -ldes -Ldes

INSTALL=/usr/bin/ginstall
INSTALLFLAGS=-o root -g root -s -m 0755
INSTALLFOLDER=/usr/local/bin
OUTPUT=samdump2
INSTALLFILE=${INSTALLFOLDER}/${OUTPUT}

all: des/des samdump2

des/des: 
	cd des && make gcc

samdump2: samdump2.o md5_dgst.o hive.o rc4_skey.o rc4_enc.o
	$(CPP) -o ${OUTPUT} $^ $(LIBS)

clean:
	-rm -f *.o ${OUTPUT}
	cd des && make clean

install:
	${INSTALL} ${INSTALLFLAGS} ${OUTPUT} ${INSTALLFOLDER}

uninstall:
	rm -f ${INSTALLFILE}

