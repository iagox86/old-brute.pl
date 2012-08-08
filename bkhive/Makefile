CC=g++
CFLAGS=-g -O3
OUTPUT=bkhive

INSTALL=/usr/bin/ginstall
INSTALLFLAGS=-o root -g root -s -m 0755
INSTALLFOLDER=/usr/local/bin
INSTALLFILE=${INSTALLFOLDER}/${OUTPUT}


all: bkhive

bkhive: bkhive.o hive.o
	${CC} ${CFLAGS} -o ${OUTPUT} bkhive.o hive.o

install: all
	${INSTALL} ${INSTALLFLAGS} ${OUTPUT} ${INSTALLFOLDER}

clean:
	rm -f *.o
	rm -f ${OUTPUT}

uninstall:
	rm -f ${INSTALLFILE}

