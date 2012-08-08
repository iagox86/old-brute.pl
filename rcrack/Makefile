CPPFLAGS=-O3

INSTALL=/usr/bin/ginstall
INSTALLFLAGS=-o root -g root -s -m 0755
INSTALLFOLDER=/usr/local/bin
CHARSETFLAGS=-o root -g root -m 0644
CHARSETFOLDER=/etc/rainbow-charset.txt


all: rtgen rtdump rtsort rcrack

rtgen: Public.o ChainWalkContext.o HashAlgorithm.o HashRoutine.o RainbowTableGenerate.o
	g++ $^ -lssl -O3 -o rtgen

rtdump: Public.o ChainWalkContext.o HashAlgorithm.o HashRoutine.o RainbowTableDump.o 
	g++ $^ -lssl -o rtdump

rtsort: Public.o RainbowTableSort.o
	g++ $^ -o rtsort

rcrack: Public.o ChainWalkContext.o HashAlgorithm.o HashRoutine.o HashSet.o MemoryPool.o ChainWalkSet.o CrackEngine.o RainbowCrack.o
	g++ $^ -lssl -O3 -o rcrack

clean:
	rm -f *.o
	rm -f rtgen rtdump rtsort rcrack

install: all
	${INSTALL} ${INSTALLFLAGS} rtgen ${INSTALLFOLDER}
	${INSTALL} ${INSTALLFLAGS} rtdump ${INSTALLFOLDER}
	${INSTALL} ${INSTALLFLAGS} rtsort ${INSTALLFOLDER}
	${INSTALL} ${INSTALLFLAGS} rcrack ${INSTALLFOLDER}
	${INSTALL} ${CHARSETFLAGS} charset.txt ${CHARSETFOLDER}

uninstall:
	rm -f ${INSTALLFOLDER}/rtgen	
	rm -f ${INSTALLFOLDER}/rtdump
	rm -f ${INSTALLFOLDER}/rtsort
	rm -f ${INSTALLFOLDER}/rcrack
	rm -f ${CHARSETFOLDER}

