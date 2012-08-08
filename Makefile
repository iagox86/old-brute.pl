
FILE=brute.pl

INSTALL=/usr/bin/ginstall
INSTALLFLAGS=-o root -g root -m 0755
INSTALLFOLDER=/usr/local/bin


all: 
	cd bkhive; make
	cd rcrack; make
	cd samdump2; make

install: all
	cd bkhive; make install
	cd rcrack; make install
	cd samdump2; make install
	${INSTALL} ${INSTALLFLAGS} ${FILE} ${INSTALLFOLDER}

clean:
	cd bkhive; make clean
	cd rcrack; make clean
	cd samdump2; make clean

uninstall:
	cd bkhive; make uninstall
	cd rcrack; make uninstall
	cd samdump2; make uninstall
	rm -f ${INSTALLFOLDER}/${FILE}

