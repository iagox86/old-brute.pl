/*  Bkhive 
	Extract Syskey bootkey from the system hive file

	DISCLAIMER:
	Bkhive is  free  software, so you are free to copy, distribute, use
	the work under the following condition

	You must give the original author credit.
	You may not use this work for commercial purposes.

	I'm in NO WAY responsible for any damage the program does.
	This program is distributed in the hope that it will be useful, but
	WITHOUT  ANY  WARRANTY,  express  or  implied.  There is no implied
	warranty  of  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE !
	Using it is at your own risk !

	Any of these conditions can be waived if you get permission from the author.

	Nicola Cuomo - ncuomo@studenti.unina.it
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hive.h"

int main( int argc, char **argv )
{
	FILE *f;

	/* hive */
	struct hive h;
	nk_hdr *n = NULL;
	unsigned char *b;

	int i, j;

	char *kn[] = { "JD", "Skew1", "GBG", "Data" };
	char kv[9];
	char *keyname;
	char reglsa[] = "$$$PROTO.HIV\\ControlSet001\\Control\\Lsa\\";
	// System\ControlSet001\Control\Lsa\ on some nt4 box
	

	unsigned char key[0x10];
	unsigned char pkey[0x10];

	// int p[] = { 0x7, 0x3, 0xa, 0x8, 0xf, 0x9, 0x1, 0x2,0x4, 0xd, 0x5, 0x0, 0xe, 0xc, 0x6, 0xb };
	int p[] = { 0xb, 0x6, 0x7, 0x1, 0x8, 0xa, 0xe, 0x0,0x3, 0x5, 0x2, 0xf, 0xd, 0x9, 0xc, 0x4 };

	// fprintf(stderr, "Bkhive ncuomo@studenti.unina.it\n\n" );

	if(argc != 3)
	{
		fprintf(stderr, "Usage: %s systemhive [keyfile]\n", argv[0] );
		fprintf(stderr, " (specify '-' to output to stdout)\n\n"); 
		return -1;
	}


	/* Initialize hive access */
	_InitHive( &h );

	/* Open the system hive file */
	if( _RegOpenHive( argv[1], &h ) )
	{
		fprintf(stderr, "Error opening hive file %s\n", argv[1] );
		return -1;
	}
	
	/* foreach keys */
	for( i = 0; i < 4; i++ )
	{
		keyname = (char *) malloc( strlen( reglsa ) + strlen( kn[i] ) + 1 );

		sprintf( keyname, "%s%s", reglsa, kn[i] );

		/* Access lsa subkey */
		if( _RegOpenKey( &h, keyname, &n ) )
		{
			_RegCloseHive( &h );

			fprintf(stderr, "Error accessing key %s\nWrong/corrupted hive??\n", kn[i] );
			return -1;
		}
	
		/* Access the data */
		b = read_data( &h, n->classname_off + 0x1000 );

		// wcstombs( kv, (const wchar_t*)b, n->classname_len );
		// Quick hack for unicode -> ascii translation
		for( j = 0; j < n->classname_len; j++)
			kv[j] = b[j*2];
		kv[8] = 0;

		sscanf( kv, "%x", (int*) ( &key[i*4] ) );

		free( keyname );
	}

	_RegCloseHive( &h );

	/* Print the boot key */
	//fprintf(stderr, "Bootkey: " );

	for( i = 0; i < 0x10; i++ )
	{
		/* Permute the class name */
		pkey[i] = key[p[i]];
		//fprintf(stderr, "%.2x", pkey[i] );
	}
	
	//fprintf(stderr,  "\n" );

	/* write the syskey bootkey to file */
	if(strcmp(argv[2], "-") == 0)
	{
		f = stdout;
		//fprintf(stderr, "Writing key to stdout\n");
	}
	else
	{
		f = fopen(argv[2], "wb");
		//fprintf(stderr, "Writing key to file: %s", argv[2]);
	}

	if( f == NULL )
	{
		fprintf(stderr, "error writing to output file\n" );
	}
	else
	{
		fwrite( pkey, 1, 16, f );
		fclose( f );
	}

	return 0;
}
