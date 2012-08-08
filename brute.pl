#!/usr/bin/perl -w

use strict; 

use Getopt::Std; # hopefully these are standard :)

my %args;
getopts("hs:k:p:r:", \%args);

# Get the needed paths
my $bkhive = `which bkhive 2> /dev/null`;
chomp($bkhive);
my $samdump2 = `which samdump2 2> /dev/null`;
chomp($samdump2);
my $rcrack = `which rcrack 2> /dev/null`;
chomp($rcrack);

if(!defined($bkhive))
{
	print "Unable to locate the program 'bkhive'.  Please make sure\n";
	print "it's installed.\n";
	print "\n";
	exit 1;
}
print "bkhive found: $bkhive\n";

if(!defined($samdump2))
{
	print "Unable to locate the program 'samdump2'.  Please make sure\n";
	print "it's installed.\n";
	print "\n";
	exit 1;
}
print "samdump2 found: $samdump2\n";

if(!defined($rcrack))
{
	print "Unable to locate the program 'rcrack'.  Please make sure\n";
	print "it's installed.\n";
	print "\n";
	exit 1;
}
print "rcrack found: $rcrack\n";

# If they used -h, give them help
&usage() if(defined($args{'h'}));
# If they tried to use -s and -p, complain
&usage() if(defined($args{'s'}) && defined($args{'p'}));
# If they used -s but didn't use -p
&usage() if(defined($args{'s'}) && !defined($args{'k'}));
# If they failed to give the rainbow tables, complain
&usage() if(!defined($args{'r'}));

my $sampath = "/mnt/windows/windows/repair/sam";
my $keypath = "/mnt/windows/windows/repair/system";
my $tables = $args{'r'};

if(defined($args{'s'}))
{
	$sampath = $args{'s'};
	$keypath = $args{'k'};
}
elsif(defined($args{'p'}))
{
	$sampath = $args{'p'} . "/windows/repair/sam";
	$keypath = $args{'k'} . "/windows/repair/system";
}

# Use bkhive to generate the system key. 
# Pipe that into samdump2 which generates a pwdump file.
# Save the pwdump file.
my $output = "/tmp/pwdump-$$";
unlink($output);

print "Running '$bkhive $keypath - | $samdump2 $sampath - > $output'";
if(system("$bkhive $keypath - | $samdump2 $sampath - > $output"))
{
	print "$output successfully generated!  Attempting RainbowCrack\n";
	system("$rcrack $tables -f $output");
}
else
{
	print "Sorry, something failed.  Please try to fix the problem and restart this.\n";
	print "You might want to delete the file '$output' (or you can use it directly.\n";
	exit 1;
}

exit 0;


sub usage
{
	print "Usage: $0 -s samfile -k systemkey -r tablefiles\n";
	print "   or: $0 -p /path/to/windows -r tablefiles\n";
	print "\n";
	print "If you have the SAM and SYSTEM files, use -s and -k to specify them.\n";
	print "If you have a windows partition mounted, then use -p to give the path\n";
	print "to it.  If no parameters are specified, /mnt/windows will be assumed.\n";
	print "\n";
	print "-s samfile - Use a specific SAM file pulled from Windows\n";
	print "    C:\\windows\\repair\\SAM\n";
	print "-k systemkey - Use a specific system key file, pulled from Windows\n";
	print "    C:\\windows\\repair\\SYSTEM\n";
	print "-r tablefiles - This is the path where the .rt files are stored\n";
	print "\n";
	exit 0;
}

