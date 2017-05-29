#!/usr/bin/perl -wU

use 5.010;
use IO::File;
use Data::Dumper;
use Term::ANSIColor;

my @Tab=();
my $Handle = IO::File->new("hosts.txt", "r") || die $!;

print (colored"\n  [+] ",'bold green');
say "Start to send requests...\n";
while (my $Reading = $Handle->getline()) {
		chomp($Reading);
		my $Current=$Reading;
		print (colored"[-] ",'yellow');
		say "Requesting $Current";
		my $Request='curl --connect-timeout 5 --data @test.txt http://'.$Current.'/xmlrpc.php 2>/dev/null';
		my $ForTab=`$Request`;
		push(@Tab,$ForTab);
		
}
print (colored"\n  [+] ",'bold green');
say "Parsing output to find RPC Pingback response...";

foreach my$Output(@Tab){
	
	say colored"[*] Response found: $Output !",'bold green'
	if ($Output=~/Hello/i);
}
print (colored"\n  [?] ",'bold blue');
say "[-] Hope that you find something...";

=info
test.txt:

	<?xml version="1.0" encoding="iso-8859-1"?>
	<methodCall>
	<methodName>demo.sayHello</methodName>
	<params>
	<param></param>
	</params>
	</methodCall>

=cut