#!/usr/bin/perl -U

use 5.010;
use IO::File;
use warnings;
use Data::Dumper;
use Net::OpenSSH;
use strict 'vars';
use Term::ANSIColor;    

BEGIN:

my $Pass;
my @File =("signatures.cgi" , "Launcher.pl");
my $Path="/var/www/html/";

# Using password:
my $PasswdFile = IO::File->new("passwd.txt",'r') || die $!;

foreach my $File(@File){
	
	print "\nUpdating $Path with $File file ...";
	while (my $Reading = $PasswdFile->getline()) {
		chomp($Reading);
		$Pass=$Reading;
	}
			
			    
	my $ssh = Net::OpenSSH->new(
		'10.29.20.2',
		 user => 'kmkz',
		 password => $Pass,
		 strict_mode => 0, 
		 ctl_dir => "/tmp/.libnet-openssh-perl",
		 );
	 

	
	$ssh->scp_put({glob => 1},$File,$Path )
		or die colored "scp failed: " . $ssh->error,'bold red';
	
	print colored("[OK]\n",'bold green');
}
say "\n[+] Repository is now up to date !\n";


__END__
