#!/usr/bin/perl

use 5.010;
use strict;
use warnings;
use Net::Tshark;
use Term::ANSIColor;

while(1){
	# Start the capture process, looking for packets containing HTTP requests and responses
	my $tshark = Net::Tshark->new or die "Could not start TShark";
	$tshark->start(interface => 1, display_filter => 'http', promiscuous => 1);

	# Do some stuff that would trigger HTTP requests/responses for 30 s
	print "\t\t\nCapturing HTTP packets for 10 seconds.";
	for (1 .. 10){
		print '.';
		$| = 1;
		sleep 1;
	}
	say "done.\n";

	# Get any packets captured
	say colored "Stopping capture and reading packet data...",'green';
	$| = 1;
	$tshark->stop;
	my @packets = $tshark->get_packets;

	# Output a report of what was captured
	say "Captured ".(@packets)." HTTP packets:";

	# Extract packet information by accessing each packet like a nested hash
	foreach my $packet (@packets) {
		
		my $src_ip = $packet->{ip}->{src};
		my $dst_ip = $packet->{ip}->{dst};
		
		if ($packet->{http}->{request}){
			
			my $host = $packet->{http}->{host};
			my $method = $packet->{http}->{'http.request.method'};
			#my $usera = $packet->{http}->{'http.request.method'};
			
			print colored "\t - HTTP $method request to $host ",'bold green';
			say colored" src: $src_ip -> dst: $dst_ip",'bold yellow';
		}
		else{
			
			my $code = $packet->{http}->{'http.response.code'};
			print colored "\t - HTTP response: $code",'bold yellow';
			say colored " src: $src_ip -> dst: $dst_ip",'bold green';
		}
	}
}
