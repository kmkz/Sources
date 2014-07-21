#!/usr/bin/tclsh




#kmkz@kali:~/Desktop# ./testIP.tcl 
#--| Please give-me the IP range to test (example: 192.168.1) |-- 
#192.168.1
#* Discovering hosts for 192.168.1.*
#192.168.1.1
#192.168.1.2
#192.168.1.3
#192.168.1.4
#192.168.1.5
#192.168.1.6



puts -nonewline "--| Please give-me the IP range to test (example: 192.168.1) |-- \n"
flush stdout
set iprange [gets stdin]

puts "* Discovering hosts for $iprange.*\n"

for { set i 1 } { $i < 254 } { incr i } {
	puts "trying $iprange.$i"
	
	# Ios version:
	#if { 
		#[regexp "(!!!)" [exec "ping $iprange.$i timeout 1" ]]
	#}	{

        # Linux version:
	if {
		[regexp "(=)" [exec  "ping $iprange.$i" ]]
	}	{
			puts "$iprange.$i : up!"
		}
		else{
			puts "$iprange.$i : down!"
		}
	}
        # exec ping  "$iprange.$i timeout 1"
       #eval $command
}
