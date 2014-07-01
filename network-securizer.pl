#!/usr/bin/perl -wU

use 5.010;
use threads;
use Pod::Usage;
use diagnostics;
use Getopt::Long;
use Switch 'Perl6';
use Term::ANSIColor;
use English '-no_match_vars';

use constant TRUE =>(1);
use constant FALSE =>(0);
use constant FILTER =>('/proc/sys/net/ipv4/conf/');


my $result = GetOptions(
			'mode|d=s'  => \my $Mode,
			);
			
pod2usage(1) if(not defined($Mode));
warnings()   if($UID ne (FALSE));

BEGIN:

my $Compt=TRUE;
my $IFACE;

if (-d  FILTER){
    opendir(FILTER_PATH , FILTER) || printf("[-] Ouverture de %s : Impossible ! \012\012",FILTER);
    my @filter_path= readdir (FILTER_PATH)|| say colored(" [NO]\n\n",'bold red');;
    close(FILTER_PATH);                              
    
    # On set les flags a "1" de chaques filtres contre le spoofing IP
    foreach(@filter_path){
        my @f_p=("/rp_filter");
        my @rep=(FILTER);
        
        next if( -e $_);
        my $Setting=print`echo 1 > @rep$_@f_p`;
       
        print("[*] Configuration du filtre $_ $Compt...........");
        say colored(" [OK]", 'bold green');
        $Compt++;
     }
     say colored("[+] Configuration des filtres terminee ($Compt)",'bold blue');
}

if($Mode !~ /nude/i){
    print("\n[*] Configuration niveau kernel...",);
    kernel_settings() || say colored(" [NO]\n\n",'bold red');;
    
    say colored(" [OK]\n",'bold green');
    say colored("[--- Saisir l interface a traiter (wlan0, eth0....) ---]",'yellow');
    say colored("\r\r[Interface]:",'bold yellow');
    $IFACE=<STDIN>;
    chomp($IFACE);
}

    
SWITCH_MODE:
given ($Mode) {
	when(/defensive/i){    
	     say colored("\nConfiguration IPTABLES en mode DEFENSIF!",'bold green');
             iptables_config("defensive","DROP",140);
        }
	when(/offensive/i){     
	    say colored("\nConfiguration IPTABLES en mode OFFENSIF",'bold yellow');
	    iptables_config("offensive","REJECT",50);
	}
	when(/nude/i){     
	    say colored("\nConfiguration IPTABLES en mode NUDE (dangereux)",'bold blue');
	    iptables_flush();
	    say colored("\r\r   Firewall stoppe avec succes... open bar !\n ",'yellow');
	    exit(TRUE);
	}
	default{ 
	    say colored("\r\r WTF??? ",'bold red');
	    exit(FALSE);
	}
}


my $ReloadService=print(`mv iptables_config.sh /etc/init.d/iptables_config.sh
                         mv ip6tables_config.sh /etc/init.d/ip6tables_config.sh 
                         chmod a+x /etc/init.d/iptables_config.sh 
                         chmod a+x /etc/init.d/ip6tables_config.sh 
                         /etc/init.d/iptables_config.sh start
                         /etc/init.d/ip6tables_config.sh start`);
exit(TRUE);



#**************************#
#        Fonctions         #
#**************************#


sub warnings{
    warn (" [-] Exiting : $! \012\012\015");
    kill($PID);
    exit(FALSE);
    my $thread1 = threads->new(\&path_cleaner) || $!;
}

sub path_cleaner{
    # Vide les variables d'environnement
    delete @ENV {qw  (IFS CDPATH ENV BASH_ENV  )   };  
    return(TRUE);
}

sub kernel_settings{
    my $KernelSetting=print(`
                        echo 2 >/proc/sys/kernel/randomize_va_space 
                        echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
                        echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
                        echo 1 > /proc/sys/net/ipv4/conf/all/accept_source_route
                        echo 1 > /proc/sys/net/ipv4/conf/all/accept_redirects
                        echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
                        echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
                        `);
    if($Mode =~ /offensive/i){
        
         my $HardKernelSettings=print(`
                                    echo 1 > /proc/sys/net/ipv4/tcp_syncookies
                                    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
                                    echo 1 > /proc/sys/net/ipv4/conf/default/accept_redirects
                                    echo 1 > /proc/sys/net/ipv4/conf/lo/accept_redirects
         `);
         
    }

    my $modules_iptables = threads->new(\&iptables_modules) || $!;
    return(TRUE);
}

sub iptables_modules{
    
system<<EOF ;
modprobe ipt_tcpmss
modprobe iptable_nat
modprobe ip_conntrack
modprobe iptable_filter
modprobe iptable_mangle
modprobe ipt_LOG
modprobe ipt_limit
modprobe ipt_state
EOF

return(TRUE);
}


sub iptables_config{

    my @ModeValues=@_;
    
    my $Mode =$ModeValues[0]; # mode choisi
    my $Todo =$ModeValues[1]; # DROP / REJECT
    my $Burst=$ModeValues[2]; # Burst-limit  

    unless(open(IPTABLES_CONF ,"> iptables_config.sh")){
        warn("[-] $! \012\015");
        exit(FALSE);
}

print IPTABLES_CONF <<EOF;
#!/bin/bash -e

### BEGIN INIT INFO
# Provides:          iptables_config : $Mode
# Required-Start:    $IFACE
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Lightweight network security system
# Description:       Security system that will
#                    analyse traffic from the network cards and will
#                    match against a set of known attacks.
### END INIT INFO


iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F


###############################################################
#    Partie a decommenter si les chaines ont deja ete crees   #
###############################################################

# iptables -X UDP_INPUT
# iptables -X TCP_INPUT
# iptables -X UDP_OUTPUT
# iptables -X TCP_OUTPUT
# iptables -X ICMP
# iptables -X ALLOWED_INPUT

# iptables -X SYN_FLOOD
# iptables -X Attacks
# iptables -X FRAG_Attacks
# iptables -X BlackList

###############################################################
#               Creation de nouvelles chaines                 #
###############################################################
 
iptables -N ALLOWED_INPUT
iptables -N TCP_INPUT
iptables -N UDP_INPUT
iptables -N TCP_OUTPUT
iptables -N UDP_OUTPUT
iptables -N ICMP


iptables -N Attacks
iptables -N SYN_FLOOD
iptables -N FRAG_Attacks
iptables -N BlackList

# Politiques par defaut
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP


# Autoriser la boucle locale  
iptables -t filter -A INPUT  -p ALL -s 127.0.0.1 -i lo -m state --state ESTABLISHED,NEW,RELATED  -j ACCEPT
iptables -t filter -A OUTPUT -p ALL -d 127.0.0.1 -o lo -m state --state ESTABLISHED,NEW,RELATED  -j ACCEPT

################################
# Trafic autorisé pour le  LAN #
#       si mode routeur        #
################################
# ID réseau a modifier au besoin (si routeur)

##iptables -t filter -A FORWARD -i $IFACE:1 -s 10.11.12.0/29  -j ACCEPT
##iptables -t filter -A FORWARD -i $IFACE:1 -d 0.0.0.0/0 -m state --state ESTABLISHED,NEW -j ACCEPT

# Envoi des paquets dans leurs chaines de traitements pour les connections entrantes
iptables -A INPUT 		-i $IFACE					-j BlackList
iptables -A INPUT -p ALL 	-i $IFACE -m state --state ESTABLISHED,RELATED 	-j ACCEPT
iptables -A INPUT 		-i $IFACE					-j Attacks
iptables -A INPUT -p TCP 	-i $IFACE 					-j TCP_INPUT
iptables -A INPUT -p UDP 	-i $IFACE 					-j UDP_INPUT
iptables -A INPUT -p ICMP 	-i $IFACE					-j ICMP


############################################
# 	DISPATCH DANS LES CHAINES OUTPUT
############################################
# Envoi des paquets dans leurs chaines de traitements pour les connections sortantes
iptables -A OUTPUT 		-o $IFACE					-j ACCEPT
iptables -A OUTPUT -p ALL 	-o $IFACE -m state --state ESTABLISHED,RELATED 	-j ACCEPT
iptables -A OUTPUT 		-o $IFACE					-j ACCEPT
iptables -A OUTPUT -p TCP 	-o $IFACE 					-j ACCEPT
iptables -A OUTPUT -p UDP 	-o $IFACE					-j ACCEPT 
iptables -A OUTPUT -p ICMP 	-o $IFACE 					-j ACCEPT

iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A ALLOWED_INPUT -p TCP --syn 			-j ACCEPT
iptables -A ALLOWED_INPUT -p TCP -m state --state ESTABLISHED,RELATED 	-j ACCEPT
iptables -A ALLOWED_INPUT -p UDP 					-j ACCEPT
iptables -A INPUT  -m state --state RELATED,ESTABLISHED                 -j ACCEPT

# ouverture de service si besoin ... (HTTP, SSH, DNS)
#iptables -A TCP_INPUT -p TCP -s 0/0 --dport 80  -j ALLOWED_INPUT
#iptables -A TCP_OUTPUT -p TCP --dport 80 	-j ACCEPT
#iptables -A TCP_OUTPUT -p TCP --dport 22 	-j ACCEPT
#iptables -A UDP_OUTPUT -p UDP --dport 53        -j ACCEPT

#iptables -A INPUT -s off -j ACCEPT
#iptables -A INPUT -d off -j ACCEPT

#####################
# Scans protections #
#####################

iptables -N rate_limit
iptables -F rate_limit
iptables -A rate_limit -p tcp  -m limit --limit 3/min --limit-burst 3 -j ACCEPT
iptables -A rate_limit -p udp  -m limit --limit 3/min --limit-burst 3 -j ACCEPT
iptables -A rate_limit -p tcp  -j REJECT --reject-with tcp-reset
iptables -A rate_limit -p udp  -j REJECT --reject-with icmp-port-unreachable

# En cas de scan icmp ...
iptables -A rate_limit -p icmp -j $Todo --reject-with icmp-host-unreachable 

# Autres
iptables -A rate_limit -j DROP

##################################################
# 	Protection contre attaques de Base       #
##################################################

# Global Attack Call
iptables -A Attacks -j SYN_FLOOD
iptables -A Attacks -j FRAG_Attacks
iptables -A Attacks -j RETURN

# Smurf attack / Ping flood
iptables -A INPUT -i $IFACE -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT
iptables -A INPUT -i $IFACE -p icmp --icmp-type echo-reply   -m limit --limit 1/second -j ACCEPT
 
# Syn Flood
iptables -A SYN_FLOOD -m limit --limit 80/second --limit-burst $Burst -j RETURN
iptables -A SYN_FLOOD -j DROP

# Fragment Attacks **** 1.Classics Frag - 2. XMAS - 3. Null Packets
iptables -A FRAG_Attacks -f 				-j $Todo
iptables -A FRAG_Attacks -p tcp --tcp-flags ALL ALL 	-j $Todo   # 1
iptables -A FRAG_Attacks -p tcp --tcp-flags ALL NONE 	-j $Todo   # 2
iptables -A FRAG_Attacks 				-j RETURN # 3

# CHAINE LogAndDrop Syn Flood
iptables -N LogAndDropSynFlood 	-j LOG --log-level 4 	--log-prefix '*** SYNFLOOD ATTACK *** '
iptables -N LogAndDropSynFlood 	-j $Todo

# CHAINE LogAndDrop Frag Attacks
iptables -N LogAndDropFrag 		-j LOG --log-level 4 	--log-prefix '*** Frag ATTACK *** '
iptables -N LogAndDropFrag 		-j $Todo

# CHAINE LogAndDrop XMAS
iptables -N LogAndDropFragMas 		-j LOG --log-level 4 	--log-prefix '*** XMAS ATTACK *** '
iptables -N LogAndDropFragMas 		-j $Todo

# CHAINE LogAndDrop Null Packet
iptables -N LogAndDropFragNull 	-j LOG --log-level 4 	--log-prefix '*** NULL ATTACK *** '
iptables -N LogAndDropFragNull 	-j $Todo 

EOF

print colored("\nConfiguration IPV6 ...",'bold blue');
ip6tables_conf($Mode,$Todo,$Burst) || say colored(" [NO]\n\n",'bold red');
say colored(" [OK]\n\n",'bold green');

close(IPTABLES_CONF);
return(TRUE);
}

sub iptables_flush{

    unless(open(IPTABLES_FLUSH ,"> iptables_flush.sh")){
        warn("[-] $! \012\015");
        exit(FALSE);
}
print`rm /etc/init.d/iptables_config.sh`;

print IPTABLES_FLUSH <<EOF;
#!/bin/bash -e
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# IPV6
ip6tables -F
ip6tables -X

EOF

my $ReloadService=print(`chmod a+x iptables_flush.sh
                         bash iptables_flush.sh`);
close(IPTABLES_FLUSH);
return(TRUE);
}

sub ip6tables_conf{

    my @ModeValues=@_;
    
    my $Mode =$ModeValues[0]; # mode choisi
    my $Todo =$ModeValues[1]; # DROP / REJECT
    my $Burst=$ModeValues[2]; # Burst-limit  
    
    unless(open(IP6TABLES_CONF ,"> ip6tables_config.sh")){
        warn("[-] $! \012\015");
        exit(FALSE);
}


print IP6TABLES_CONF <<EOF;
#!/bin/bash -e

### BEGIN INIT INFO
# Provides:          ip6tables_config : $Mode
# Required-Start:    $IFACE
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Lightweight network security system
# Description:       Security system that will
#                    analyse traffic from the network cards and will
#                    match against a set of known attacks based on IPV6
### END INIT INFO

# Politique par défaut
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP

# Autoriser la boucle locale et l interface (statefull)
ip6tables -A INPUT -t filter -p ALL -s 0/0  -d 0/0 -i lo -m state --state ESTABLISHED,NEW,RELATED  -j ACCEPT
ip6tables -A INPUT -i $IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT

# Traitement ICMPV6
ip6tables -A INPUT -i $IFACE -p icmpv6 --icmpv6-type echo-request -j $Todo

# DROP en INPUT TCP et UDP (la chaine FORWARD au cas ou ...)
ip6tables -I INPUT -i $IFACE -p tcp --syn -j DROP
ip6tables -I FORWARD -i $IFACE -p tcp --syn -j $Todo 

ip6tables -I INPUT -i $IFACE -p udp ! --dport 32768:60999 -j DROP 
ip6tables -I FORWARD -i $IFACE -p udp ! --dport 32768:60999 -j $Todo

# Autres
ip6tables -A INPUT -p ALL -i $IFACE -j $Todo --reject-with icmp6-adm-prohibited

EOF

close(IP6TABLES_CONF);
return(TRUE);
}

	
=info

[1] Description:

Tool developed for IPTABLES/IP6TABLES configurations generation.
This Version permit to protect you from many network attacks
and / or scans.
	
	
[2] Parameters / Options:

This tool require only one required parameter.

	-mode: select which mode you want to configure IPTABLES for (not case sensitive)
	
            .Defensive: configure IPTABLES to be carefull, apply DROP rules on DoS/DDoS, it protect you as well as possible.
            .Offensive: configure IPTABLES to be agressive and apply REJECT rules on DoS/DDoS, so it protect you too ;) 
            .Nude: flush all IPTABLES rules ! 
	
		
Note: there is no default value!

		
[3] Example:

./Securize.pl --mode=offensive 


[4] Securizer todo list:	

	- Build a dynamic configuration (adapted configuration to received packets)
	- Add "parano" mode 
        - Add an port-knocking functionality
	- Add others services configurations (SNORT, Fail2ban...)
        - Optimizations ??

[5] Contact (to whip me \o/):
	
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

