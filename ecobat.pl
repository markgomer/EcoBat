#!/usr/bin/perl

use strict;
use warnings;
use Net::PcapUtils;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Data::HexDump;
use Net::Traceroute;

my $fh;
my %ip_count; # Hash to store IP counts
my $i = 0;

sub sniff {
    my ($ip_address) = @_;
    my $log_file = 'pacotes.log';

    open($fh, '>', $log_file) or die "Unable to open log file: $!";

    print "Starting packet capture for IP: $ip_address\n";

    Net::PcapUtils::loop(
        \&process_pkt,
        FILTER => "ip host $ip_address"
    );

    close $fh;

    print "Packet capture completed. Log saved to $log_file.\n";

    # Find the IP with the highest count
    my ($most_common_ip) = (sort { $ip_count{$b} <=> $ip_count{$a} } keys %ip_count)[0];
    my $most_common_ip_count = $ip_count{$most_common_ip} || 0;
    print "Most common IP address: $most_common_ip ($most_common_ip_count requests)\n";

    # Perform traceroute for the most common IP
    my $traceroute_log_file = "$most_common_ip-traceroute.log";
    print "Performing traceroute for $most_common_ip. Log saved to $traceroute_log_file.\n";
    my $tr = Net::Traceroute->new();
    $tr->traceroute(host => $most_common_ip, debug => 0);
    my @trace = $tr->trace;
    open(my $fh_trace, '>', $traceroute_log_file) or die "Unable to open traceroute log file: $!";
    print $fh_trace join("\n", @trace);
    close $fh_trace;
}

sub process_pkt {
    my ($user_data, $hdr, $pkt) = @_;
    my $eth = NetPacket::Ethernet->decode($pkt);
    if ($eth->{type} == 2048) {
        my $ip = NetPacket::IP->decode($eth->{data});
        if ($ip->{proto} == 6) {
            my $tcp = NetPacket::TCP->decode($ip->{data});
            print $fh "\n\n$i $ip->{src_ip}($tcp->{src_port}) -> $ip->{dest_ip}($tcp->{dest_port})\n";
            print $fh HexDump $ip->{data};
            $i++;

            # Track IP addresses
            $ip_count{$ip->{src_ip}}++;
        }
    }
}

sub main {
    my $desenho = '
    ....._      
    `.   ``-.                               .-----.._
    `,     `-.                          .:      /`
        :       `"..                 ..-``       :
        /   ...--:::`n            n.`::...       :
        `:``      .` ::          /  `.     ``---..:.
        `\    .`  ._:   .-:   ::    `.     .-``
            :  :    :_\\_/: :  .::      `.  /
            : /      \\-../:/_.`-`         \ :
            :: _.._  q` p ` /`             \|
            :-`    ``(_. ..-----hh``````/-._:
                        `:      ``     /     `
        [wkm]          :          _/
                        :    _..-``
                        l--``
    ';

    my $title = '

        ___________           __________         __   
        \_   _____/ ____  ____\______   \_____ _/  |_ 
        |    __)__/ ___\/  _ \|    |  _/\__  \\   __\
        |        \  \__(  <_> )    |   \ / __ \|  |  
        /_______  /\___  >____/|______  /(____  /__|  
                \/     \/             \/      \/      

    ';

    print $desenho;
    print $title;

    # Check if an IP address was provided as an argument
    if (@ARGV != 1) {
        die "Usage: $0 <ip_address>\n";
    }

    my $ip_address = $ARGV[0];

    # Basic IP address validation
    unless ($ip_address =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
        die "Invalid IP address format. Please use xxx.xxx.xxx.xxx\n";
    }

    sniff($ip_address);
}

main();
