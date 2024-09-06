#!/usr/bin/perl

use strict;
use warnings;
use Net::PcapUtils;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Data::HexDump;
use Net::Traceroute;
use Time::HiRes qw(time alarm);

my $fh;
my %ip_count;
my $i = 0;
my $start_time;
my $duration = 300;  # Set duration to 5 minutes (300 seconds)
my $packet_limit = 10000;  # Set a limit of 10,000 packets
my $is_running = 1;
my $log_file = 'pacotes.log';

$SIG{INT} = \&finish_up;


sub finish_up {
    $is_running = 0;
    print "\nCapture interrupted. Finishing up...\n";
}


sub sniff {
    my ($ip_address) = @_;

    open($fh, '>', $log_file) or die "Unable to open log file: $!";

    print "\nStarting packet capture for IP: $ip_address\n";
    print "Will capture for $duration seconds or $packet_limit packets, whichever comes first.\n";
    print "Press Ctrl+C to stop capture early.\n";

    $start_time = time;

    eval {
        Net::PcapUtils::loop(sub {
            my ($user_data, $header, $packet) = @_;
            process_pkt($user_data, $header, $packet);
            if (!$is_running || $i >= $packet_limit || (time - $start_time) >= $duration) {
                die "LoopBreak\n";
            }
        }, FILTER => "ip host $ip_address");
    };
    if ($@ && $@ ne "LoopBreak\n") {
        warn "Error during packet capture: $@";
    }

    close $fh;

    print "Packet capture completed. Log saved to $log_file.\n";

    analyze_results($ip_address);
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

            $ip_count{$ip->{src_ip}}++;
        }
    }
}


sub analyze_results {
    my ($target_ip) = @_;

    if (keys %ip_count == 0) {
        print "No packets were captured. Skipping analysis and traceroute.\n";
        return;
    }

    my @sorted_ips = sort { $ip_count{$b} <=> $ip_count{$a} } keys %ip_count;
    my $most_common_ip = $sorted_ips[0];
    my $most_common_ip_count = $ip_count{$most_common_ip};
    print "Most common IP address: $most_common_ip ($most_common_ip_count packets)\n";

    my $ip_to_trace;
    if ($most_common_ip eq $target_ip) {
        if (@sorted_ips > 1) {
            $ip_to_trace = $sorted_ips[1];
            my $second_most_common_count = $ip_count{$ip_to_trace};
            print "Second most common IP address: $ip_to_trace ($second_most_common_count packets)\n";
        } else {
            print "No other IPs found besides the target IP. Skipping traceroute.\n";
            $ip_to_trace = undef;
        }
    } else {
        $ip_to_trace = $most_common_ip;
    }

    if ($ip_to_trace) {
        my $traceroute_log_file = "$ip_to_trace-traceroute.log";
        print "Performing traceroute for $ip_to_trace.\n";

        eval {
            my $tr = Net::Traceroute->new(host => $ip_to_trace, debug => 0);
            $tr->traceroute();
            my @trace;
            for my $hop (1 .. $tr->hops) {
                if ($tr->hop_queries($hop)) {
                    for my $query (0 .. $tr->hop_queries($hop) - 1) {
                        my $host = $tr->hop_query_host($hop, $query);
                        push @trace, $host if $host;
                    }
                }
            }

            open(my $fh_trace, '>', $traceroute_log_file) or die "Unable to open traceroute log file: $!";
            if (@trace) {
                print $fh_trace join("\n", @trace);
                print "Log saved to $traceroute_log_file.\n";
            } else {
                print $fh_trace "No traceroute results available.\n";
            }
            close $fh_trace;
        };
        if ($@) {
            warn "Error during traceroute: $@";
            print "Traceroute failed. Please check your network connection and permissions.\n";
        }
    }

    print "Total packets captured: $i\n";
    print "Capture duration: ", time - $start_time, " seconds\n";

    print "\nTop most common IPs:\n";
    my $count = 0;
    foreach my $ip (@sorted_ips) {
        print "$ip: $ip_count{$ip} packets\n";
        $count++;
        last if $count == 5 or $count == scalar(@sorted_ips);
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

    unless ($ip_address =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
        die "Invalid IP address format. Please use xxx.xxx.xxx.xxx\n";
    }

    sniff($ip_address);
}

main();
