#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use Net::PcapUtils;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Net::Traceroute;
use IO::File;
use Time::HiRes qw(time alarm);

# Constants for TCP flags
use constant SYN_FLAG => 0x02;
use constant ACK_FLAG => 0x10;

# Initialize variables
my $filename = "IPsForFQDN.txt";
my $log_file = 'pacotes.log';
my $duration = 300;  # Duration in seconds
my $packet_limit = 10000;  # Packet limit
my $scan_threshold = 100;  # Threshold for detecting scans
my $attempt_threshold = 10;  # Threshold for connection attempts
my $ddos_threshold = 1000;  # Threshold for detecting DDoS
my %ip_count;
my %attack_logs;
my $i = 0;
my $start_time;
my $is_running = 1;

$SIG{INT} = \&finish_up;

sub finish_up {
    $is_running = 0;
    print "\nCapture interrupted. Finishing up...\n";
}

sub sniff {
    my ($ip_address) = @_;

    # Open log file for appending
    my $fh = IO::File->new(">> $log_file") or die "Cannot open log file: $!";

    print "\nStarting packet capture for IP: $ip_address\n";
    print "Will capture for $duration seconds or $packet_limit packets, whichever comes first.\n";
    print "Press Ctrl+C to stop capture early.\n";

    $start_time = time;

    eval {
        Net::PcapUtils::loop(sub {
            my ($user_data, $header, $packet) = @_;
            process_pkt($user_data, $header, $packet, $fh);
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
    my ($user_data, $hdr, $pkt, $fh) = @_;
    my $eth = NetPacket::Ethernet->decode($pkt);
    if ($eth->{type} == 2048) {
        my $ip = NetPacket::IP->decode($eth->{data});
        if ($ip->{proto} == 6) {
            my $tcp = NetPacket::TCP->decode($ip->{data});
            print $fh "\n\n$i $ip->{src_ip}($tcp->{src_port}) -> $ip->{dest_ip}($tcp->{dest_port})\n";
            print $fh "Flags: SYN:" . (($tcp->{flags} & SYN_FLAG) ? '1' : '0') . " ACK:" . (($tcp->{flags} & ACK_FLAG) ? '1' : '0') . "\n";
            print $fh "Time: " . localtime(time) . "\n";
            print $fh HexDump($ip->{data});
            $i++;

            $ip_count{$ip->{src_ip}}++;

            # Heuristic analysis
            if ($ip_count{$ip->{src_ip}} > $scan_threshold) {
                print $fh "Warning: Possible port scan from $ip->{src_ip}, detected $ip_count{$ip->{src_ip}} packets.\n";
                $attack_logs{$ip->{src_ip}}{scan}++;
            }
            if ($tcp->{flags} & SYN_FLAG && $ip_count{$ip->{src_ip}} > $attempt_threshold) {
                print $fh "Warning: Possible attack attempt from $ip->{src_ip}, detected $ip_count{$ip->{src_ip}} packets with SYN flag.\n";
                system("iptables -A INPUT -s $ip->{src_ip} -j DROP");
                print $fh "Blocked IP $ip->{src_ip} via iptables\n";
                $attack_logs{$ip->{src_ip}}{brute_force}++;
            }
            if ($ip_count{$ip->{src_ip}} > $ddos_threshold) {
                print $fh "Warning: Possible DDoS attack from $ip->{src_ip}, detected $ip_count{$ip->{src_ip}} packets.\n";
                $attack_logs{$ip->{src_ip}}{ddos}++;
            }
        }
    }
}

sub HexDump {
    my ($data) = @_;
    my $dump = '';
    for (my $i = 0; $i < length($data); $i += 16) {
        my $chunk = substr($data, $i, 16);
        my $hex = unpack('H*', $chunk);
        $hex =~ s/(.{2})/$1 /g;
        my $ascii = $chunk;
        $ascii =~ s/[^ -~]/./g;
        $dump .= sprintf("%04x  %-48s  %s\n", $i, $hex, $ascii);
    }
    return $dump;
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

    print "\nDetailed attack logs:\n";
    foreach my $ip (keys %attack_logs) {
        my $log = $attack_logs{$ip};
        print "IP: $ip\n";
        print "Scan attacks detected: $log->{scan}\n" if $log->{scan};
        print "Brute force attempts detected: $log->{brute_force}\n" if $log->{brute_force};
        print "DDoS attacks detected: $log->{ddos}\n" if $log->{ddos};
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

    print "$title\n";
    print "$desenho\n";
    print "This script monitors network traffic, detects potential attacks, and performs traceroutes.\n";
    print "Usage: $0 <IP address>\n";

    if (@ARGV != 1) {
        die "Usage: $0 <IP address>\n";
    }

    my $ip_address = $ARGV[0];
    sniff($ip_address);
}

main();
