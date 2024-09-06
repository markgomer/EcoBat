# EcoBat - Network Packet Capture Tool

## Purpose
EcoBat is a Perl script designed to capture network packets and identify potential attacks by analyzing traffic patterns. It captures packets on a specified IP address and logs the packet details. Additionally, it performs a traceroute to the IP address that generates the most traffic, providing insight into the network path taken by the packets.

## Prerequisites
- Perl installed on your system.
- Required Perl modules: `Net::PcapUtils`, `NetPacket::Ethernet`, `NetPacket::IP`, `NetPacket::TCP`, `Data::HexDump`, `Net::Traceroute`.

## Usage
1. Clone the repository to your local machine:

```bash
git clone <repository-url>
```

2. Navigate to the directory containing the script:

```bash
cd EcoBat
```

3. Ensure that Perl and the required Perl modules are installed on your system. If not, install them using your system's package manager or CPAN:

```bash
cpanm --installdeps .
```

4. Modify the script to specify the target IP address you want to monitor. You can change the value of the `$ip_address` variable in the `main()` function.

5. Run the script:

```bash
./ecobat.pl <ip_address>
```

Example:
```bash
./ecobat.pl 192.168.0.1
```

6. The script will start capturing packets on the specified IP address. It will log packet details to `pacotes.log` and perform a traceroute to the IP address that generates the most traffic, saving the result to a log file named `<most_common_ip>-traceroute.log`.

7. To stop the script, press `Ctrl+C`.

## Example
Suppose you want to monitor traffic on your local network to identify potential attacks. You can specify your local IP address as the target IP in the script. After running the script, it will capture packets on your local network, log packet details, and perform a traceroute to the IP address that generates the most traffic. This information can help you identify suspicious activity and take appropriate measures to mitigate potential threats.

## Disclaimer
This script is provided for educational purposes only. It should be used responsibly and ethically. The authors are not responsible for any misuse of this tool.

