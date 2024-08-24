#!/bin/bash

# Atualiza o índice de pacotes
sudo apt-get update

# Instala o Perl
sudo apt-get install -y perl

# Instala os módulos Perl necessários via CPAN
cpan Net::PcapUtils
cpan NetPacket::Ethernet
cpan NetPacket::IP
cpan NetPacket::TCP
cpan Data::HexDump
cpan Net::Traceroute

echo "Instalação concluída."
