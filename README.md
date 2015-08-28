# Bro EtherNet/IP Protocol Analyser #
This repository contains the necessary files in order to inspect Ethernet/IP
packets with Bro.

# Installation #
You can download Bro sources at https://www.bro.org/, or by typing:

    $ cd ~
    $ git clone --recursive git://git.bro.org/bro

Then, dowload this Ethernet/IP extension:

    $ cd ~
    $ git clone https://github.com/scy-phy/bro-cip-enip.git

And go to this bro-cip-enip directory:

    $ cd ~/bro-cip-enip

To install this EtherNet/IP Protocol Analyser, you can run:

    $ ./install.sh </path/to/bro/directory>

For this example it would be:

    $ ./install.sh ~/bro

Then, go to your Bro directory and run:

    $ cd ~/bro
    # ./configure && make && make install

# Usage #
You can run Bro with any of your .pcap files containing some Ethernet/IP
traffic with the following command:

    $ bro -r <file.pcap> [<bro-script.bro>]

For instance, if you are in your Bro directory:

    $ cd ~/bro
    $ bro -C -r testing/btest/Traces/enip/enip_metasploit.pcapng scripts/policy/protocols/enip/detect-metasploit.bro

(-C means ignore the TCP checksums)

And then take a look at the .log files and more precisely the enip.log file, and
the notice.log file if you ran bro with a notice script.

You can also inspect live trafic from an interface using Broctl (use the help command):

    # broctl
    # [BroControl] > help

or by typing:

    # bro -i <iface1> -i <iface2> -i <iface3>

See the full documentation at https://www.bro.org/documentation/index.html.

# TODO #
-Add documentation
-Add UDP keep-alive packets (Ethernet-IP1 on port 2222).
-Debug the following issues.

# Known issues #
-Some packets are not parsed.
-The keep-alive packet on port 2222 without header are not parsed.
-There is a out_of_bound: RR_Unit:timeout exception on some packets.
-There is a out_of_bound: Data_Address:len exception on some packets.

## Detecting attacks ##
From http://reversemode.com/downloads/logix_report_basecamp.pdf
     Generic attacks
     	  1: Interface Configuration

     Specific to 1756-ENBT module
     	  4: Dump 1756-ENBT’s module boot code
	  5: Reset 1756-ENBT module
	  6: Crash 1756-ENBT module
	  7: Flash Update
