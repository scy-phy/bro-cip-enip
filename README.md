# Bro EtherNet/IP Protocol Analyser #
This repository contains the necessary files in order to inspect Ethernet/IP
packets with Bro.
For the EtherNet/IP documentation, see:

    * THE CIP NETWORKS LIBRARY Volume 1 Edition 3.3 November, 2007: http://www.tud.ttu.ee/im/Kristjan.Sillmann/ISP0051%20Rakenduslik%20Andmeside/CIP%20docs/CIP%20Vol1_3.3.pdf
    * THE CIP NETWORKS LIBRARY Volume 2 Edition 1.4 November 2007: http://www.tud.ttu.ee/im/Kristjan.Sillmann/ISP0051%20Rakenduslik%20Andmeside/CIP%20docs/CIP%20Vol2_1.4.pdf
    * Wireshark dissector: https://github.com/wireshark/wireshark/blob/0808f4c9584b309548996388aafde51820a68932/epan/dissectors/packet-enip.c
      https://github.com/wireshark/wireshark/blob/0808f4c9584b309548996388aafde51820a68932/epan/dissectors/packet-enip.h
    * Programming Manual Logix5000 Data Access: http://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf

# Installation #
You can download Bro sources at https://www.bro.org/, or by typing:

    $ cd ~
    $ git clone --recursive git://git.bro.org/bro

Then, dowload this EtherNet/IP extension:

    $ cd ~
    $ git clone https://github.com/scy-phy/bro-cip-enip.git

And go to this bro-cip-enip directory:

    $ cd ~/bro-cip-enip

To install this EtherNet/IP Protocol Analyser, you can run (please note the ending /):

    $ ./install.sh </path/to/bro/directory/>

For this example it would be (please note the ending /):

    $ ./install.sh ~/bro/

Then, go to your Bro directory and run:

    $ cd ~/bro
    # ./configure && make && make install

The last step is to add the Bro binaries to your PATH environment variable:

    $ export PATH=/usr/local/bro/bin:$PATH

You can also add it to your bashrc file to make it permanent, or use /usr/local/bro/bin directory if you don't want to change your PATH vriable.

## Troubleshooting ##

Before compiling bro, be sure that the ./install.sh script worked well, and the files are copied in the right directory.
You can see the output of this command to be sure:

    $ find ~/bro -name enip

As Libcaf (C++ Actor Framework) is now a requirement to build Bro, you may have some problems during the ./configure command, for instance the libcaf packet missing.
If it is the case you have two solutions:

   * Download and compile libcaf from https://github.com/actor-framework/actor-framework
   * Don't compile the Broker plugin using ./configure --disable-broker as mentioned in http://comments.gmane.org/gmane.comp.security.detection.bro/8473

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

    * Add UDP keep-alive packets (Ethernet-IP1 on port 2222)
    * Debug the following issues

# Known issues #

    * Some packets are not parsed
    * The keep-alive packet on port 2222 without header are not parsed
    * There is a out_of_bound: RR_Unit:timeout exception on some packets
    * There is a out_of_bound: Data_Address:len exception on some packets

## Detecting attacks ##
From http://reversemode.com/downloads/logix_report_basecamp.pdf

    * Interface Configuration

Specific to 1756-ENBT module

    * Dump 1756-ENBT’s module boot code
    * Reset 1756-ENBT module
    * Crash 1756-ENBT module
    * Flash Update
