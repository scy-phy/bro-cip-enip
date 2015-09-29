# Bro EtherNet/IP and Common Industrial Protocol Analysers #
This repository contains the necessary files in order to inspect Ethernet/IP and 
Common Industrial Protocol packets with Bro.
For the documentation, see:

    * THE CIP NETWORKS LIBRARY Volume 1 Edition 3.3 November, 2007: http://www.tud.ttu.ee/im/Kristjan.Sillmann/ISP0051%20Rakenduslik%20Andmeside/CIP%20docs/CIP%20Vol1_3.3.pdf
    * THE CIP NETWORKS LIBRARY Volume 2 Edition 1.4 November 2007: http://www.tud.ttu.ee/im/Kristjan.Sillmann/ISP0051%20Rakenduslik%20Andmeside/CIP%20docs/CIP%20Vol2_1.4.pdf
    * Wireshark dissector: https://github.com/wireshark/wireshark/blob/0808f4c9584b309548996388aafde51820a68932/epan/dissectors/packet-enip.c
      https://github.com/wireshark/wireshark/blob/0808f4c9584b309548996388aafde51820a68932/epan/dissectors/packet-enip.h
      https://github.com/wireshark/wireshark/blob/0808f4c9584b309548996388aafde51820a68932/epan/dissectors/packet-cip.c
      https://github.com/wireshark/wireshark/blob/0808f4c9584b309548996388aafde51820a68932/epan/dissectors/packet-cip.h
    * Programming Manual Logix5000 Data Access: http://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf

## Installation ##
### Prerequisites ###
See the full documentation at https://www.bro.org/sphinx/install/install.html#prerequisites.

### Installation from source ###
You can download Bro sources at https://www.bro.org/, or by typing:

    $ cd ~
    $ git clone --recursive git://git.bro.org/bro

Then, download this EtherNet/IP extension:

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

### Troubleshooting ###

Before compiling bro, be sure that the ./install.sh script worked well, and the files are copied in the right directory.
You can see the output of this command to be sure:

    $ find ~/bro -name enip
    $ find ~/bro -name cip

As Libcaf (C++ Actor Framework) is now a requirement to build Bro, you may have some problems during the ./configure command, for instance the libcaf packet missing.
If it is the case you have two solutions:

   * Download and compile libcaf from https://github.com/actor-framework/actor-framework
   * Don't compile the Broker plugin using ./configure --disable-broker as mentioned in http://comments.gmane.org/gmane.comp.security.detection.bro/8473

## Usage ##
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

## TODO EtherNet/IP ##

    * Add UDP keep-alive packets (Ethernet-IP1 on port 2222)
    * Debug the following issues

## Known issues EtherNet/IP ##

    * Some packets are not parsed
    * The keep-alive packet on port 2222 without header are not parsed
    * There is a out_of_bound: RR_Unit:timeout exception on some packets
    * There is a out_of_bound: Data_Address:len exception on some packets
    * The CIP payloads are interpreted as numbers (count) and not as bytes

## TODO CIP ##
For the CIP analyser, there is only the basic code in order to analyse the SWaT
testbed communications.

    * cip-protocol: the enum describe only the services available in the SWaT
      testbed, the segment types (for the path field), the different tag types
      and the errors. The record types describe every kind of packet available
      for these services (see the Logix5000 documentation).
      All the rest is commented and describe other services and packets, from
      the CIP Volume I documentation
    * cip-analyser: this analyser describes the CIP connection and the CIP
      flow types. In the flow type there is 2 functions (cip_message_request and
      proc_cip_message), the second one is the basic one generated by Binpac,
      and the first one is the one parsing all the message requests. This
      function tells Bro when the packet is not from the CIP protocol or when it
      is. Then the two refine lines at the bottom of the file add a field to the
      type Message_Request and CIP_PDU, and call the previous functions to fill
      this field
    * events.bif: there is only the general event cip_event and the event
      cip_message_request, in order to analyse each message request. The
      type of service, the size of the path and the path will be logged
    * main.bro: this script only logs the service, the path size and the path
      when a message request packet is parsed

This code compiles, but can't be executed. The main supposed reason, is that the
payload of the EtherNet/IP is still attached in the ENIP analyser. So this CIP
payload can't be parsed by the CIP analyser. This data is in the Data_Address
record type, in the data field (enip-protocol.pac).

The next tasks to do are:

    * Detach the CIP payload from the ENIP analyzer
    * Continue to write the cip-protocol, cip-analyser and events.bif in
      order to analyse all the CIP packets according to CIP Volume I
    * [Optional] Change main.bro in order to log different information
    * [Optional] Add some policy script in order to detect some CIP attacks

## Detecting attacks ##
From http://reversemode.com/downloads/logix_report_basecamp.pdf

    * Interface Configuration

Specific to 1756-ENBT module

    * Dump 1756-ENBT’s module boot code
    * Reset 1756-ENBT module
    * Crash 1756-ENBT module
    * Flash Update