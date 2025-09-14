# NIDS

[![GitHub issues](https://img.shields.io/github/issues/rileyandrsn/NIDS)](https://github.com/rileyandrsn/NIDS/issues)
[![GitHub forks](https://img.shields.io/github/forks/rileyandrsn/NIDS)](https://github.com/rileyandrsn/NIDS/network)


Lightweight network intrusion detection system (NIDS) made as a passion project using C and the libpcap library.

## Usage
The program has 4 commands
```bash
./nids -i <NIC>
./nids -c <HEX>
./nids -f <FILEPATH>
./nids -h / --help
```
# -i Flag
The -i flag is used to indicate you would like to run the program using a network interface card (NIC) to capture live packets, common examples include
- Ethernet
- en0
- Wi-Fi

You can find a list of the available devices you can use by using Wireshark (highly reccomended for using this program as you will read later). Upon installing and opening Wireshark, you are greeted with the list of available NIC devices to choose, and a chart showing their activity. The best option when finding a device to use is the one with at least some network activity.

# -c Flag
The -c flag indicates you would like to feed custom packet information into the program, this was highly used during testing and is an easy option to compare a single packet against common signatures. I integrated this system specifically so you can get packet information easily from wireshark and copy it to the command line to check it. To get specific packet data, you can follow these steps:
1. Open Wireshark and choose a device that has some network activity
2. Start capturing with the blue shark fin button until you at least have one packet captured
3. Right click a specific packet and hover over "copy"
4. Select "as a hex stream" to copy the packets byte data into your clipboard

Upon copying a packets data, you can run the packet against the NIDS by typing "./nids -c " and then pasting the copied hex stream into your command line. Upon pressing enter, you will have an alert appear or log written if you created a rule to detect the packets signature

# -f Flag
During testing, I realized how redundant copy and pasting packet hex streams was for every single packet. Thus, the "-f" flag was born. To use this flag, you first need a packet capture ".pcap" file or packet capture next generation ".pcapng" file. To use Wireshark to acquire such file, you can follow these steps:
1. Open Wireshark and choose a device with network activity
2. Start capture with the start button and allow however many packets to be captured
3. Once happy with the amount of packets captured, stop packet capture with the red square button
4. In the top left of your screen under "File", choose "save as" and save the file to your location of choice

Now that you have a packet capture file, you can use the file designator flag by typing "./nids -f " followed by the ABSOLUTE path of your packet capture file.

# Using Rules
Now that you know all three methods of passing in packets to the program, now it's time to apply rules to do the real signature-based intrusion detecting this program is built for. The rules of this program take inspiration from popular intrusion detection system (IDS) called Snort. To create a rule, you must have the following fields in your rule:

- name - every rule should be named appropriately to it's intention
- action - this program has two built in actions to designate what happens when a rule is matched
    
    - ALERT - every rule with this action will print an alert message to the console
    - LOG - every time your rule is triggered, it will log the alert to the "events.log" file
- msg - this field allows you to specify the appropriate message to be printed/logged when an event occurs

The following fields are technically optional, but reccomended to have a functioning rule

- protocol - This program has 5 built in protocols that are available to be specifically indicated with their respective json format:

    - Transmission Control Protocol (TCP) -- g "protocol": "TCP"
    - User Datagram Protocol (UDP) --  "protocol": "UDP"
    - Internet Control Message Protocol version 6 (ICMPv6) -- "protocol": "ICMP"
    - Address Resolution Protocol (ARP) -- "protocol": "ARP"
    - Any protocol (default) -- "protocol": "ANY"
    
- src_addr - This is the source IPv4 or IPv6 address sending the packet -- default: "src_addr": "ANY"
- src_port - This specifies the port number the source address is sending from -- default: "src_port": "ANY"
- dst_addr - This is the destination IPv4 or IPv6 address that is the designated target of the packet -- default: "dst_addr": "ANY"
- dst_port - This is the port number that the sender intends to deliver the packet to -- default: "dst_port": "ANY"
- flags - These are the TCP flags that can be filtered the same way as using Wireshark. To select a certain flag or combinations of flags, translate the hexadecimal of the flag(s) to decimal -- default: "flags": 255
