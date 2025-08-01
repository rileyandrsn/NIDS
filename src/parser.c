
} else if(pkt.net_hdr.ipv6_hdr.next_hdr == 6){
    printf("\n < ! - - - - - TCP HEADER IPv6 - - - - - ! >\n");
trans_layer_start = 40;
printf(" Trans layer start: %d\n",trans_layer_start);
memcpy(&pkt.trans_hdr.tcp_hdr.src_port,packet + net_layer_start + trans_layer_start, 2);
printf("SRC PORT: %u\n",ntohs(pkt.trans_hdr.tcp_hdr.src_port));
memcpy(&pkt.trans_hdr.tcp_hdr.dst_port,packet + net_layer_start + trans_layer_start + 2, 2);
printf("DST PORT: %u\n",ntohs(pkt.trans_hdr.tcp_hdr.dst_port));
memcpy(&pkt.trans_hdr.tcp_hdr.sequence_num,packet + net_layer_start + trans_layer_start + 4, 4);
printf("Sequence Number (raw): %x\n",ntohl(pkt.trans_hdr.tcp_hdr.sequence_num));
memcpy(&pkt.trans_hdr.tcp_hdr.ack_num,packet + net_layer_start + trans_layer_start + 8, 4); // issue: ntohs only goes up to 16 bits, needed to change to ntohl (32 bits) [fixed]
printf("ACK NUM: %x\n",ntohl(pkt.trans_hdr.tcp_hdr.ack_num));
        memcpy(&pkt.trans_hdr.tcp_hdr.data_offset_reserved,packet + net_layer_start + trans_layer_start + 12, 1);
        printf("Data offset + reserved: %x\n",ntohs(pkt.trans_hdr.tcp_hdr.data_offset_reserved));
        memcpy(&pkt.trans_hdr.tcp_hdr.flags,packet + net_layer_start + trans_layer_start + 13, 1);
        printf("Flags: %x\n",pkt.trans_hdr.tcp_hdr.flags);
        if((pkt.trans_hdr.tcp_hdr.flags & 0x01) == 0x01)printf("-FIN\n");
        if((pkt.trans_hdr.tcp_hdr.flags & 0x02) == 0x02)printf("-SYN\n");
        if((pkt.trans_hdr.tcp_hdr.flags & 0x04) == 0x04)printf("-RESET\n");
        if((pkt.trans_hdr.tcp_hdr.flags & 0x08) == 0x08)printf("-PUSH\n");\
        if((pkt.trans_hdr.tcp_hdr.flags & 0x10) == 0x10)printf("-ACK\n");
        if((pkt.trans_hdr.tcp_hdr.flags & 0x20) == 0x20)printf("-URGENT\n");
        if((pkt.trans_hdr.tcp_hdr.flags & 0x40) == 0x40)printf("-ECE\n");
        if((pkt.trans_hdr.tcp_hdr.flags & 0x80) == 0x80)printf("-CWR\n");
        memcpy(&pkt.trans_hdr.tcp_hdr.window_size,packet + net_layer_start + trans_layer_start + 14, 2);
        printf("\nWindow Size: %u\n",ntohs(pkt.trans_hdr.tcp_hdr.window_size));
        memcpy(&pkt.trans_hdr.tcp_hdr.checksum,packet + net_layer_start + trans_layer_start + 16, 2);
        printf("\n Checksum: %x \n",ntohs(pkt.trans_hdr.tcp_hdr.checksum));
        memcpy(&pkt.trans_hdr.tcp_hdr.urgent_pointer,packet + net_layer_start + trans_layer_start + 18, 2);
        printf("\n Urgent Pointer: %x \n",ntohs(pkt.trans_hdr.tcp_hdr.urgent_pointer));
    } else if(pkt.net_hdr.ipv4_hdr.protocol == 17 || pkt.net_hdr.ipv6_hdr.next_hdr == 17){
        if (pkt.net_hdr.ipv4_hdr.protocol == 17) {
            trans_layer_start = 20;
        } else {
trans_layer_start = 40;
}        
printf("\n < ! - - - - - UDP HEADER - - - - - ! >\n");
memcpy(&pkt.trans_hdr.udp_hdr.src_port, packet + net_layer_start + trans_layer_start, 2);
printf("Source Port: %u\n",ntohs(pkt.trans_hdr.udp_hdr.src_port));
memcpy(&pkt.trans_hdr.udp_hdr.dst_port, packet + net_layer_start + trans_layer_start + 2, 2);
printf("Destination Port: %u\n",ntohs(pkt.trans_hdr.udp_hdr.dst_port));
memcpy(&pkt.trans_hdr.udp_hdr.len, packet + net_layer_start + trans_layer_start + 4, 2);
printf("Length: %u\n",ntohs(pkt.trans_hdr.udp_hdr.len));
memcpy(&pkt.trans_hdr.udp_hdr.checksum, packet + net_layer_start + trans_layer_start + 6, 2);
printf("Checksum: %x\n",ntohs(pkt.trans_hdr.udp_hdr.checksum));
} else if(pkt.net_hdr.ipv6_hdr.next_hdr == 58){
trans_layer_start = 40;
printf("\n < ! - - - - - ICMP HEADER - - - - - ! >\n");
memcpy(&pkt.trans_hdr.icmp_hdr.type,packet+net_layer_start+trans_layer_start, 1);
printf("Type: %u\n",pkt.trans_hdr.icmp_hdr.type);
memcpy(&pkt.trans_hdr.icmp_hdr.code,packet+net_layer_start+trans_layer_start +1, 1);
printf("Code: %u\n",pkt.trans_hdr.icmp_hdr.code);
memcpy(&pkt.trans_hdr.icmp_hdr.checksum,packet+net_layer_start+trans_layer_start +2, 2);
printf("Checksum: %x\n",ntohs(pkt.trans_hdr.icmp_hdr.checksum));
}

//void *payload;
//int payload_len;

return 0;