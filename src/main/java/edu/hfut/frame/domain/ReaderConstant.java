package edu.hfut.frame.domain;

/**
 * Frame 解析相关常量
 * @author donglei
 * @date: 2016年4月26日 下午9:30:10
 */
public class ReaderConstant {

	public static final int HTTP_PORT = 80;
	public static final int FTP_CTRL_PORT = 21;
	public static final int FTP_DATA_PORT = 20;
	public static final int SMTP_PORT = 25;
	public static final int POP3_PORT = 110;
	public static final int IMAP_PORT = 143;

	public static final long MAGIC_NUMBER = 0xA1B2C3D4;
	public static final int PCAP_HEADER_SIZE = 24;
	public static final int PCAP_HEADER_SNAPLEN_OFFSET = 16;
	public static final int PCAP_HEADER_LINKTYPE_OFFSET = 20;
	public static final int PACKET_HEADER_SIZE = 16;
	public static final int TIMESTAMP_OFFSET = 0;
	public static final int TIMESTAMP_MICROS_OFFSET = 4;
	public static final int PACKET_LEN_OFFSET = 8;
	public static final int ETHERNET_DES_MAC_OFFSET = 0;
	public static final int ETHERNET_SRC_MAC_OFFSET = 6;
	public static final int ETHERNET_HEADER_SIZE = 14;
	public static final int ETHERNET_TYPE_OFFSET = 12;
	public static final int ETHERNET_TYPE_IP = 0x800;
	public static final int ETHERNET_TYPE_IPV6 = 0x86dd;
	public static final int ETHERNET_TYPE_ARP = 0x0806;
	public static final int ETHERNET_TYPE_8021Q = 0x8100;
	public static final int SLL_HEADER_BASE_SIZE = 10; // SLL stands for Linux cooked-mode capture
	public static final int SLL_ADDRESS_LENGTH_OFFSET = 4; // relative to SLL header
	public static final int IPV6_HEADER_SIZE = 40;
	public static final int IP_VHL_OFFSET = 0; // relative to start of IP header
	public static final int IP_TTL_OFFSET = 8; // relative to start of IP header
	public static final int IP_TOTAL_LEN_OFFSET = 2; // relative to start of IP header
	public static final int IPV6_PAYLOAD_LEN_OFFSET = 4; // relative to start of IP header
	public static final int IPV6_HOPLIMIT_OFFSET = 7; // relative to start of IP header
	public static final int IP_PROTOCOL_OFFSET = 9; // relative to start of IP header
	public static final int IPV6_NEXTHEADER_OFFSET = 6; // relative to start of IP header
	public static final int IP_SRC_OFFSET = 12; // relative to start of IP header
	public static final int IPV6_SRC_OFFSET = 8; // relative to start of IP header
	public static final int IP_DST_OFFSET = 16; // relative to start of IP header
	public static final int IPV6_DST_OFFSET = 24; // relative to start of IP header
	public static final int IP_ID_OFFSET = 4; // relative to start of IP header
	public static final int IPV6_ID_OFFSET = 4; // relative to start of IP header
	public static final int IP_FLAGS_OFFSET = 6; // relative to start of IP header
	public static final int IPV6_FLAGS_OFFSET = 3; // relative to start of IP header
	public static final int IP_FRAGMENT_OFFSET = 6; // relative to start of IP header
	public static final int IPV6_FRAGMENT_OFFSET = 2; // relative to start of IP header
	public static final int UDP_HEADER_SIZE = 8;
	public static final int ICMP_HEADER_SIZE = 4;
	public static final int PROTOCOL_HEADER_SRC_PORT_OFFSET = 0;
	public static final int PROTOCOL_HEADER_DST_PORT_OFFSET = 2;
	public static final int PROTOCOL_HEADER_TCP_SEQ_OFFSET = 4;
	public static final int PROTOCOL_HEADER_TCP_ACK_OFFSET = 8;
	public static final int TCP_HEADER_DATA_OFFSET = 12;
	public static final String PROTOCOL_ICMP = "ICMP";
	public static final String PROTOCOL_TCP = "TCP";
	public static final String PROTOCOL_UDP = "UDP";
	public static final String PROTOCOL_FRAGMENT = "Fragment";
	public static final String PROTOCOL_GRE = "GRE";
}
