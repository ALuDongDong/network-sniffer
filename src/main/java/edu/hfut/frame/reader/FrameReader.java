package edu.hfut.frame.reader;

import static edu.hfut.frame.domain.ReaderConstant.ETHERNET_HEADER_SIZE;
import static edu.hfut.frame.domain.ReaderConstant.ETHERNET_TYPE_8021Q;
import static edu.hfut.frame.domain.ReaderConstant.ETHERNET_TYPE_ARP;
import static edu.hfut.frame.domain.ReaderConstant.ETHERNET_TYPE_IP;
import static edu.hfut.frame.domain.ReaderConstant.ETHERNET_TYPE_IPV6;
import static edu.hfut.frame.domain.ReaderConstant.ETHERNET_TYPE_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IPV6_DST_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IPV6_FLAGS_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IPV6_FRAGMENT_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IPV6_HEADER_SIZE;
import static edu.hfut.frame.domain.ReaderConstant.IPV6_ID_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IPV6_NEXTHEADER_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IPV6_PAYLOAD_LEN_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IPV6_SRC_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IP_DST_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IP_FLAGS_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IP_FRAGMENT_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IP_ID_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IP_PROTOCOL_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IP_SRC_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IP_TOTAL_LEN_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.IP_VHL_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.PACKET_HEADER_SIZE;
import static edu.hfut.frame.domain.ReaderConstant.PACKET_LEN_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_FRAGMENT;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_HEADER_DST_PORT_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_HEADER_SRC_PORT_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_HEADER_TCP_ACK_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_HEADER_TCP_SEQ_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_ICMP;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_TCP;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_UDP;
import static edu.hfut.frame.domain.ReaderConstant.SLL_ADDRESS_LENGTH_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.SLL_HEADER_BASE_SIZE;
import static edu.hfut.frame.domain.ReaderConstant.TCP_HEADER_DATA_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.TIMESTAMP_MICROS_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.TIMESTAMP_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.UDP_HEADER_SIZE;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.hfut.frame.domain.Frame;
import edu.hfut.frame.domain.Frame.FrameBuilder;
import edu.hfut.frame.domain.FrameConstant;
import edu.hfut.frame.domain.LinkType;
import edu.hfut.frame.domain.ReaderConstant;
import edu.hfut.frame.util.PcapReaderUtil;

/**
 * 实现从数据包中读取frame信息
 * @author donglei
 * @date: 2016年4月26日 下午8:55:12
 */
public class FrameReader {

	private static final Logger logger = LoggerFactory.getLogger(FrameReader.class);

	private ByteBuffer data;

	// To read reversed-endian PCAPs; the header is the only part that switches
	private boolean reverseHeaderByteOrder = false;
	private LinkType linkType = LinkType.EN10MB;

	public FrameReader(byte[] datas) {
		this.data = ByteBuffer.wrap(datas);
		// 跳过数据包头32个字节
		if (data.remaining() > 32) {
			data.position(32);
		} else {
			this.data = ByteBuffer.wrap(new byte[0]);
		}
	}

	/**
	 * 从输入流中读取buf.length字节的数据到buf中
	 * @param buf
	 * @return
	 */
	private boolean readBytes(byte[] buf) {
		try {
			this.data.get(buf);
			return true;
		} catch (BufferUnderflowException e) {
			// Reached the end of the stream
			return false;
		}
	}

	protected int findIPStart(byte[] packet) {
		int start = -1;
		switch (this.linkType) {
		case NULL:
			return 4;
		case EN10MB:
			start = ETHERNET_HEADER_SIZE;
			int etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET);
			if (etherType == ETHERNET_TYPE_8021Q) {
				etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET + 4);
				start += 4;
			}
			if (etherType == ETHERNET_TYPE_IP || etherType == ETHERNET_TYPE_IPV6 || etherType == ETHERNET_TYPE_ARP) {
				return start;
			}
			break;
		case RAW:
			return 0;
		case LOOP:
			return 4;
		case LINUX_SLL:
			start = SLL_HEADER_BASE_SIZE;
			int sllAddressLength = PcapReaderUtil.convertShort(packet, SLL_ADDRESS_LENGTH_OFFSET);
			start += sllAddressLength;
			return start;
		}
		return -1;
	}

	private int findEtherType(byte[] packet) {
		int etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET);
		switch (etherType) {
		case ETHERNET_TYPE_IP:
			return ETHERNET_TYPE_IP;
		case ETHERNET_TYPE_IPV6:
			return ETHERNET_TYPE_IPV6;
		case ETHERNET_TYPE_ARP:
			return ETHERNET_TYPE_ARP;
		default:
			return 0;
		}
	}

	private int getInternetProtocolHeaderVersion(byte[] packet, int ipStart) {
		return packet[ipStart + IP_VHL_OFFSET] >> 4 & 0xF;
	}

	private int getInternetProtocolHeaderLength(byte[] packet, int ipProtocolHeaderVersion, int ipStart) {
		if (ipProtocolHeaderVersion == 4) {
			return (packet[ipStart + IP_VHL_OFFSET] & 0xF) * 4;
		} else if (ipProtocolHeaderVersion == 6) {
			return 40;
		}
		return -1;
	}

	private void buildInternetProtocolV4Packet(FrameBuilder builder, byte[] packetData, int ipStart) {
		long id = PcapReaderUtil.convertShort(packetData, ipStart + IP_ID_OFFSET);
		builder.setId(id);
		int flags = packetData[ipStart + IP_FLAGS_OFFSET] & 0xE0;
		builder.addFlags(FrameConstant.IP_FLAGS_DF, (flags & 0x40) == 0 ? false : true);
		builder.addFlags(FrameConstant.IP_FLAGS_MF, (flags & 0x20) == 0 ? false : true);

		long fragmentOffset = (PcapReaderUtil.convertShort(packetData, ipStart + IP_FRAGMENT_OFFSET) & 0x1FFF) * 8;
		builder.addFlags(FrameConstant.FRAGMENT_OFFSET, fragmentOffset);

		if ((flags & 0x20) != 0 || fragmentOffset != 0) {
			builder.addFlags(FrameConstant.FRAGMENT, true);
			builder.addFlags(FrameConstant.LAST_FRAGMENT, (flags & 0x20) == 0 && fragmentOffset != 0);
		} else {
			builder.addFlags(FrameConstant.FRAGMENT, false);
		}

		int protocol = packetData[ipStart + IP_PROTOCOL_OFFSET];
		builder.setTransProto(PcapReaderUtil.convertProtocolIdentifier(protocol));

		String src = PcapReaderUtil.convertAddress(packetData, ipStart + IP_SRC_OFFSET, 4);
		builder.setSrcIp(src);

		String dst = PcapReaderUtil.convertAddress(packetData, ipStart + IP_DST_OFFSET, 4);
		builder.setDesIp(dst);
	}

	private void buildInternetProtocolV6Packet(FrameBuilder builder, byte[] packetData, int ipStart) {
		int protocol = packetData[ipStart + IPV6_NEXTHEADER_OFFSET];
		builder.setTransProto(PcapReaderUtil.convertProtocolIdentifier(protocol));

		String src = PcapReaderUtil.convertAddress(packetData, ipStart + IPV6_SRC_OFFSET, 16);
		builder.setSrcIp(src);

		String dst = PcapReaderUtil.convertAddress(packetData, ipStart + IPV6_DST_OFFSET, 16);
		builder.setDesIp(dst);
	}

	private int buildInternetProtocolV6ExtensionHeaderFragment(FrameBuilder builder, byte[] packetData, int ipStart) {
		if (PROTOCOL_FRAGMENT.equals(builder.getTransProto())) {
			long id = PcapReaderUtil.convertUnsignedInt(packetData, ipStart + IPV6_HEADER_SIZE + IPV6_ID_OFFSET);
			builder.setId(id);

			int flags = packetData[ipStart + IPV6_HEADER_SIZE + IPV6_FLAGS_OFFSET] & 0x7;
			builder.addFlags(FrameConstant.IPV6_FLAGS_M, (flags & 0x1) == 0 ? false : true);

			long fragmentOffset = PcapReaderUtil.convertShort(packetData, ipStart + IPV6_HEADER_SIZE
					+ IPV6_FRAGMENT_OFFSET) & 0xFFF8;
			builder.addFlags(FrameConstant.FRAGMENT_OFFSET, fragmentOffset);

			builder.addFlags(FrameConstant.FRAGMENT, true);
			builder.addFlags(FrameConstant.LAST_FRAGMENT, (flags & 0x1) == 0 && fragmentOffset != 0);

			int protocol = packetData[ipStart + IPV6_HEADER_SIZE];
			// Change protocol to value from fragment header
			builder.setTransProto(PcapReaderUtil.convertProtocolIdentifier(protocol));

			return 8; // Return fragment header extension length
		}

		// Not a fragment
		builder.addFlags(FrameConstant.FRAGMENT, false);
		return 0;
	}

	/**
	 * Reads the packet payload and returns it as byte[]. If the payload could
	 * not be read an empty byte[] is returned.
	 *
	 * @param packetData
	 * @param payloadDataStart
	 * @return payload as byte[]
	 */
	protected byte[] readPayload(byte[] packetData, int payloadDataStart, int payloadLength) {
		if (payloadLength < 0) {
			logger.warn("Malformed packet - negative payload length. Returning empty payload.");
			return new byte[0];
		}
		if (payloadDataStart > packetData.length) {
			logger.warn("Payload start (" + payloadDataStart + ") is larger than packet data (" + packetData.length
					+ "). Returning empty payload.");
			return new byte[0];
		}
		if (payloadDataStart + payloadLength > packetData.length) {
			payloadLength = packetData.length - payloadDataStart;
		}
		byte[] data = new byte[payloadLength];
		System.arraycopy(packetData, payloadDataStart, data, 0, payloadLength);
		return data;
	}

	private int getUdpChecksum(byte[] packetData, int ipStart, int ipHeaderLen) {
		/*
		 * No Checksum on this packet?
		 */
		if (packetData[ipStart + ipHeaderLen + 6] == 0 && packetData[ipStart + ipHeaderLen + 7] == 0) {
			return -1;
		}

		/*
		 * Build data[] that we can checksum. Its a pseudo-header followed by
		 * the entire UDP packet.
		 */
		byte data[] = new byte[packetData.length - ipStart - ipHeaderLen + 12];
		int sum = 0;
		System.arraycopy(packetData, ipStart + IP_SRC_OFFSET, data, 0, 4);
		System.arraycopy(packetData, ipStart + IP_DST_OFFSET, data, 4, 4);
		data[8] = 0;
		data[9] = 17; /* IPPROTO_UDP */
		System.arraycopy(packetData, ipStart + ipHeaderLen + 4, data, 10, 2);
		System.arraycopy(packetData, ipStart + ipHeaderLen, data, 12, packetData.length - ipStart - ipHeaderLen);
		for (int i = 0; i < data.length; i++) {
			int j = data[i];
			if (j < 0) {
				j += 256;
			}
			sum += j << (i % 2 == 0 ? 8 : 0);
		}
		sum = (sum >> 16) + (sum & 0xffff);
		sum += sum >> 16;
			return ~sum & 0xffff;
	}

	private int getUdpLength(byte[] packetData, int ipStart, int ipHeaderLen) {
		int udpLen = PcapReaderUtil.convertShort(packetData, ipStart + ipHeaderLen + 4);
		return udpLen;
	}

	private int getTcpHeaderLength(byte[] packet, int tcpStart) {
		int dataOffset = tcpStart + TCP_HEADER_DATA_OFFSET;
		return (packet[dataOffset] >> 4 & 0xF) * 4;
	}

	/*
	 * packetData is the entire layer 2 packet read from pcap ipStart is the
	 * start of the IP packet in packetData
	 */
	private byte[] buildTcpAndUdpPacket(FrameBuilder builder, byte[] packetData, int ipProtocolHeaderVersion,
			int ipStart, int ipHeaderLen, int totalLength) {
		builder.setSrcPort(PcapReaderUtil.convertShort(packetData, ipStart + ipHeaderLen
				+ PROTOCOL_HEADER_SRC_PORT_OFFSET));
		builder.setDesPort(PcapReaderUtil.convertShort(packetData, ipStart + ipHeaderLen
				+ PROTOCOL_HEADER_DST_PORT_OFFSET));

		int tcpOrUdpHeaderSize;
		final String protocol = builder.getTransProto();
		if (PROTOCOL_UDP.equals(protocol)) {
			tcpOrUdpHeaderSize = UDP_HEADER_SIZE;

			if (ipProtocolHeaderVersion == 4) {
				int cksum = getUdpChecksum(packetData, ipStart, ipHeaderLen);
				if (cksum >= 0) {
					builder.addFlags(FrameConstant.UDPSUM, cksum);
				}
			}
			// TODO UDP Checksum for IPv6 packets

			int udpLen = getUdpLength(packetData, ipStart, ipHeaderLen);
			builder.addFlags(FrameConstant.UDP_LENGTH, udpLen);
		} else if (PROTOCOL_TCP.equals(protocol)) {
			tcpOrUdpHeaderSize = getTcpHeaderLength(packetData, ipStart + ipHeaderLen);

			// Store the sequence and acknowledgement numbers --M
			builder.setSeq(PcapReaderUtil.convertUnsignedInt(packetData, ipStart + ipHeaderLen
					+ PROTOCOL_HEADER_TCP_SEQ_OFFSET));
			builder.setAwk(PcapReaderUtil.convertUnsignedInt(packetData, ipStart + ipHeaderLen
					+ PROTOCOL_HEADER_TCP_ACK_OFFSET));

			// Flags stretch two bytes starting at the TCP header offset
			int flags = PcapReaderUtil.convertShort(new byte[] {
					packetData[ipStart + ipHeaderLen + TCP_HEADER_DATA_OFFSET],
					packetData[ipStart + ipHeaderLen + TCP_HEADER_DATA_OFFSET + 1] }) & 0x1FF;
			// Filter first 7 bits. First 4 are the data offset and the other 3 reserved for future use.
			builder.addFlags(FrameConstant.TCP_FLAG_NS, (flags & 0x100) == 0 ? false : true);
			builder.addFlags(FrameConstant.TCP_FLAG_CWR, (flags & 0x80) == 0 ? false : true);
			builder.addFlags(FrameConstant.TCP_FLAG_ECE, (flags & 0x40) == 0 ? false : true);
			builder.addFlags(FrameConstant.TCP_FLAG_URG, (flags & 0x20) == 0 ? false : true);
			builder.addFlags(FrameConstant.TCP_FLAG_ACK, (flags & 0x10) == 0 ? false : true);
			builder.addFlags(FrameConstant.TCP_FLAG_PSH, (flags & 0x8) == 0 ? false : true);
			builder.addFlags(FrameConstant.TCP_FLAG_RST, (flags & 0x4) == 0 ? false : true);
			builder.addFlags(FrameConstant.TCP_FLAG_SYN, (flags & 0x2) == 0 ? false : true);
			builder.addFlags(FrameConstant.TCP_FLAG_FIN, (flags & 0x1) == 0 ? false : true);
		} else {
			return null;
		}

		// 传输层负载 相对于数据帧  payloadDataStart ＝ 链路层长度(14) + 网络层长度(20) + 传输层长度(32)
		// payloadLength = 总长度 － 网络层长度 － 传输层
		int payloadDataStart = ipStart + ipHeaderLen + tcpOrUdpHeaderSize;
		int payloadLength = totalLength - ipHeaderLen - tcpOrUdpHeaderSize;
		byte[] data = readPayload(packetData, payloadDataStart, payloadLength);
		return data;
	}

	private byte[] buildIcmpPacket(FrameBuilder builder, byte[] packetData, int ipProtocolHeaderVersion, int ipStart,
			int ipHeaderLen, int totalLength) {
		if (PROTOCOL_ICMP.equals(builder.getTransProto())) {
			int type = packetData[ipStart + ipHeaderLen];
			int code = packetData[ipStart + ipHeaderLen + 1];
			int checksum = PcapReaderUtil.convertShort(packetData, ipStart + ipHeaderLen + 2);
			builder.addFlags(FrameConstant.ICMP_TYPE, type);
			builder.addFlags(FrameConstant.ICMP_CODE, code);
			builder.addFlags(FrameConstant.ICMP_CHECKSUM, checksum);
			int payloadDataStart = ipStart + ipHeaderLen + ReaderConstant.ICMP_HEADER_SIZE;
			int payloadLength = totalLength - ipHeaderLen - ReaderConstant.ICMP_HEADER_SIZE;
			byte[] data = readPayload(packetData, payloadDataStart, payloadLength);
			return data;
		}
		return new byte[0];
	}

	private String getMacAddress(byte[] packetData, int offset) {
		byte[] macData = new byte[6];
		System.arraycopy(packetData, offset, macData, 0, 6);
		return PcapReaderUtil.getMacAddress(macData);
	}

	public Frame nextFrame() {
		/**
		 * 解析Packet Header，长度16B，分别是时间戳秒（4B）、时间戳微秒（4B）、数据帧的长度（4B）、数据包网络中原始长度（4B）
		 */
		byte[] pcapPacketHeader = new byte[PACKET_HEADER_SIZE];
		if (!readBytes(pcapPacketHeader)) {
			return null;
		}

		FrameBuilder builder = new FrameBuilder();

		long packetTimestamp = PcapReaderUtil.convertInt(pcapPacketHeader, TIMESTAMP_OFFSET, reverseHeaderByteOrder);

		long packetTimestampMicros = PcapReaderUtil.convertInt(pcapPacketHeader, TIMESTAMP_MICROS_OFFSET,
				reverseHeaderByteOrder);

		builder.setTimestamp(packetTimestamp + packetTimestampMicros / 1000);

		// 数据帧的长度,包含数据链路层到传输层的负载，应用层需根据传输层的负载判断
		long packetSize = PcapReaderUtil.convertInt(pcapPacketHeader, PACKET_LEN_OFFSET, reverseHeaderByteOrder);

		byte[] packetData = new byte[(int) packetSize];
		if (!readBytes(packetData)) {
			return builder.build();
		}

		// 找到网络层的地址 ipStart＝14
		int ipStart = findIPStart(packetData);
		if (ipStart == -1) {
			return builder.build();
		}

		int etherType = this.findEtherType(packetData);
		if (ETHERNET_TYPE_IP == etherType || ETHERNET_TYPE_IPV6 == etherType) {
			/**
			 * 解析Packet Data区，这里跳过了链路层协议的解析，注释以IPv4为例
			 */
			String desMac = getMacAddress(packetData, ReaderConstant.ETHERNET_DES_MAC_OFFSET);
			builder.setDesMac(desMac);

			String srcMac = getMacAddress(packetData, ReaderConstant.ETHERNET_SRC_MAC_OFFSET);
			builder.setSrcMac(srcMac);

			// 网络层协议类型 4
			int ipProtocolHeaderVersion = getInternetProtocolHeaderVersion(packetData, ipStart);
			builder.setInterProto("IPv" + ipProtocolHeaderVersion);
			if (ipProtocolHeaderVersion == 4 || ipProtocolHeaderVersion == 6) {
				// 网络层头长度 20
				int ipHeaderLen = getInternetProtocolHeaderLength(packetData, ipProtocolHeaderVersion, ipStart);
				int totalLength = 0;
				if (ipProtocolHeaderVersion == 4) {
					buildInternetProtocolV4Packet(builder, packetData, ipStart);
					// totalLength=196  数据帧长度－链路层长度
					totalLength = PcapReaderUtil.convertShort(packetData, ipStart + IP_TOTAL_LEN_OFFSET);
				} else if (ipProtocolHeaderVersion == 6) {
					buildInternetProtocolV6Packet(builder, packetData, ipStart);
					ipHeaderLen += buildInternetProtocolV6ExtensionHeaderFragment(builder, packetData, ipStart);
					int payloadLength = PcapReaderUtil.convertShort(packetData, ipStart + IPV6_PAYLOAD_LEN_OFFSET);
					totalLength = payloadLength + IPV6_HEADER_SIZE;
				}

				String protocol = builder.getTransProto();
				// 传输层数据相对于数据帧的数据块     payloadDataStart＝ipStart：14 ＋ ipHeaderLen：20       payloadLength＝196 - 20
				int payloadDataStart = ipStart + ipHeaderLen;
				int payloadLength = totalLength - ipHeaderLen;
				byte[] packetPayload = readPayload(packetData, payloadDataStart, payloadLength);
				if (PROTOCOL_UDP == protocol || PROTOCOL_TCP == protocol) {
					packetPayload = buildTcpAndUdpPacket(builder, packetData, ipProtocolHeaderVersion, ipStart,
							ipHeaderLen, totalLength);
				} else if (PROTOCOL_ICMP == protocol) {
					packetPayload = buildIcmpPacket(builder, packetData, ipProtocolHeaderVersion, ipStart, ipHeaderLen,
							totalLength);
				}
				builder.setPayload(packetPayload);
			}
		} else if (ETHERNET_TYPE_ARP == etherType) {
			builder.setInterProto("ARP");
			int hardwareType = PcapReaderUtil.convertShort(packetData, ipStart);
			int protocolType = PcapReaderUtil.convertShort(packetData, ipStart + 2);
			int hardwareSize = packetData[ipStart + 4];
			int protocolSize = packetData[ipStart + 5];
			int opcode = PcapReaderUtil.convertShort(packetData, ipStart + 6);
			builder.addFlags(FrameConstant.ARP_FLAG_OPCODE, opcode);
			if (hardwareSize == 6 && protocolSize == 4 && hardwareType == 1 && protocolType == (short) 0x0800) {
				byte[] senderMac = new byte[6];
				System.arraycopy(packetData, 22, senderMac, 0, 6);
				builder.setSrcMac(PcapReaderUtil.getMacAddress(senderMac));
				builder.setSrcIp(PcapReaderUtil.convertAddress(packetData, 28, 4));
				byte[] targetMac = new byte[6];
				System.arraycopy(packetData, 32, targetMac, 0, 6);
				builder.setDesMac(PcapReaderUtil.getMacAddress(targetMac));
				builder.setDesIp(PcapReaderUtil.convertAddress(packetData, 38, 4));
				builder.setPayload(new byte[0]);
			}
		}
		return builder.build();
	}

}
