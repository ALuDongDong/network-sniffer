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
import static edu.hfut.frame.domain.ReaderConstant.MAGIC_NUMBER;
import static edu.hfut.frame.domain.ReaderConstant.PACKET_HEADER_SIZE;
import static edu.hfut.frame.domain.ReaderConstant.PACKET_LEN_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.PCAP_HEADER_LINKTYPE_OFFSET;
import static edu.hfut.frame.domain.ReaderConstant.PCAP_HEADER_SIZE;
import static edu.hfut.frame.domain.ReaderConstant.PCAP_HEADER_SNAPLEN_OFFSET;
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

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;
import com.google.common.primitives.Bytes;

import edu.hfut.frame.domain.Datagram;
import edu.hfut.frame.domain.DatagramPayload;
import edu.hfut.frame.domain.Flow;
import edu.hfut.frame.domain.Frame;
import edu.hfut.frame.domain.Frame.FrameBuilder;
import edu.hfut.frame.domain.FrameConstant;
import edu.hfut.frame.domain.LinkType;
import edu.hfut.frame.domain.ReaderConstant;
import edu.hfut.frame.domain.SequencePayload;
import edu.hfut.frame.util.PcapReaderUtil;

/**
 * 从输入流中读取Pcap数据帧
 * @author donglei
 * @date: 2016年4月20日 下午2:58:54
 */
public class PcapReader implements Iterable<Frame> {

	public static final Logger logger = LoggerFactory.getLogger(PcapReader.class);

	private final DataInputStream is;
	private Iterator<Frame> iterator;
	private LinkType linkType;
	private long snapLen;
	private boolean caughtEOF = false;

	//To read reversed-endian PCAPs; the header is the only part that switches
	private boolean reverseHeaderByteOrder = false;

	private Multimap<Flow, SequencePayload> flows = TreeMultimap.create();
	private Multimap<Datagram, DatagramPayload> datagrams = TreeMultimap.create();

	public byte[] pcapHeader;
	public byte[] pcapPacketHeader;
	public byte[] packetData;

	public PcapReader(DataInputStream is) throws IOException {
		this.is = is;
		this.iterator = new PacketIterator();

		// 读取pcap头信息24B，分别是magic_number(4B)、version_major(2B)、vesion_minor(2B)、thiszone(4B)、sigfigs(4B)、snaplen(4B)、network(4B)
		this.pcapHeader = new byte[PCAP_HEADER_SIZE];
		if (!readBytes(this.pcapHeader)) {
			// 读取pcap头时，检查EOF
			// This special check for EOF is because we don't want
			// PcapReader to barf on an empty file.  This is the only
			// place we check caughtEOF.
			//
			if (this.caughtEOF) {
				logger.warn("Skipping empty file");
				return;
			}
			throw new IOException("Couldn't read PCAP header");
		}
		// magic_number判断字节序
		if (!validateMagicNumber(this.pcapHeader)) {
			throw new IOException("Not a PCAP file (Couldn't find magic number)");
		}
		// 数据包最大存储长度
		this.snapLen = PcapReaderUtil.convertInt(this.pcapHeader, PCAP_HEADER_SNAPLEN_OFFSET,
				this.reverseHeaderByteOrder);
		// 链路层类型
		long linkTypeVal = PcapReaderUtil.convertInt(this.pcapHeader, PCAP_HEADER_LINKTYPE_OFFSET,
				this.reverseHeaderByteOrder);
		if ((this.linkType = LinkType.getLinkType(linkTypeVal)) == null) {
			throw new IOException("Unsupported link type: " + linkTypeVal);
		}
	}

	// Only use this constructor for testcases
	protected PcapReader(LinkType lt) {
		this.is = null;
		this.linkType = lt;
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

	private String getMacAddress(byte[] packetData, int offset) {
		byte[] macData = new byte[6];
		System.arraycopy(packetData, offset, macData, 0, 6);
		return PcapReaderUtil.getMacAddress(macData);
	}

	private Frame nextPacket() {
		/**
		 * 解析Packet Header，长度16B，分别是时间戳秒（4B）、时间戳微秒（4B）、数据帧的长度（4B）、数据包网络中原始长度（4B）
		 */
		this.pcapPacketHeader = new byte[PACKET_HEADER_SIZE];
		if (!readBytes(this.pcapPacketHeader)) {
			return null;
		}

		FrameBuilder builder = new FrameBuilder();

		long packetTimestamp = PcapReaderUtil.convertInt(this.pcapPacketHeader, TIMESTAMP_OFFSET,
				this.reverseHeaderByteOrder);

		long packetTimestampMicros = PcapReaderUtil.convertInt(this.pcapPacketHeader, TIMESTAMP_MICROS_OFFSET,
				this.reverseHeaderByteOrder);

		builder.setTimestamp(packetTimestamp + packetTimestampMicros / 1000);

		// 数据帧的长度,包含数据链路层到传输层的负载，应用层需根据传输层的负载判断
		long packetSize = PcapReaderUtil.convertInt(this.pcapPacketHeader, PACKET_LEN_OFFSET,
				this.reverseHeaderByteOrder);
		this.packetData = new byte[(int) packetSize];
		if (!readBytes(this.packetData)) {
			return builder.build();
		}

		// 找到网络层的地址 ipStart＝14
		int ipStart = findIPStart(this.packetData);
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
			int ipProtocolHeaderVersion = getInternetProtocolHeaderVersion(this.packetData, ipStart);
			builder.setInterProto("IPv" + ipProtocolHeaderVersion);

			if (ipProtocolHeaderVersion == 4 || ipProtocolHeaderVersion == 6) {
				// 网络层头长度 20
				int ipHeaderLen = getInternetProtocolHeaderLength(this.packetData, ipProtocolHeaderVersion, ipStart);
				int totalLength = 0;
				if (ipProtocolHeaderVersion == 4) {
					buildInternetProtocolV4Packet(builder, this.packetData, ipStart);
					// totalLength=196  数据帧长度－链路层长度
					totalLength = PcapReaderUtil.convertShort(this.packetData, ipStart + IP_TOTAL_LEN_OFFSET);
					// TSO - TCP segmentation offload
					if (totalLength == 0) {
						totalLength = (int) (packetSize - ipStart);
					}
				} else if (ipProtocolHeaderVersion == 6) {
					buildInternetProtocolV6Packet(builder, this.packetData, ipStart);
					ipHeaderLen += buildInternetProtocolV6ExtensionHeaderFragment(builder, this.packetData, ipStart);
					int payloadLength = PcapReaderUtil.convertShort(this.packetData, ipStart + IPV6_PAYLOAD_LEN_OFFSET);
					totalLength = payloadLength + IPV6_HEADER_SIZE;
				}

				if ((Boolean) builder.getFlags(FrameConstant.FRAGMENT)) {
					if (isReassembleDatagram()) {
						Datagram datagram = new Datagram(builder.build());
						Long fragmentOffset = (Long) builder.getFlags(FrameConstant.FRAGMENT_OFFSET);

						byte[] fragmentPacketData = Arrays.copyOfRange(this.packetData, ipStart + ipHeaderLen, ipStart
								+ totalLength);
						DatagramPayload payload = new DatagramPayload(fragmentOffset, fragmentPacketData);
						this.datagrams.put(datagram, payload);

						if ((Boolean) builder.getFlags(FrameConstant.LAST_FRAGMENT)) {
							Collection<DatagramPayload> datagramPayloads = this.datagrams.removeAll(datagram);
							if (datagramPayloads != null && datagramPayloads.size() > 0) {
								byte[] reassmbledPacketData = Arrays.copyOfRange(this.packetData, 0, ipStart
										+ ipHeaderLen); // Start re-fragmented packet with header from current packet
								int reassmbledTotalLength = ipHeaderLen;
								int reassembledFragments = 0;
								DatagramPayload prev = null;
								for (DatagramPayload datagramPayload : datagramPayloads) {
									if (prev == null && datagramPayload.getOffset() != 0) {
										logger.warn("Datagram chain not starting at 0. Probably received packets out-of-order. Can't reassemble this packet.");
										break;
									}
									if (prev != null && !datagramPayload.linked(prev)) {
										logger.warn("Broken datagram chain between " + datagramPayload + " and " + prev
												+ ". Can't reassemble this packet.");
										break;
									}
									reassmbledPacketData = Bytes.concat(reassmbledPacketData,
											datagramPayload.getPayload());
									reassmbledTotalLength += datagramPayload.getPayload().length;
									reassembledFragments++;
									prev = datagramPayload;
								}
								if (reassembledFragments == datagramPayloads.size()) {
									this.packetData = reassmbledPacketData;
									totalLength = reassmbledTotalLength;
									builder.addFlags(FrameConstant.REASSEMBLED_DATAGRAM_FRAGMENTS, reassembledFragments);
								}
							}
						} else {
							builder.setTransProto(PROTOCOL_FRAGMENT);
						}
					} else {
						builder.setTransProto(PROTOCOL_FRAGMENT);
					}
				}

				String protocol = builder.getTransProto();
				// 传输层数据相对于数据帧的数据块     payloadDataStart＝ipStart：14 ＋ ipHeaderLen：20       payloadLength＝196 - 20
				if (PROTOCOL_UDP == protocol || PROTOCOL_TCP == protocol) {
					int payloadDataStart = ipStart + ipHeaderLen;
					int payloadLength = totalLength - ipHeaderLen;
					byte[] packetPayload = readPayload(this.packetData, payloadDataStart, payloadLength);
					packetPayload = buildTcpAndUdpPacket(builder, this.packetData, ipProtocolHeaderVersion, ipStart,
							ipHeaderLen, totalLength);
					// 顺序的TCP流合并，暂时不用
					if (isReassembleTcp() && PROTOCOL_TCP == protocol) {
						Flow flow = new Flow(builder.build());

						if (packetPayload.length > 0) {
							Long seq = builder.getSeq();
							SequencePayload sequencePayload = new SequencePayload(seq, packetPayload);
							this.flows.put(flow, sequencePayload);
						}

						if ((Boolean) builder.getFlags(FrameConstant.TCP_FLAG_FIN) || isPush()
								&& (Boolean) builder.getFlags(FrameConstant.TCP_FLAG_PSH)) {
							Collection<SequencePayload> fragments = this.flows.removeAll(flow);
							if (fragments != null && fragments.size() > 0) {

								builder.addFlags(FrameConstant.REASSEMBLED_TCP_FRAGMENTS, fragments.size());
								packetPayload = new byte[0];
								SequencePayload prev = null;
								for (SequencePayload seqPayload : fragments) {
									if (prev != null && !seqPayload.linked(prev)) {
										logger.warn("Broken sequence chain between " + seqPayload + " and " + prev
												+ ". Returning empty payload.");
										packetPayload = new byte[0];
										break;
									}
									packetPayload = Bytes.concat(packetPayload, seqPayload.getPayload());
									prev = seqPayload;
								}
							}
						}
					}
					builder.setPayload(packetPayload);
					processPacketPayload(builder, packetPayload);
				} else if (PROTOCOL_ICMP == protocol) {
					byte[] packetPayload = buildIcmpPacket(builder, this.packetData, ipProtocolHeaderVersion, ipStart,
							ipHeaderLen, totalLength);
					builder.setPayload(packetPayload);
				}
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

	protected boolean isReassembleDatagram() {
		return false;
	}

	protected boolean isReassembleTcp() {
		return false;
	}

	protected boolean isPush() {
		return false;
	}

	protected void processPacketPayload(FrameBuilder builder, byte[] payload) {
		String protocol = builder.getTransProto();

		if (!PROTOCOL_TCP.equals(protocol)) {
			return;
		}

		// 尝试以首个CR-LF截取Packet信息
		byte lastByte = 0;
		for (int i = 0; i < payload.length; i++) {
			if (lastByte == (byte) 0x0d && payload[i] == (byte) 0x0a) {
				byte[] strB = new byte[i - 1];
				System.arraycopy(payload, 0, strB, 0, i - 1);
				builder.addFlags(FrameConstant.PACKET_INFO, new String(strB));
				break;
			}
			lastByte = payload[i];
		}

		// 	获取文件名等信息
		//		PacketInfoParser.getInstance().parsePacket(packet);
	}

	/**
	 * 验证pcap头的magic_number(0xa1b2c3d4),并将字节序写入reverseHeaderByteOrder
	 * reverseHeaderByteOrder ＝ false : little-endian
	 * reverseHeaderByteOrder ＝ true : big-endian
	 * @param pcapHeader
	 * @return
	 */
	protected boolean validateMagicNumber(byte[] pcapHeader) {
		if (PcapReaderUtil.convertInt(pcapHeader) == MAGIC_NUMBER) {
			return true;
		} else if (PcapReaderUtil.convertInt(pcapHeader, true) == MAGIC_NUMBER) {
			this.reverseHeaderByteOrder = true;
			return true;
		} else {
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

	private int getInternetProtocolHeaderLength(byte[] packet, int ipProtocolHeaderVersion, int ipStart) {
		if (ipProtocolHeaderVersion == 4) {
			return (packet[ipStart + IP_VHL_OFFSET] & 0xF) * 4;
		} else if (ipProtocolHeaderVersion == 6) {
			return 40;
		}
		return -1;
	}

	private int getInternetProtocolHeaderVersion(byte[] packet, int ipStart) {
		return packet[ipStart + IP_VHL_OFFSET] >> 4 & 0xF;
	}

	private int getTcpHeaderLength(byte[] packet, int tcpStart) {
		int dataOffset = tcpStart + TCP_HEADER_DATA_OFFSET;
		return (packet[dataOffset] >> 4 & 0xF) * 4;
	}

	private void buildInternetProtocolV4Packet(FrameBuilder builder, byte[] packetData, int ipStart) {
		long id = new Long(PcapReaderUtil.convertShort(packetData, ipStart + IP_ID_OFFSET));
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
			if (payloadDataStart + payloadLength <= this.snapLen) {
				logger.warn("Payload length field value (" + payloadLength + ") is larger than available packet data ("
						+ (packetData.length - payloadDataStart)
						+ "). Packet may be corrupted. Returning only available data.");
			}
			payloadLength = packetData.length - payloadDataStart;
		}
		byte[] data = new byte[payloadLength];
		System.arraycopy(packetData, payloadDataStart, data, 0, payloadLength);
		return data;
	}

	/**
	 * 从输入流中读取buf.length字节的数据到buf中
	 * @param buf
	 * @return
	 */
	protected boolean readBytes(byte[] buf) {
		try {
			this.is.readFully(buf);
			return true;
		} catch (EOFException e) {
			// Reached the end of the stream
			this.caughtEOF = true;
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public Iterator<Frame> iterator() {
		return this.iterator;
	}

	private class PacketIterator implements Iterator<Frame> {
		private Frame next;

		private void fetchNext() {
			if (this.next == null) {
				this.next = nextPacket();
			}
		}

		@Override
		public boolean hasNext() {
			fetchNext();
			if (this.next != null) {
				return true;
			}
			int remainingFlows = PcapReader.this.flows.size();
			if (remainingFlows > 0) {
				logger.warn("Still " + remainingFlows + " flows queued. Missing packets to finish assembly?");
			}
			return false;
		}

		@Override
		public Frame next() {
			fetchNext();
			try {
				return this.next;
			} finally {
				this.next = null;
			}
		}

		@Override
		public void remove() {
			// Not supported
		}
	}
}
