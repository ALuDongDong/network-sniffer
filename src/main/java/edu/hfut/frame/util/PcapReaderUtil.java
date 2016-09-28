package edu.hfut.frame.util;

import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_FRAGMENT;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_GRE;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_ICMP;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_TCP;
import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_UDP;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * pcap解析工具类
 * @author donglei
 * @date: 2016年4月27日 上午11:49:29
 */
public class PcapReaderUtil {

	private static final Logger logger = LoggerFactory.getLogger(PcapReaderUtil.class);

	private static Map<Integer, String> protocols;

	static {
		protocols = new HashMap<Integer, String>();
		protocols.put(1, PROTOCOL_ICMP);
		protocols.put(6, PROTOCOL_TCP);
		protocols.put(17, PROTOCOL_UDP);
		protocols.put(44, PROTOCOL_FRAGMENT); // Using IPv4 fragment protocol number across protocols (see http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
		protocols.put(47, PROTOCOL_GRE);
	}

	public static long convertInt(byte[] data) {
		return convertInt(data, false);
	}

	public static long convertInt(byte[] data, boolean reversed) {
		if (!reversed) {
			return (data[3] & 0xFF) << 24 | (data[2] & 0xFF) << 16 | (data[1] & 0xFF) << 8 | data[0] & 0xFF;
		} else {
			return (data[0] & 0xFF) << 24 | (data[1] & 0xFF) << 16 | (data[2] & 0xFF) << 8 | data[3] & 0xFF;
		}
	}

	public static long convertInt(byte[] data, int offset, boolean reversed) {
		byte[] target = new byte[4];
		System.arraycopy(data, offset, target, 0, target.length);
		return convertInt(target, reversed);
	}

	public static long convertInt(byte[] data, int offset) {
		byte[] target = new byte[4];
		System.arraycopy(data, offset, target, 0, target.length);
		return convertInt(target, false);
	}

	public static int convertShort(byte[] data) {
		return (data[0] & 0xFF) << 8 | data[1] & 0xFF;
	}

	public static byte[] convertShort(int data) {
		byte[] result = new byte[2];
		result[0] = (byte) (data >> 8);
		result[1] = (byte) data;
		return result;
	}

	public static int convertShort(byte[] data, int offset) {
		byte[] target = new byte[2];
		System.arraycopy(data, offset, target, 0, target.length);
		return convertShort(target);
	}

	//A java workaround for header fields like seq/ack which are ulongs --M
	public static long convertUnsignedInt(byte[] data, int offset) {
		byte[] target = new byte[4];
		System.arraycopy(data, offset, target, 0, target.length);

		BigInteger placeholder = new BigInteger(1, target);
		return placeholder.longValue();
	}

	public static String convertProtocolIdentifier(int identifier) {
		return protocols.get(identifier);
	}

	public static String convertAddress(byte[] data, int offset, int size) {
		byte[] addr = new byte[size];
		System.arraycopy(data, offset, addr, 0, addr.length);
		try {
			return InetAddress.getByAddress(addr).getHostAddress();
		} catch (UnknownHostException e) {
			logger.error("Can't parse the IP address because of {}", e.getMessage());
			return null;
		}
	}

	/**
	 * This method converts a byte[6] that stores a mac address to a
	 * easily readable ':' separated mac address String.
	 * @param source a byte[] that stores a hexadecimal mac address
	 * @return a String
	 */
	public static String getMacAddress(byte[] source) {
		StringBuilder str = new StringBuilder();
		try {
			String rawString = javax.xml.bind.DatatypeConverter.printHexBinary(source);
			str.append(rawString);
			int n = 0;
			for (int i = 0; i < str.length(); i++) {
				if (n == 2) {
					str.insert(i, ':');
					n = 0;
				} else {
					n++;
				}
			}

		} catch (Exception e) {
			logger.error("An error has occured while parsing a MAC address");
		}

		return str.toString();
	}

}
