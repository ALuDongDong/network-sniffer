package edu.hfut.frame.reader;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import edu.hfut.frame.domain.Frame;

public class PcapReaderTest {

	private static final String TEST_ALL = "src/test/resources/protocol-all.pcap";
	private static final String TEST_ARP = "src/test/resources/ARP.pcap";
	private static final String TEST_ICMP = "src/test/resources/ICMP.pcap";
	private static final String TEST_UDP = "src/test/resources/UDP.pcap";
	private static final String TEST_TCPNOPayLoad = "src/test/resources/TCP_nopayload.pcap";
	private static final String TEST_TCPPayLoad = "src/test/resources/TCP_payload.pcap";

	@Test
	public void testArp() throws IOException {
		DataInputStream inputStream = new DataInputStream(new FileInputStream(TEST_ARP));
		PcapReader reader = new PcapReader(inputStream);
		List<Frame> frames = new ArrayList<Frame>();
		for (Frame packet : reader) {
			frames.add(packet);
		}
		Assert.assertTrue(frames.size() == 1);
		Assert.assertTrue(frames.get(0).getInterProto().equals("ARP"));
		Assert.assertTrue(frames.get(0).getSrcMac().equals("90:2B:34:32:02:60"));
		Assert.assertTrue(frames.get(0).getDesMac().equals("16:58:70:27:42:39"));
		Assert.assertTrue(frames.get(0).getSrcIp().equals("10.18.22.13"));
		Assert.assertTrue(frames.get(0).getDesIp().equals("10.18.22.1"));
	}

	@Test
	public void testIcmp() throws IOException {
		DataInputStream inputStream = new DataInputStream(new FileInputStream(TEST_ICMP));
		PcapReader reader = new PcapReader(inputStream);
		List<Frame> frames = new ArrayList<Frame>();
		for (Frame packet : reader) {
			frames.add(packet);
		}
		Assert.assertTrue(frames.size() == 1);
		Assert.assertTrue(frames.get(0).getInterProto().equals("IPv4"));
		Assert.assertTrue(frames.get(0).getSrcMac().equals("00:0C:29:78:7E:65"));
		Assert.assertTrue(frames.get(0).getDesMac().equals("00:50:56:F2:27:1C"));
		Assert.assertTrue(frames.get(0).getSrcIp().equals("192.168.197.130"));
		Assert.assertTrue(frames.get(0).getDesIp().equals("10.18.22.13"));
		Assert.assertTrue(frames.get(0).getTransProto().equals("ICMP"));
		Assert.assertTrue(frames.get(0).getFlags("icmp_type").equals(8));
	}

	@Test
	public void testUdp() throws IOException {
		DataInputStream inputStream = new DataInputStream(new FileInputStream(TEST_UDP));
		PcapReader reader = new PcapReader(inputStream);
		List<Frame> frames = new ArrayList<Frame>();
		for (Frame packet : reader) {
			frames.add(packet);
		}
		Assert.assertTrue(frames.size() == 1);
		Assert.assertTrue(frames.get(0).getInterProto().equals("IPv4"));
		Assert.assertTrue(frames.get(0).getSrcMac().equals("90:2B:34:32:02:60"));
		Assert.assertTrue(frames.get(0).getDesMac().equals("00:E0:B4:15:96:37"));
		Assert.assertTrue(frames.get(0).getSrcIp().equals("10.18.22.13"));
		Assert.assertTrue(frames.get(0).getDesIp().equals("111.216.246.17"));
		Assert.assertTrue(frames.get(0).getTransProto().equals("UDP"));
		Assert.assertTrue(frames.get(0).getSrcPort() == 51686);
		Assert.assertTrue(frames.get(0).getDesPort() == 40359);
		Assert.assertTrue(frames.get(0).getPayload().length == 362);
	}

	@Test
	public void testTcpNopayload() throws IOException {
		DataInputStream inputStream = new DataInputStream(new FileInputStream(TEST_TCPNOPayLoad));
		PcapReader reader = new PcapReader(inputStream);
		List<Frame> frames = new ArrayList<Frame>();
		for (Frame packet : reader) {
			frames.add(packet);
		}
		Assert.assertTrue(frames.size() == 1);
		Assert.assertTrue(frames.get(0).getInterProto().equals("IPv4"));
		Assert.assertTrue(frames.get(0).getSrcMac().equals("40:8D:5C:BF:4C:6E"));
		Assert.assertTrue(frames.get(0).getDesMac().equals("00:90:0B:29:29:25"));
		Assert.assertTrue(frames.get(0).getSrcIp().equals("192.168.6.12"));
		Assert.assertTrue(frames.get(0).getDesIp().equals("220.181.7.190"));
		Assert.assertTrue(frames.get(0).getTransProto().equals("TCP"));
		Assert.assertTrue(frames.get(0).getSrcPort() == 50445);
		Assert.assertTrue(frames.get(0).getDesPort() == 80);
		Assert.assertTrue(frames.get(0).getPayload().length == 0);
	}

	@Test
	public void testTcpPayload() throws IOException {
		DataInputStream inputStream = new DataInputStream(new FileInputStream(TEST_TCPPayLoad));
		PcapReader reader = new PcapReader(inputStream);
		List<Frame> frames = new ArrayList<Frame>();
		for (Frame packet : reader) {
			frames.add(packet);
		}
		Assert.assertTrue(frames.size() == 1);
		Assert.assertTrue(frames.get(0).getInterProto().equals("IPv4"));
		Assert.assertTrue(frames.get(0).getSrcMac().equals("90:2B:34:32:02:60"));
		Assert.assertTrue(frames.get(0).getDesMac().equals("00:E0:B4:15:96:37"));
		Assert.assertTrue(frames.get(0).getSrcIp().equals("10.18.22.13"));
		Assert.assertTrue(frames.get(0).getDesIp().equals("123.125.114.101"));
		Assert.assertTrue(frames.get(0).getTransProto().equals("TCP"));
		Assert.assertTrue(frames.get(0).getSrcPort() == 62756);
		Assert.assertTrue(frames.get(0).getDesPort() == 80);
		Assert.assertTrue(frames.get(0).getPayload().length == 527);
	}

	@Test
	@SuppressWarnings("unused")
	public void test() throws IOException {
		DataInputStream inputStream = new DataInputStream(new FileInputStream(TEST_ALL));
		PcapReader reader = new PcapReader(inputStream);
		int i = 0;
		for (Frame packet : reader) {
			i++;
		}
		Assert.assertTrue(i == 345);
	}

}
