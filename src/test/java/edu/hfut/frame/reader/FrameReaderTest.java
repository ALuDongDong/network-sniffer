package edu.hfut.frame.reader;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import org.junit.Assert;
import org.junit.Test;

import edu.hfut.frame.domain.Frame;

public class FrameReaderTest {

	private byte[] generateKafkaData(String filePath) {
		ByteBuffer kafkaPack = ByteBuffer.allocate(1024 * 1024);
		// kafka data header
		kafkaPack.put(new byte[32]);

		byte[] buffer = new byte[1024];
		try (DataInputStream inputStream = new DataInputStream(new FileInputStream(filePath))) {
			// skip pcap header
			inputStream.skip(24);
			int num = inputStream.read(buffer);
			while (num != -1) {
				kafkaPack.put(buffer, 0, num);
				num = inputStream.read(buffer);
			}
		} catch (IOException e) {
			Assert.fail();
		}
		int length = kafkaPack.position();
		byte[] kafkaData = new byte[length];
		kafkaPack.flip();
		kafkaPack.get(kafkaData);
		return kafkaData;
	}

	@Test
	public void testArp() {
		byte[] kafkaData = generateKafkaData("src/test/resources/ARP.pcap");
		FrameReader reader = new FrameReader(kafkaData);
		Frame frame = reader.nextFrame();
		Assert.assertTrue(frame.getInterProto().equals("ARP"));
		Assert.assertTrue(frame.getSrcMac().equals("90:2B:34:32:02:60"));
		Assert.assertTrue(frame.getDesMac().equals("16:58:70:27:42:39"));
		Assert.assertTrue(frame.getSrcIp().equals("10.18.22.13"));
		Assert.assertTrue(frame.getDesIp().equals("10.18.22.1"));
	}

	@Test
	public void testIcmp() {
		byte[] kafkaData = generateKafkaData("src/test/resources/ICMP.pcap");
		FrameReader reader = new FrameReader(kafkaData);
		Frame frame = reader.nextFrame();
		Assert.assertTrue(frame.getInterProto().equals("IPv4"));
		Assert.assertTrue(frame.getSrcMac().equals("00:0C:29:78:7E:65"));
		Assert.assertTrue(frame.getDesMac().equals("00:50:56:F2:27:1C"));
		Assert.assertTrue(frame.getSrcIp().equals("192.168.197.130"));
		Assert.assertTrue(frame.getDesIp().equals("10.18.22.13"));
		Assert.assertTrue(frame.getTransProto().equals("ICMP"));
		Assert.assertTrue(frame.getFlags("icmp_type").equals(8));
	}

	@Test
	public void testUdp() {
		byte[] kafkaData = generateKafkaData("src/test/resources/UDP.pcap");
		FrameReader reader = new FrameReader(kafkaData);
		Frame frame = reader.nextFrame();
		Assert.assertTrue(frame.getInterProto().equals("IPv4"));
		Assert.assertTrue(frame.getSrcMac().equals("90:2B:34:32:02:60"));
		Assert.assertTrue(frame.getDesMac().equals("00:E0:B4:15:96:37"));
		Assert.assertTrue(frame.getSrcIp().equals("10.18.22.13"));
		Assert.assertTrue(frame.getDesIp().equals("111.216.246.17"));
		Assert.assertTrue(frame.getTransProto().equals("UDP"));
		Assert.assertTrue(frame.getSrcPort() == 51686);
		Assert.assertTrue(frame.getDesPort() == 40359);
		Assert.assertTrue(frame.getPayload().length == 362);
	}

	@Test
	public void testTcpNopayload() {
		byte[] kafkaData = generateKafkaData("src/test/resources/TCP_nopayload.pcap");
		FrameReader reader = new FrameReader(kafkaData);
		Frame frame = reader.nextFrame();
		Assert.assertTrue(frame.getInterProto().equals("IPv4"));
		Assert.assertTrue(frame.getSrcMac().equals("40:8D:5C:BF:4C:6E"));
		Assert.assertTrue(frame.getDesMac().equals("00:90:0B:29:29:25"));
		Assert.assertTrue(frame.getSrcIp().equals("192.168.6.12"));
		Assert.assertTrue(frame.getDesIp().equals("220.181.7.190"));
		Assert.assertTrue(frame.getTransProto().equals("TCP"));
		Assert.assertTrue(frame.getSrcPort() == 50445);
		Assert.assertTrue(frame.getDesPort() == 80);
		Assert.assertTrue(frame.getPayload().length == 0);
	}

	@Test
	public void testTcpPayload() {
		byte[] kafkaData = generateKafkaData("src/test/resources/TCP_payload.pcap");
		FrameReader reader = new FrameReader(kafkaData);
		Frame frame = reader.nextFrame();
		Assert.assertTrue(frame.getInterProto().equals("IPv4"));
		Assert.assertTrue(frame.getSrcMac().equals("90:2B:34:32:02:60"));
		Assert.assertTrue(frame.getDesMac().equals("00:E0:B4:15:96:37"));
		Assert.assertTrue(frame.getSrcIp().equals("10.18.22.13"));
		Assert.assertTrue(frame.getDesIp().equals("123.125.114.101"));
		Assert.assertTrue(frame.getTransProto().equals("TCP"));
		Assert.assertTrue(frame.getSrcPort() == 62756);
		Assert.assertTrue(frame.getDesPort() == 80);
		Assert.assertTrue(frame.getPayload().length == 527);
	}

}
