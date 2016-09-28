package edu.hfut.sniffer.parser.domain;

import org.junit.Assert;
import org.junit.Test;


public class ChainBufferTest {

	@Test
	public void testChainBuffer() {
		Buffer buffer = new ChainBuffer();
		buffer.addLast(new byte[] { 0x01, 0x02, 0x03 });
		buffer.addLast(new byte[] { 0x04, 0x05, 0x06 });
		Assert.assertTrue(buffer.position() == 0);
		Assert.assertTrue(buffer.readableBytes() == 6);
		Assert.assertTrue(buffer.get() == 0x01);
		Assert.assertTrue(buffer.position() == 1);
	}

}
