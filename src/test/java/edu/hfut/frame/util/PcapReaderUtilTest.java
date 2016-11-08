package edu.hfut.frame.util;

import org.junit.Assert;
import org.junit.Test;


public class PcapReaderUtilTest {

	@Test
	public void testGetMacAddress() {
		byte[] a = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
		String mac = PcapReaderUtil.getMacAddress(a);
		Assert.assertEquals("01:02:03:04:05:06", mac);
	}

}
