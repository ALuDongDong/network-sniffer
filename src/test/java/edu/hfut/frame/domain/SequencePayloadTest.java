package edu.hfut.frame.domain;

import java.util.TreeSet;

import org.junit.Assert;
import org.junit.Test;

public class SequencePayloadTest {

	@Test
	public void testSuccessConcat1() {
		TreeSet<SequencePayload> payloads = new TreeSet<>();
		payloads.add(new SequencePayload(1L, new byte[] { 0x01, 0x02, 0x03 }));
		payloads.add(new SequencePayload(4L, new byte[] { 0x04, 0x05, 0x06 }));
		payloads.add(new SequencePayload(7L, new byte[] { 0x07, 0x08, 0x09 }));
		SequencePayload total = SequencePayload.concat(payloads);
		Assert.assertEquals(total, new SequencePayload(1L, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09 }));
		Assert.assertArrayEquals(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 },
				total.getPayload());
		payloads.clear();
		payloads.add(new SequencePayload(10L, new byte[] { 0x10 }));
		payloads.add(total);
		SequencePayload total2 = SequencePayload.concat(payloads);
		Assert.assertEquals(total2, new SequencePayload(1L, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x10 }));
		Assert.assertArrayEquals(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10 },
				total2.getPayload());

	}

	@Test
	public void testSuccessConcat2() {
		TreeSet<SequencePayload> payloads = new TreeSet<>();
		payloads.add(new SequencePayload(1L, new byte[] { 0x01, 0x02, 0x03 }));
		payloads.add(new SequencePayload(4L, new byte[] { 0x04, 0x05, 0x06 }));
		payloads.add(new SequencePayload(4L, new byte[] { 0x04, 0x05, 0x06 }));
		payloads.add(new SequencePayload(7L, new byte[] { 0x07, 0x08, 0x09 }));
		SequencePayload total = SequencePayload.concat(payloads);
		Assert.assertEquals(total, new SequencePayload(1L, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09 }));
		Assert.assertArrayEquals(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 },
				total.getPayload());
	}

	@Test
	public void testFailConcat3() {
		TreeSet<SequencePayload> payloads = new TreeSet<>();
		payloads.add(new SequencePayload(1L, new byte[] { 0x01, 0x02, 0x03 }));
		payloads.add(new SequencePayload(4L, new byte[] { 0x04, 0x05, 0x06 }));
		payloads.add(new SequencePayload(3L, new byte[] { 0x04, 0x05, 0x06 }));
		payloads.add(new SequencePayload(7L, new byte[] { 0x07, 0x08, 0x09 }));
		SequencePayload total = SequencePayload.concat(payloads);
		Assert.assertEquals(total, new SequencePayload(1L, new byte[0]));
	}


}
