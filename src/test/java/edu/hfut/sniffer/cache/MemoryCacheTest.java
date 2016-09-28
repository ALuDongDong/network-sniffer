package edu.hfut.sniffer.cache;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Test;

import com.google.common.primitives.Bytes;

import edu.hfut.frame.domain.Flow;
import edu.hfut.frame.domain.SequencePayload;

public class MemoryCacheTest {

	@Test
	public void testBasic() throws ExecutionException {
		MemoryCache<String, Integer> cache = new MemoryCache<>();
		cache.add("1", 1);
		cache.add("1", 3);
		cache.add("1", 2);
		StringBuilder sb = new StringBuilder();
		for (Integer i : cache.members("1")) {
			sb.append(i + "");
		}
		Assert.assertEquals("123", sb.toString());
	}

	@Test
	public void testSeq() throws ExecutionException {
		MemoryCache<Flow, SequencePayload> cache = new MemoryCache<>();
		Flow flow = new Flow("192.168.6.129", 34534, "192.168.6.127", 80, "HTTP");
		cache.add(flow, new SequencePayload(1L, new byte[] { (byte) 0x01 }));
		cache.add(flow, new SequencePayload(2L, new byte[] { (byte) 0x02 }));
		cache.add(flow, new SequencePayload(3L, new byte[] { (byte) 0x03 }));
		byte[] data = new byte[0];
		for (SequencePayload seq : cache.members(flow)) {
			data = Bytes.concat(data, seq.getPayload());
		}
		Assert.assertArrayEquals(new byte[] { 0x01, 0x02, 0x03 }, data);
	}

	@Test
	public void testRepeat() throws ExecutionException {
		MemoryCache<Flow, SequencePayload> cache = new MemoryCache<>();
		Flow flow = new Flow("192.168.6.129", 34534, "192.168.6.127", 80, "HTTP");
		cache.add(flow, new SequencePayload(1L, new byte[] { (byte) 0x01 }));
		cache.add(flow, new SequencePayload(1L, new byte[] { (byte) 0x02 }));
		cache.add(flow, new SequencePayload(1L, new byte[] { (byte) 0x03 }));
		Assert.assertEquals(new SequencePayload(1L, new byte[] { (byte) 0x01 }), cache.members(flow).first());
	}

	@Test
	public void testFlow() throws InterruptedException, ExecutionException {
		Flow flow = new Flow("192.168.6.129", 34534, "192.168.6.127", 80, "HTTP");
		System.out.println(flow.hashCode());
		Flow flow2 = new Flow("192.168.6.129", 34534, "192.168.6.127", 80, "HTTP");
		System.out.println(flow2.hashCode());
		Flow flow3 = new Flow("192.168.6.129", 34534, "192.168.6.127", 80, "HTTP");
		System.out.println(flow3.hashCode());
		System.out.println(flow.compareTo(flow2));
		System.out.println(flow2.compareTo(flow3));
		MemoryCache<Flow, Integer> cache = new MemoryCache<>();
		cache.add(flow, 1);
		cache.add(flow2, 2);
		cache.add(flow3, 3);
		int i = 0;
		for (int in : cache.invalidate(flow)) {
			Assert.assertEquals(i + 1, in);
			i++;
		}
	}

	@Test
	public void testTimeOut() throws ExecutionException, InterruptedException {
		MemoryCache<String, Integer> cache = new MemoryCache<>();
		cache.add("1", 1);
		cache.add("1", 2);
		cache.add("1", 3);

		TimeUnit.SECONDS.sleep(61);
		Assert.assertNull(cache.invalidate("1"));

		cache.add("2", 1);
		Assert.assertTrue(cache.members("2").size() == 1);
		cache.invalidate("2");
		Assert.assertNull(cache.members("2"));
	}



}
