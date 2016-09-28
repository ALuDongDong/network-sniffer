package edu.hfut.sniffer.common;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Assert;
import org.junit.Test;

public class MatcherTest {

	@Test
	public void testMatcher() {
		Pattern pattern = Pattern.compile(".*FETCH.*BODY.*");
		Matcher m = pattern.matcher("Line: C9 UID FETCH 1320389380 (UID BODY.PEEK[])\r\n");
		Assert.assertTrue(m.find());
	}

	@Test
	public void testByte() {
		String a = "C9 OK Fetch completed\r\n";
		System.out.println(a.getBytes().length);

		for (byte b : a.getBytes()) {
			System.out.print(b + " ");
		}
	}

}
