package edu.hfut.sniffer.parser.core;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import edu.hfut.frame.domain.Frame;
import edu.hfut.frame.reader.PcapReader;
import edu.hfut.sniffer.parser.util.Configs;

public class ParserCoreTest {

	//	private static final String TEST_HTTP = "src/test/resources/http.pcap";
	private static final String TEST_HTTP = "src/test/resources/http_multi.pcap";
	private static final String TEST_HTTPGZIP = "src/test/resources/http_gzip.pcap";
	private static final String TEST_POP3 = "src/test/resources/pop_attach.pcap";
	private static final String TEST_SMTP = "src/test/resources/smtp_attach.pcap";
	private static final String TEST_SMTP2 = "src/test/resources/smtp_attach2.pcap";
	private static final String TEST_IMAP1 = "src/test/resources/imap_pure.pcap";
	private static final String TEST_IMAP2 = "src/test/resources/imap_2fujian.pcap";
	private static final String TEST_FTP = "src/test/resources/ftp_one.pcap";

	private ParserCore parser;

	@Before
	public void init() {
		parser = new ParserCore();
		String path = Configs.getProps(Configs.OUTPUT_DIR);
		File file = new File(path);
		if (!file.exists()) {
			file.mkdirs();
		}
	}

	@Test
	public void testHttp() throws FileNotFoundException, IOException {
		PcapReader reader = new PcapReader(new DataInputStream(new FileInputStream(TEST_HTTP)));
		int i = 1;
		for (Frame frame : reader) {
			System.out.println(i);
			parser.parse(frame);
			i++;
		}
	}

	@Test
	public void testHttpGzip() throws FileNotFoundException, IOException {
		PcapReader reader = new PcapReader(new DataInputStream(new FileInputStream(TEST_HTTPGZIP)));
		int i = 1;
		for (Frame frame : reader) {
			System.out.println(i);
			parser.parse(frame);
			i++;
		}
	}

	@Test
	public void testFTP() throws FileNotFoundException, IOException {
		PcapReader reader = new PcapReader(new DataInputStream(new FileInputStream(TEST_FTP)));
		int i = 1;
		for (Frame frame : reader) {
			System.out.println(i);
			parser.parse(frame);
			i++;
		}
	}

	@Test
	public void testPop3() throws FileNotFoundException, IOException {
		PcapReader reader = new PcapReader(new DataInputStream(new FileInputStream(TEST_POP3)));
		int i = 1;
		for (Frame frame : reader) {
			System.out.println(i);
			parser.parse(frame);
			i++;
		}
	}

	@Test
	public void testSmtp() throws FileNotFoundException, IOException {
		PcapReader reader = new PcapReader(new DataInputStream(new FileInputStream(TEST_SMTP)));
		int i = 1;
		for (Frame frame : reader) {
			System.out.println(i);
			parser.parse(frame);
			i++;
		}
	}

	@Test
	public void testSmtp2() throws FileNotFoundException, IOException {
		PcapReader reader = new PcapReader(new DataInputStream(new FileInputStream(TEST_SMTP2)));
		int i = 1;
		for (Frame frame : reader) {
			//			System.out.println(i);
			parser.parse(frame);
			i++;
		}
	}

	@Test
	public void testImap1() throws FileNotFoundException, IOException {
		PcapReader reader = new PcapReader(new DataInputStream(new FileInputStream(TEST_IMAP1)));
		int i = 1;
		for (Frame frame : reader) {
			System.out.println(i);
			parser.parse(frame);
			i++;
		}
	}

	@Test
	public void testImap2() throws FileNotFoundException, IOException {
		PcapReader reader = new PcapReader(new DataInputStream(new FileInputStream(TEST_IMAP2)));
		int i = 1;
		for (Frame frame : reader) {
			System.out.println(i);
			parser.parse(frame);
			i++;
		}
	}


}
