package edu.hfut.sniffer.payload.parser.ftp;

import edu.hfut.sniffer.parser.domain.Buffer;
import edu.hfut.sniffer.parser.domain.ChainBuffer;

/**
 * @author donglei
 */
public class FtpDataSession {
	private Buffer ftpData;

	public FtpDataSession() {
		ftpData = new ChainBuffer();
	}

	public Buffer getData() {
		return ftpData;
	}

	public void putData(Buffer data) {
		ftpData.addLast(data);
	}
}
