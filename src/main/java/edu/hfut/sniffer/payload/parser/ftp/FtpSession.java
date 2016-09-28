package edu.hfut.sniffer.payload.parser.ftp;


/**
 * @author donglei
 */
public class FtpSession {

	private String fileName;

	private FtpDataSession dataSession;

	public FtpSession() {
		this.fileName = "";
		this.dataSession = new FtpDataSession();
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public FtpDataSession getDataSession() {
		return dataSession;
	}

	public void setDataSession(FtpDataSession dataSession) {
		this.dataSession = dataSession;
	}

}
