package edu.hfut.sniffer.payload.parser.imap;

/**
 * @author donglei
 */
public class ImapSession {

	private String requestTag;

	private String request;

	private boolean isFetchBody;

	public ImapSession() {
	}

	public String getRequestTag() {
		return requestTag;
	}

	public void setRequestTag(String requestTag) {
		this.requestTag = requestTag;
	}

	public String getRequest() {
		return request;
	}

	public void setRequest(String request) {
		this.request = request;
	}

	public boolean isFetchBody() {
		return isFetchBody;
	}

	public void setFetchBody(boolean isFetchBody) {
		this.isFetchBody = isFetchBody;
	}

}