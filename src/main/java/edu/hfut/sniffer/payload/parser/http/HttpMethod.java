package edu.hfut.sniffer.payload.parser.http;

/**
 * @author donglei
 */
public enum HttpMethod {
	OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT;

	public static HttpMethod parse(String a) {
		switch (a) {
			case "OPTI":
				return OPTIONS;
			case "GET ":
				return GET;
			case "HEAD":
				return HEAD;
			case "POST":
				return POST;
			case "PUT ":
				return PUT;
			case "DELE":
				return DELETE;
			case "TRAC":
				return TRACE;
			case "CONN":
				return CONNECT;
			default:
				return null;
		}
	}
};