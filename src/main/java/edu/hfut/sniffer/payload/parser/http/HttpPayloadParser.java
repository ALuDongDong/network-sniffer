package edu.hfut.sniffer.payload.parser.http;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.hfut.frame.domain.Frame;
import edu.hfut.sniffer.parser.domain.ProcessStatus;
import edu.hfut.sniffer.parser.domain.TcpDirection;
import edu.hfut.sniffer.parser.domain.TcpSessionKey;
import edu.hfut.sniffer.parser.domain.TcpSessionKeyImpl;
import edu.hfut.sniffer.payload.parser.IPayloadParser;

/**
 * http协议负载解析
 * @author donglei
 * @date: 2016年5月4日 下午4:30:18
 */
public class HttpPayloadParser implements IPayloadParser {

	private static final Logger logger = LoggerFactory.getLogger(HttpPayloadParser.class);

	public static final int HTTP_PORT_1 = 80;
	public static final int HTTP_PORT_2 = 8080;
	public static final String HEADER_PREFIX = "header_";

	private HttpDecoder decoder;

	public HttpPayloadParser() {
		this.decoder = new HttpDecoder();
	}

	@Override
	public ProcessStatus processPacketPayload(Frame frame, byte[] payload) {

		try {
			TcpSessionKey sessionKey = new TcpSessionKeyImpl(InetAddress.getByName(frame.getSrcIp()),
					InetAddress.getByName(frame.getDesIp()), frame.getSrcPort(), frame.getDesPort());
			TcpDirection direction = getDirection(frame, payload);
			if (direction == TcpDirection.ToClient) {
				return this.decoder.handleRx(sessionKey, payload, frame.getTimestamp());
			} else {
				return this.decoder.handleTx(sessionKey, payload, frame.getTimestamp());
			}

		} catch (UnknownHostException e) {
			logger.error(e.getMessage());
		}
		return ProcessStatus.ERROR;
	}

	public TcpDirection getDirection(Frame frame, byte[] payload) {
		byte[] codes = new byte[4];
		System.arraycopy(payload, 0, codes, 0, 4);
		String code = new String(codes);
		if (code.matches("HTTP")) {
			return TcpDirection.ToClient;
		} else if (HttpMethod.parse(code) != null) {
			return TcpDirection.ToServer;
		}
		return null;
	}

}
