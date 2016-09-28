package edu.hfut.sniffer.payload.pop3.parser;

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
 * POP3协议负载解析
 * @author donglei
 * @date: 2016年8月19日 下午4:30:18
 */
public class Pop3PayloadParser implements IPayloadParser {

	private static final Logger logger = LoggerFactory.getLogger(Pop3PayloadParser.class);

	private static final int POP3_PORT = 110;

	private Pop3Decoder pop3Decoder;


	public Pop3PayloadParser() {
		this.pop3Decoder = new Pop3Decoder();
	}

	@Override
	public ProcessStatus processPacketPayload(Frame frame, byte[] payload) {
		try {
			TcpSessionKey sessionKey = new TcpSessionKeyImpl(InetAddress.getByName(frame.getSrcIp()),
					InetAddress.getByName(frame.getDesIp()), frame.getSrcPort(), frame.getDesPort());
			TcpDirection direction = getDirection(frame, payload);
			if (direction == TcpDirection.ToClient) {
				return this.pop3Decoder.handleRx(sessionKey, payload, frame.getTimestamp());
			} else {
				return this.pop3Decoder.handleTx(sessionKey, payload, frame.getTimestamp());
			}

		} catch (UnknownHostException e) {
			logger.error(e.getMessage());
		}
		return ProcessStatus.ERROR;
	}

	public TcpDirection getDirection(Frame frame, byte[] payload) {
		if (frame.getSrcPort() == POP3_PORT) {
			return TcpDirection.ToClient;
		} else {
			return TcpDirection.ToServer;
		}
	}

}
