package edu.hfut.sniffer.payload.smtp.parser;

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
 * SMTP协议负载解析
 * @author donglei
 * @date: 2016年8月19日 下午4:30:18
 */
public class SmtpPayloadParser implements IPayloadParser {

	private static final Logger logger = LoggerFactory.getLogger(SmtpPayloadParser.class);

	private static final int SMTP_PORT_1 = 25;
	private static final int SMTP_PORT_2 = 587;

	private SmtpDecoder smtpDecoder;

	public SmtpPayloadParser() {
		this.smtpDecoder = new SmtpDecoder();
	}

	@Override
	public ProcessStatus processPacketPayload(Frame frame, byte[] payload) {
		try {
			TcpSessionKey sessionKey = new TcpSessionKeyImpl(InetAddress.getByName(frame.getSrcIp()),
					InetAddress.getByName(frame.getDesIp()), frame.getSrcPort(), frame.getDesPort());
			TcpDirection direction = getDirection(frame, payload);
			if (direction == TcpDirection.ToClient) {
				return this.smtpDecoder.handleRx(sessionKey, payload, frame.getTimestamp());
			} else {
				return this.smtpDecoder.handleTx(sessionKey, payload, frame.getTimestamp());
			}

		} catch (UnknownHostException e) {
			logger.error(e.getMessage());
		}
		return ProcessStatus.ERROR;
	}

	public TcpDirection getDirection(Frame frame, byte[] payload) {
		if (frame.getSrcPort() == SMTP_PORT_1 || frame.getSrcPort() == SMTP_PORT_2) {
			return TcpDirection.ToClient;
		} else {
			return TcpDirection.ToServer;
		}
	}

}
