package edu.hfut.sniffer.payload.parser.imap;

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
public class ImapPayloadParser implements IPayloadParser {

	private static final Logger logger = LoggerFactory.getLogger(ImapPayloadParser.class);

	private static final int IMAP_PORT = 143;

	private ImapDecoder imapDecoder;

	public ImapPayloadParser() {
		this.imapDecoder = new ImapDecoder();
	}

	@Override
	public ProcessStatus processPacketPayload(Frame frame, byte[] payload) {
		try {
			TcpSessionKey sessionKey = new TcpSessionKeyImpl(InetAddress.getByName(frame.getSrcIp()),
					InetAddress.getByName(frame.getDesIp()), frame.getSrcPort(), frame.getDesPort());
			TcpDirection direction = getDirection(frame, payload);
			if (direction == TcpDirection.ToClient) {
				return this.imapDecoder.handleRx(sessionKey, payload, frame.getTimestamp());
			} else {
				return this.imapDecoder.handleTx(sessionKey, payload, frame.getTimestamp());
			}

		} catch (UnknownHostException e) {
			logger.error(e.getMessage());
		}
		return ProcessStatus.ERROR;
	}

	public TcpDirection getDirection(Frame frame, byte[] payload) {
		if (frame.getSrcPort() == IMAP_PORT) {
			return TcpDirection.ToClient;
		} else {
			return TcpDirection.ToServer;
		}
	}

}
