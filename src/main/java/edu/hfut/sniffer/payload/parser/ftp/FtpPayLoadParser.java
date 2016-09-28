package edu.hfut.sniffer.payload.parser.ftp;

import java.net.InetAddress;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.hfut.frame.domain.Frame;
import edu.hfut.sniffer.parser.core.TcpProtocolMapper;
import edu.hfut.sniffer.parser.domain.Buffer;
import edu.hfut.sniffer.parser.domain.ChainBuffer;
import edu.hfut.sniffer.parser.domain.ProcessStatus;
import edu.hfut.sniffer.parser.domain.TcpSessionKey;
import edu.hfut.sniffer.parser.domain.TcpSessionKeyImpl;
import edu.hfut.sniffer.payload.parser.IPayloadParser;

/**
 * FTP协议负载解析
 * @author donglei
 * @date: 2016年5月15日 下午8:49:40
 */
public class FtpPayLoadParser implements IPayloadParser {

	private static final Logger logger = LoggerFactory.getLogger(FtpPayLoadParser.class);

	private FtpDecoder processor;

	public FtpPayLoadParser(TcpProtocolMapper mapper) {
		this.processor = new FtpDecoder(mapper);
	}

	@Override
	public ProcessStatus processPacketPayload(Frame frame, byte[] payload) {
		try {
			TcpSessionKey key = new TcpSessionKeyImpl(InetAddress.getByName(frame.getSrcIp()),
					InetAddress.getByName(frame.getDesIp()), frame.getSrcPort(), frame.getDesPort());
			this.processor.handleData(key, pack(payload), frame.getTimestamp());
			return ProcessStatus.OK;
		} catch (Exception e) {
			logger.info(e.getMessage());
		}
		return ProcessStatus.ERROR;
	}

	public Buffer pack(byte[] data) {
		Buffer payload = new ChainBuffer();
		payload.addLast(data);
		return payload;
	}

}
