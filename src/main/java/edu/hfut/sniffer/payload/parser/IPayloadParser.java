package edu.hfut.sniffer.payload.parser;

import edu.hfut.frame.domain.Frame;
import edu.hfut.sniffer.parser.domain.ProcessStatus;

/**
 * 抽象的协议层负载解析
 * @author donglei
 * @date: 2016年5月4日 下午4:10:57
 */
public interface IPayloadParser {

	public ProcessStatus processPacketPayload(Frame frame, byte[] payload);

}
