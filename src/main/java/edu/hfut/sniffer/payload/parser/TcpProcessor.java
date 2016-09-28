package edu.hfut.sniffer.payload.parser;

import edu.hfut.sniffer.parser.domain.ProcessStatus;
import edu.hfut.sniffer.parser.domain.TcpSessionKey;

/**
 * @author donglei
 */
public interface TcpProcessor {

	ProcessStatus handleTx(TcpSessionKey session, byte[] data, long timestamp);

	ProcessStatus handleRx(TcpSessionKey session, byte[] data, long timestamp);
}
