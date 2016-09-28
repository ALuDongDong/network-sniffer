package edu.hfut.sniffer.parser.core;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.hfut.frame.domain.Frame;
import edu.hfut.sniffer.parser.domain.Protocol;
import edu.hfut.sniffer.parser.domain.TcpSessionKey;
import edu.hfut.sniffer.parser.domain.TcpSessionKeyImpl;
import edu.hfut.sniffer.parser.util.LogbackUtil;
import edu.hfut.sniffer.payload.parser.IPayloadParser;

public class TcpProtocolMapper {

	private static final Logger logger = LoggerFactory.getLogger(TcpProtocolMapper.class);

	private ConcurrentMap<Integer, Protocol> tcpMap;
	private ConcurrentMap<TcpSessionKey, Protocol> temporaryTcpMap;
	private ConcurrentMap<Protocol, Set<IPayloadParser>> tcpProcessorMap;

	public TcpProtocolMapper() {
		tcpMap = new ConcurrentHashMap<Integer, Protocol>();
		temporaryTcpMap = new ConcurrentHashMap<TcpSessionKey, Protocol>();
		tcpProcessorMap = new ConcurrentHashMap<Protocol, Set<IPayloadParser>>();

		tcpMap.put(80, Protocol.HTTP);
		tcpMap.put(8080, Protocol.HTTP);
		tcpMap.put(25, Protocol.SMTP);
		tcpMap.put(587, Protocol.SMTP);
		tcpMap.put(110, Protocol.POP3);
		tcpMap.put(1863, Protocol.MSN);
		tcpMap.put(21, Protocol.FTP);
		tcpMap.put(138, Protocol.NETBIOS);
		tcpMap.put(139, Protocol.NETBIOS);
		tcpMap.put(445, Protocol.NETBIOS);
		tcpMap.put(22, Protocol.SSH);
		tcpMap.put(23, Protocol.TELNET);
		tcpMap.put(43, Protocol.WHOIS);
		tcpMap.put(53, Protocol.DNS);
		tcpMap.put(66, Protocol.SQLNET);
		tcpMap.put(79, Protocol.FINGER);
		tcpMap.put(143, Protocol.IMAP);
		tcpMap.put(179, Protocol.BGP);
		tcpMap.put(1433, Protocol.MSSQL);
		tcpMap.put(1434, Protocol.MSSQL);
		tcpMap.put(3306, Protocol.MYSQL);
		tcpMap.put(5432, Protocol.POSTGRES);
	}

	public void register(int port, Protocol protocol) {
		tcpMap.put(port, protocol);
	}

	public void unregister(int port) {
		if (tcpMap.containsKey(port)) {
			tcpMap.remove(port);
		}
	}

	public void register(TcpSessionKey sockAddr, Protocol protocol) {
		temporaryTcpMap.put(sockAddr, protocol);
	}

	public void unregister(TcpSessionKey sockAddr) {
		if (temporaryTcpMap.containsKey(sockAddr)) {
			temporaryTcpMap.remove(sockAddr);
		}
	}

	public void register(Protocol protocol, IPayloadParser processor) {
		tcpProcessorMap.putIfAbsent(protocol,
				Collections.newSetFromMap(new ConcurrentHashMap<IPayloadParser, Boolean>()));
		tcpProcessorMap.get(protocol).add(processor);
	}

	public void unregister(Protocol protocol, IPayloadParser processor) {
		tcpProcessorMap.putIfAbsent(protocol,
				Collections.newSetFromMap(new ConcurrentHashMap<IPayloadParser, Boolean>()));
		tcpProcessorMap.get(protocol).remove(processor);
	}

	public Protocol map(Frame frame) {
		Protocol result = null;
		try {
			TcpSessionKey sessionKey = new TcpSessionKeyImpl(InetAddress.getByName(frame.getSrcIp()),
					InetAddress.getByName(frame.getDesIp()), frame.getSrcPort(), frame.getDesPort());
			result = this.temporaryTcpMap.get(sessionKey);
			if (result != null) {
				return result;
			}
		} catch (UnknownHostException e) {
			logger.error(LogbackUtil.expection2Str(e));
		}
		int srcPort = frame.getSrcPort();
		int desPort = frame.getDesPort();
		Protocol srcProtocol = tcpMap.get(srcPort);
		Protocol desProtocol = tcpMap.get(desPort);
		if (srcProtocol != null) {
			result = srcProtocol;
		}
		if (desProtocol != null) {
			if (result != null) {
				logger.error("Multiple protocol maps, can't decide the right protocol. srcPort = {}, desPort = {}",
						srcPort, desPort);
				return null;
			}
			result = desProtocol;
		}
		return result;
	}

	public Collection<IPayloadParser> getTcpProcessors(Protocol protocol) {
		if (protocol == null) {
			return null;
		}

		if (tcpProcessorMap.containsKey(protocol)) {
			Set<IPayloadParser> processors = tcpProcessorMap.get(protocol);
			if (processors.size() > 0) {
				return processors;
			}
		}
		return null;
	}

}