package edu.hfut.sniffer.parser.domain;

import java.net.InetAddress;

/**
 * The structure for identifying the specific TCP session.
 *
 * @author mindori
 */
public interface TcpSessionKey {

	InetAddress getClientIp();

	InetAddress getServerIp();

	int getClientPort();

	int getServerPort();
}
