package edu.hfut.sniffer.payload.parser.ftp;

import java.io.File;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import edu.hfut.sniffer.parser.core.TcpProtocolMapper;
import edu.hfut.sniffer.parser.domain.Buffer;
import edu.hfut.sniffer.parser.domain.Protocol;
import edu.hfut.sniffer.parser.domain.TcpSessionKey;
import edu.hfut.sniffer.parser.domain.TcpSessionKeyImpl;
import edu.hfut.sniffer.parser.util.Configs;

/**
 * @author donglei
 */
public class FtpDecoder {

	private Logger logger = LoggerFactory.getLogger(FtpDecoder.class.getName());
	private Map<TcpSessionKey, FtpSession> sessionMap;
	private final TcpProtocolMapper mapper;

	private BiMap<TcpSessionKey, TcpSessionKey> dataToControlMap;

	public FtpDecoder(TcpProtocolMapper mapper) {
		this.sessionMap = new HashMap<>();
		this.dataToControlMap = HashBiMap.create();
		this.mapper = mapper;
	}

	public void handleData(TcpSessionKey sessionKey, Buffer data, long timestamp) {
		FtpSession session = this.sessionMap.get(sessionKey);
		if (session == null && !this.dataToControlMap.containsKey(sessionKey)) {
			session = new FtpSession();
			this.sessionMap.put(sessionKey, session);
		} else if (this.dataToControlMap.containsKey(sessionKey)) {
			TcpSessionKey controlSessionKey = this.dataToControlMap.get(sessionKey);
			FtpSession controlSession = this.sessionMap.get(controlSessionKey);
			controlSession.getDataSession().putData(data);
			return;
		}
		handleCommandSession(sessionKey, session, data, timestamp);
	}

	private void handleCommandSession(TcpSessionKey key, FtpSession session, Buffer buffer, long timestamp) {
		while (true) {
			if (buffer.isEOB()) {
				break;
			}
			int length = buffer.bytesBefore(new byte[] { 0x0d, 0x0a });
			if (length == 0) {
				return;
			}

			byte[] codes = new byte[4];
			buffer.mark();
			buffer.gets(codes, 0, 4);
			buffer.reset();

			String code = new String(codes);
			if (code.matches("\\d{3} ")) {
				byte[] reply = new byte[length];
				buffer.gets(reply, 0, length);
				/* skip \r\n */
				buffer.get();
				buffer.get();
				//				dispatchReply(new String(reply));

				if (code.equals("227 ")) {
					/* passive mode */
					String replyStr = new String(reply);
					String[] token = replyStr.split(" ");
					TcpSessionKey passive = new TcpSessionKeyImpl(key.getClientIp(), key.getServerIp(), getPort(token),
							key.getServerPort());
					mapper.register(passive, Protocol.FTP);
				}

				else if (code.equals("226 ") || code.equals("250 ")) {
					/* get attached file */
					if (session.getFileName() != "") {
						Buffer data = this.sessionMap.get(key).getDataSession().getData();
						saveFile(data, key.getClientIp().getHostAddress() + "_" + key.getServerIp().getHostAddress()
								+ "_" + timestamp + "_FTP_" + session.getFileName());
						initSession();
					}
				}
			}

			else {
				byte[] command = new byte[length];
				buffer.gets(command, 0, length);
				/* 跳过 \r\n */
				buffer.get();
				buffer.get();
				String commandStr = new String(command);

				if (code.equalsIgnoreCase("STOR") || code.equalsIgnoreCase("RETR")) {
					String fileName = commandStr.split(" ")[1].replaceAll("\r\n", "");
					session.setFileName(fileName);
				} else if (code.equalsIgnoreCase("PORT")) {
					/* 主动模式 - 注册端口 */
					String[] token = commandStr.split(" ");
					TcpSessionKey activePort = new TcpSessionKeyImpl(key.getClientIp(), key.getServerIp(),
							getPort(token), 20);
					mapper.register(activePort, Protocol.FTP);
					this.dataToControlMap.put(activePort, key);

				}
			}
		}
	}

	private int getPort(String[] token) {
		String[] portCommand = token[token.length - 1].replaceAll("[()]\\.", "").split(",");
		int port = (Integer.parseInt(portCommand[4]) * 256) + Integer.parseInt(portCommand[5].replaceAll("\r\n", ""));
		return port;
	}

	private void initSession() {

	}

	private void saveFile(Buffer buffer, String fileName) {
		String path = Configs.getProps(Configs.OUTPUT_DIR);
		byte[] data = new byte[1024];
		try (FileOutputStream outputStream = new FileOutputStream(new File(path + File.separator + fileName))) {
			while (buffer.readableBytes() > 1024) {
				buffer.gets(data);
				outputStream.write(data);
			}
			if (buffer.readableBytes() > 0) {
				int size = buffer.readableBytes();
				buffer.gets(data, 0, size);
				outputStream.write(data, 0, size);
			}
		} catch (Exception e) {
			logger.error("exception has throwed when saved to DB. case {}", e.getMessage());
		}
	}

}
