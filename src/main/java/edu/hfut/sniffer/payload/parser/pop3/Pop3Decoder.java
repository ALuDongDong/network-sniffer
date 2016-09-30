package edu.hfut.sniffer.payload.parser.pop3;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.BufferUnderflowException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.hfut.sniffer.parser.domain.Buffer;
import edu.hfut.sniffer.parser.domain.ChainBuffer;
import edu.hfut.sniffer.parser.domain.ProcessStatus;
import edu.hfut.sniffer.parser.domain.TcpSessionKey;
import edu.hfut.sniffer.parser.util.Configs;
import edu.hfut.sniffer.payload.mail.parser.MailData;
import edu.hfut.sniffer.payload.mail.parser.MailDataImpl;
import edu.hfut.sniffer.payload.parser.TcpProcessor;

/**
 * @author donglei
 */
public class Pop3Decoder implements TcpProcessor {

	private Logger logger = LoggerFactory.getLogger(Pop3Decoder.class.getName());

	private Map<TcpSessionKey, Pop3Session> sessionMap;

	public Pop3Decoder() {
		sessionMap = new HashMap<TcpSessionKey, Pop3Session>();
	}

	@Override
	public ProcessStatus handleTx(TcpSessionKey sessionKey, byte[] data, long timestamp) {
		Pop3Session session = sessionMap.get(sessionKey);
		Buffer payload = new ChainBuffer();
		payload.addLast(data);
		if (session == null) {
			session = new Pop3Session();
			this.sessionMap.put(sessionKey, session);
		}
		return parseTx(sessionKey, session, payload);
	}

	@Override
	public ProcessStatus handleRx(TcpSessionKey sessionKey, byte[] data, long timestamp) {
		Buffer payload = new ChainBuffer();
		payload.addLast(data);
		Pop3Session session = sessionMap.get(sessionKey);
		if (session == null) {
			session = new Pop3Session();
			this.sessionMap.put(sessionKey, session);
		}
		return parseRx(sessionKey, session, payload);
	}

	private ProcessStatus parseTx(TcpSessionKey sessionKey, Pop3Session session, Buffer txBuffer) {
		try {
			int len = txBuffer.bytesBefore(new byte[] { 0x0d, 0x0a });
			if (len == 0) {
				return ProcessStatus.ERROR;
			}

			byte[] t = new byte[len];
			txBuffer.gets(t, 0, t.length);
			/* skip \r\n */
			txBuffer.get();
			txBuffer.get();

			String command = new String(t);
			handleCommand(command, session, txBuffer);
		} catch (BufferUnderflowException e) {
			txBuffer.reset();
			return ProcessStatus.ERROR;
		}
		return ProcessStatus.OK;
	}

	private ProcessStatus parseRx(TcpSessionKey sessionKey, Pop3Session session, Buffer rxBuffer) {
		switch (session.getState()) {
			case NONE:
				try {
					int len = rxBuffer.bytesBefore(new byte[] { 0x0d, 0x0a });
					if (len == 0) {
						return ProcessStatus.ERROR;
					}

					byte[] t = new byte[len];
					rxBuffer.gets(t, 0, t.length);
					/* skip \r\n */
					rxBuffer.get();
					rxBuffer.get();

					String response = new String(t);
					logger.info("Pop3 response is {}", response);
					return ProcessStatus.OK;
				} catch (BufferUnderflowException e) {
					rxBuffer.reset();
					return ProcessStatus.ERROR;
				}

			case FIND_UIDL:
			case FIND_LIST:
				try {
					int len = rxBuffer.bytesBefore(new byte[] { 0x0d, 0x0a, 0x2e, 0x0d, 0x0a });
					if (len == 0) {
						return ProcessStatus.ERROR;
					}

					byte[] t = new byte[len + 5];
					rxBuffer.gets(t, 0, t.length);
					logger.info("Pop3 response is {}", new String(t));
					return ProcessStatus.OK;
				} catch (BufferUnderflowException e) {
					rxBuffer.reset();
					return ProcessStatus.ERROR;
				}

			case FIND_TOP:
				return ProcessStatus.OK;

			case FIND_RETR:
				if (!session.isSkipRETRMessage()) {
					/* skip response message */
					try {
						int len = rxBuffer.bytesBefore(new byte[] { 0x0d, 0x0a });
						if (len == 0) {
							return ProcessStatus.ERROR;
						}

						byte[] t = new byte[len + 2];
						rxBuffer.gets(t, 0, t.length);
						session.setSkipRETRMessage(true);
					} catch (BufferUnderflowException e) {
						rxBuffer.reset();
						return ProcessStatus.ERROR;
					}
					return ProcessStatus.OK;
				}

				else {
					if (!session.isRemarkStart()) {
						/* record start point of e-mail */
						session.setRemarkStart(true);
					}
					int length = rxBuffer.bytesBefore(new byte[] { 0x0d, 0x0a, 0x2e, 0x0d, 0x0a });
					if (length == 0) {
						return ProcessStatus.MORE;
					}
					byte[] emailData = new byte[length];
					rxBuffer.gets(emailData, 0, length);

					MimeMessage msg = createMimeMessage(emailData);
					//					MimeHeader header = new MimeHeader();
					//					Charset headerCharset = header.getHeaderCharset(msg);
					//					header.decodeHeader(headerCharset, emailData);

					MailData pop3Data = new MailDataImpl(msg);
					//					getMessage(header, pop3Data);
					saveFile(sessionKey, pop3Data);

					/* skip 'CRLF.CRLF' */
					byte[] t = new byte[5];
					rxBuffer.gets(t, 0, t.length);

					/* initialize e-mail variables */
					session.setRemarkStart(false);
					session.setSkipRETRMessage(false);

					/* deallocate and reallocate */
					session.clear();
					session.setState(Pop3State.NONE);
					return ProcessStatus.OK;
				}
			case FIND_DELE:
				/* skip '+OK' */
				byte[] msg = new byte[6];
				rxBuffer.gets(msg);
				break;
		}
		return ProcessStatus.OK;
	}

	private void handleCommand(String command, Pop3Session session, Buffer txBuffer) {
		if (command.equalsIgnoreCase("UIDL")) {
			session.setState(Pop3State.FIND_UIDL);
		} else if (command.equalsIgnoreCase("LIST")) {
			session.setState(Pop3State.FIND_LIST);
		} else if (command.length() > 4 && command.substring(0, 3).equalsIgnoreCase("TOP")) {
			session.setState(Pop3State.FIND_TOP);
		} else if (command.length() > 5 && command.substring(0, 4).equalsIgnoreCase("RETR")) {
			session.setState(Pop3State.FIND_RETR);
		} else if (command.length() > 5 && command.substring(0, 4).equalsIgnoreCase("DELE")) {
			session.setState(Pop3State.FIND_DELE);
		} else if (session.getState().compareTo(Pop3State.FIND_TOP) == 0) {
			session.setState(Pop3State.NONE);
		}
	}

	private MimeMessage createMimeMessage(byte[] data) {
		Session mailSession = Session.getDefaultInstance(new Properties());
		InputStream is = new ByteArrayInputStream(data, 0, data.length);

		try {
			return new MimeMessage(mailSession, is);
		} catch (MessagingException e) {
			logger.error("pop3 decoder: mime parse error" + e);
		}
		return null;
	}

	private void saveFile(TcpSessionKey sessionKey, MailData pop3Data) {
		String path = Configs.getProps(Configs.OUTPUT_DIR);
		Set<String> attachNames = pop3Data.getAttachmentNames();
		for (String attachname : attachNames) {
			String fileName = sessionKey.getClientIp().getHostAddress() + "_"
					+ sessionKey.getServerIp().getHostAddress() + "_" + System.currentTimeMillis() + "_POP3_"
					+ attachname;
			try (FileOutputStream outputStream = new FileOutputStream(new File(path + File.separator + fileName))) {
				byte[] data = new byte[1024];
				try (InputStream inputStream = pop3Data.getAttachment(attachname)) {
					int count = inputStream.read(data);
					while (count > 0) {
						outputStream.write(data, 0, count);
						count = inputStream.read(data);
					}
				} catch (IllegalStateException | IOException e) {
					e.printStackTrace();
				}
			} catch (Exception e) {
				logger.error("exception has throwed when saved to DB. case {}", e.getMessage());
			}
		}

	}

}