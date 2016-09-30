package edu.hfut.sniffer.payload.parser.smtp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
public class SmtpDecoder implements TcpProcessor {

	private Logger logger = LoggerFactory.getLogger(SmtpDecoder.class.getName());

	private Map<TcpSessionKey, SmtpSession> sessionMap;

	public SmtpDecoder() {
		sessionMap = new HashMap<TcpSessionKey, SmtpSession>();
	}

	@Override
	public ProcessStatus handleTx(TcpSessionKey sessionKey, byte[] data, long timestamp) {
		Buffer payload = new ChainBuffer();
		payload.addLast(data);
		SmtpSession session = sessionMap.get(sessionKey);
		if (session == null) {
			session = new SmtpSession();
			this.sessionMap.put(sessionKey, session);
		}
		return handleTx(sessionKey, session, payload);
	}

	@Override
	public ProcessStatus handleRx(TcpSessionKey sessionKey, byte[] data, long timestamp) {
		Buffer payload = new ChainBuffer();
		payload.addLast(data);
		SmtpSession session = sessionMap.get(sessionKey);
		if (session == null) {
			session = new SmtpSession();
			this.sessionMap.put(sessionKey, session);
		}
		return handleRx(sessionKey, session, payload);
	}

	private ProcessStatus handleTx(TcpSessionKey sessionKey, SmtpSession session, Buffer buf) {
		if (session.isDataMode()) {
			return handleClientData(sessionKey, session, buf);
		} else {
			handleClientCommand(session, buf);
			session.resetTx();
			return ProcessStatus.OK;
		}

	}

	private ProcessStatus handleRx(TcpSessionKey sessionKey, SmtpSession session, Buffer buf) {
		handleReply(session, buf);
		session.resetRx();
		return ProcessStatus.OK;
	}

	private ProcessStatus handleClientData(TcpSessionKey sessionKey, SmtpSession session, Buffer txBuffer) {
		// store until find \r\n.\r\n
		int length = txBuffer.bytesBefore(new byte[] { 0x0d, 0x0a, 0x2e, 0x0d, 0x0a });
		if (length == 0) {
			return ProcessStatus.MORE;
		}

		session.setDataMode(false);
		byte[] emailData = new byte[length];
		txBuffer.gets(emailData, 0, length);

		MimeMessage msg = createMimeMessage(emailData);
		//		MimeHeader header = new MimeHeader();
		//		Charset headerCharset = header.getHeaderCharset(msg);
		//		header.decodeHeader(headerCharset, emailData);

		MailDataImpl smtpData = new MailDataImpl(msg);
		//		getMessage(header, smtpData);

		saveFile(sessionKey, smtpData);

		session.reset();
		return ProcessStatus.OK;
	}

	private void handleClientCommand(SmtpSession session, Buffer txBuffer) {
		while (true) {
			int length = txBuffer.bytesBefore(new byte[] { 0x0d, 0x0a });
			if (length == 0) {
				return;
			}

			byte[] b = new byte[length];
			txBuffer.gets(b, 0, length);
			/* skip \r\n */
			txBuffer.get();
			txBuffer.get();

			String command = new String(b);
			logger.info("Request is {}", command);
			if (command.equals("DATA")) {
				session.setDataMode(true);
				dispatchCommand(command, "");
				break;
			} else if (command.matches("\\w{4} .+")) {
				String parameter = command.substring(5);
				command = command.substring(0, 4);
				dispatchCommand(command, parameter);
			} else {
				/* don't have parameter(ex. QUIT) */
				dispatchCommand(command, "");
			}
		}
	}

	private void handleReply(SmtpSession session, Buffer rxBuffer) {
		while (true) {
			int length = rxBuffer.bytesBefore(new byte[] { 0x0d, 0x0a });
			if (length == 0) {
				return;
			}

			byte[] b = new byte[length];
			rxBuffer.gets(b, 0, length);
			/* skip \r\n */
			rxBuffer.get();
			rxBuffer.get();

			String reply = new String(b);
			logger.info("SMTP response is {}", reply);
			if (reply.matches("\\d{3}.+")) {
				int replyCode = Integer.parseInt(reply.substring(0, 3));
				dispatchReply(replyCode, reply.substring(4));
			}
		}
	}

	private MimeMessage createMimeMessage(byte[] data) {
		Session mailSession = Session.getDefaultInstance(new Properties());
		InputStream is = new ByteArrayInputStream(data, 0, data.length);

		try {
			return new MimeMessage(mailSession, is);
		} catch (MessagingException e) {
			logger.error("smtp decoder: mime parse error" + e);
		}
		return null;
	}

	private void dispatchCommand(String command, String parameter) {
		//		for (SmtpProcessor processor : callbacks) {
		//			processor.onCommand(command, parameter);
		//		}
	}

	private void dispatchReply(int replyCode, String replyMessage) {
		//		for (SmtpProcessor processor : callbacks) {
		//			processor.onReply(replyCode, replyMessage);
		//		}
	}

	private void saveFile(TcpSessionKey sessionKey, MailData smtpData) {
		String path = Configs.getProps(Configs.OUTPUT_DIR);
		Set<String> attachNames = smtpData.getAttachmentNames();
		for (String attachname : attachNames) {
			String fileName = sessionKey.getClientIp().getHostAddress() + "_"
					+ sessionKey.getServerIp().getHostAddress() + "_" + System.currentTimeMillis() + "_SMTP_"
					+ attachname;
			try (FileOutputStream outputStream = new FileOutputStream(new File(path + File.separator + fileName))) {
				byte[] data = new byte[1024];
				try (InputStream inputStream = smtpData.getAttachment(attachname)) {
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