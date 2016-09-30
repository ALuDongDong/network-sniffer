/*
 * Copyright 2010 NCHOVY
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.hfut.sniffer.payload.parser.imap;

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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * Imap解码
 * @author donglei
 * @date: 2016年8月21日 下午3:56:20
 */
public class ImapDecoder implements TcpProcessor {

	private Logger logger = LoggerFactory.getLogger(ImapDecoder.class.getName());

	private Map<TcpSessionKey, ImapSession> sessionMap;
	private Pattern pattern;

	public ImapDecoder() {
		sessionMap = new HashMap<TcpSessionKey, ImapSession>();
		this.pattern = Pattern.compile(".*FETCH.*BODY.*");
	}

	@Override
	public ProcessStatus handleTx(TcpSessionKey sessionKey, byte[] data, long timestamp) {
		Buffer payload = new ChainBuffer();
		payload.addLast(data);
		ImapSession session = sessionMap.get(sessionKey);
		if (session == null) {
			session = new ImapSession();
			this.sessionMap.put(sessionKey, session);
		}
		return handleTx(sessionKey, session, payload);
	}

	@Override
	public ProcessStatus handleRx(TcpSessionKey sessionKey, byte[] data, long timestamp) {
		Buffer payload = new ChainBuffer();
		payload.addLast(data);
		ImapSession session = sessionMap.get(sessionKey);
		if (session == null) {
			session = new ImapSession();
			this.sessionMap.put(sessionKey, session);
		}
		return handleRx(sessionKey, session, payload);
	}

	private ProcessStatus handleTx(TcpSessionKey sessionKey, ImapSession session, Buffer buf) {
		try {
			int len = buf.bytesBefore(new byte[] { 0x0d, 0x0a });
			if (len == 0) {
				return ProcessStatus.ERROR;
			}

			byte[] t = new byte[len];
			buf.gets(t, 0, t.length);
			/* skip \r\n */
			buf.get();
			buf.get();

			String request = new String(t);
			logger.info("Request is {}", request);
			handleRequest(request, session, buf);
		} catch (BufferUnderflowException e) {
			return ProcessStatus.ERROR;
		}
		return ProcessStatus.OK;

	}

	private ProcessStatus handleRx(TcpSessionKey sessionKey, ImapSession session, Buffer buf) {
		return handleResponse(sessionKey, session, buf);
	}

	private void handleRequest(String line, ImapSession session, Buffer txBuffer) {
		int tagIndex = line.indexOf(" ");
		String tag = line.substring(0, tagIndex);
		session.setRequestTag(tag);
		String request = line.substring(tagIndex + 1, line.length());
		session.setRequest(request);
		session.setFetchBody(requestFetchBody(request));
	}

	private ProcessStatus handleResponse(TcpSessionKey sessionKey, ImapSession session, Buffer rxBuffer) {
		if(session.isFetchBody()) {
			String fetchCompleted = session.getRequestTag() + " OK Fetch completed";
			int length = rxBuffer.bytesBefore(fetchCompleted.getBytes());
			if (length == 0) {
				return ProcessStatus.MORE;
			}

			byte[] emailData = new byte[length];
			rxBuffer.gets(emailData, 0, length);

			MimeMessage msg = createMimeMessage(emailData);
			//		MimeHeader header = new MimeHeader();
			//		Charset headerCharset = header.getHeaderCharset(msg);
			//		header.decodeHeader(headerCharset, emailData);

			MailDataImpl imapData = new MailDataImpl(msg);
			//		getMessage(header, smtpData);

			saveFile(sessionKey, imapData);
			session.setFetchBody(false);
			return ProcessStatus.OK;
		} else {
			while (true) {
				int length = rxBuffer.bytesBefore(new byte[] { 0x0d, 0x0a });
				if (length == 0) {
					return ProcessStatus.OK;
				}

				byte[] b = new byte[length];
				rxBuffer.gets(b, 0, length);
				/* skip \r\n */
				rxBuffer.get();
				rxBuffer.get();

				String reply = new String(b);
				logger.info("SMTP response is {}", reply);
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

	private boolean requestFetchBody(String request) {
		Matcher m = this.pattern.matcher(request);
		return m.find();
	}
}