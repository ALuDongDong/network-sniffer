package edu.hfut.sniffer.payload.mail.parser;

import java.io.InputStream;
import java.util.Date;
import java.util.Set;

import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

/**
 * 邮件数据
 * @author donglei
 * @date: 2016年8月17日 下午10:56:18
 */
public interface MailData {

	int getSize();

	Date getSentDate();

	Set<InternetAddress> getFrom();

	Set<InternetAddress> getTo();

	Set<InternetAddress> getCc();

	String getSubject();

	String getContentType();

	String getTextContent();

	String getHtmlContent();

	Set<String> getAttachmentNames();

	InputStream getAttachment(String fileName);

	MimeMessage getMimeMessage();
}
