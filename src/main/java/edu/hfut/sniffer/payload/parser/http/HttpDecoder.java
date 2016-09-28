package edu.hfut.sniffer.payload.parser.http;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import org.apache.http.Header;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpEntity;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseFactory;
import org.apache.http.RequestLine;
import org.apache.http.impl.DefaultHttpRequestFactory;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.conn.DefaultClientConnection;
import org.apache.http.impl.io.AbstractSessionInputBuffer;
import org.apache.http.impl.io.AbstractSessionOutputBuffer;
import org.apache.http.impl.io.DefaultHttpRequestParser;
import org.apache.http.impl.io.DefaultHttpResponseParser;
import org.apache.http.io.HttpMessageParser;
import org.apache.http.io.SessionInputBuffer;
import org.apache.http.io.SessionOutputBuffer;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.hfut.sniffer.parser.domain.ProcessStatus;
import edu.hfut.sniffer.parser.domain.TcpSessionKey;
import edu.hfut.sniffer.parser.util.Configs;
import edu.hfut.sniffer.payload.parser.TcpProcessor;

/**
 * HTTP 协议解析
 * @author donglei
 * @date: 2016年8月16日 上午9:45:48
 */
public class HttpDecoder implements TcpProcessor {

	private static final Logger logger = LoggerFactory.getLogger(HttpDecoder.class);

	private HttpParams params;
	private HttpRequestFactory reqFactory;
	private HttpResponseFactory respFactory;
	private Map<TcpSessionKey, HttpSession> httpSessions;

	public HttpDecoder() {
		this.params = new BasicHttpParams();
		this.reqFactory = new DefaultHttpRequestFactory();
		this.respFactory = new DefaultHttpResponseFactory();
		this.httpSessions = new HashMap<>();
	}

	@Override
	public ProcessStatus handleTx(TcpSessionKey sessionKey, byte[] data, long timestamp) {
		HttpSession session = this.httpSessions.get(sessionKey);
		if (session == null) {
			session = new HttpSession();
			this.httpSessions.put(sessionKey, session);
		}
		final SessionInputBuffer inBuf = new AbstractSessionInputBuffer() {

			{
				init(new ByteArrayInputStream(data), 1024, params);
			}

			@Override
			public boolean isDataAvailable(int timeout) throws IOException {
				return true;
			}
		};
		HttpMessageParser<HttpRequest> parser = new DefaultHttpRequestParser(inBuf, null, reqFactory, params);
		try {
			HttpRequest request = parser.parse();
			decodeRequestHeader(request, session);
			return ProcessStatus.OK;
		} catch (Exception e) {
			logger.error("HttpException when decoding HTTP request");
			return ProcessStatus.ERROR;
		}
	}

	@Override
	public ProcessStatus handleRx(TcpSessionKey session, byte[] data, long timestamp) {
		HttpSession httpSession = this.httpSessions.get(session);
		if (httpSession == null) {
			httpSession = new HttpSession();
		}
		final SessionInputBuffer inBuf = new AbstractSessionInputBuffer() {

			{
				init(new ByteArrayInputStream(data), 1024, params);
			}

			@Override
			public boolean isDataAvailable(int timeout) throws IOException {
				return true;
			}
		};
		final SessionOutputBuffer outBuf = new AbstractSessionOutputBuffer() {
		};
		HttpMessageParser<HttpResponse> parser = new DefaultHttpResponseParser(inBuf, null, respFactory, params);

		HttpClientConnection conn = new DefaultClientConnection() {

			{
				init(inBuf, outBuf, params);
			}

			@Override
			protected void assertNotOpen() {
			}

			@Override
			protected void assertOpen() {
			}
		};

		try {
			HttpResponse response = parser.parse();
			conn.receiveResponseEntity(response);
			saveBody(response, session.getClientIp().getHostAddress() + "_" + session.getServerIp().getHostAddress()
					+ "_" + timestamp + "_HTTP_" + httpSession.getFileName());
			return ProcessStatus.OK;
		} catch (Exception e) {
			logger.error("HttpException when decoding HTTP response");
			return ProcessStatus.ERROR;
		}
	}

	private void saveBody(HttpResponse response, String fileName) {
		String path = Configs.getProps(Configs.OUTPUT_DIR);
		try (FileOutputStream outputStream = new FileOutputStream(new File(path + File.separator + fileName))) {
			HttpEntity entity = response.getEntity();
			byte[] data = new byte[1024];
			InputStream inputStream = null;
			try {
				try {
					inputStream = entity.getContent();
					// "Transfer-Encoding: chunked" 已经在conn.receiveResponseEntity(response)处理了，所以不要处理
					// "Content-Encoding: gzip"
					Header contentEncoding = response.getFirstHeader("Content-Encoding");
					if (contentEncoding != null && contentEncoding.getValue().equals("gzip")) {
						inputStream = new GZIPInputStream(inputStream);
					}
					int count = inputStream.read(data);
					while (count > 0) {
						outputStream.write(data, 0, count);
						count = inputStream.read(data);
					}
				} finally {
					if (inputStream != null) {
						inputStream.close();
					}
				}
			} catch (IllegalStateException | IOException e) {
				e.printStackTrace();
			}
		} catch (Exception e) {
			logger.error("exception has throwed when saved to DB. case {}", e.getMessage());
		}
	}

	private void decodeRequestHeader(HttpRequest request, HttpSession session) {
		RequestLine requestLine = request.getRequestLine();
		String url = requestLine.getUri();
		logger.info("HTTP Request URL : " + url);
		int askIndex = url.indexOf("?");
		url = url.substring(0, askIndex < 0 ? url.length() : askIndex);
		String fileName = "";
		int lastIndex = url.lastIndexOf("/");
		if (lastIndex + 1 < url.length()) {
			fileName = url.substring(lastIndex < 0 ? 0 : lastIndex + 1, url.length());
		}
		session.setFileName(fileName);
	}

}
