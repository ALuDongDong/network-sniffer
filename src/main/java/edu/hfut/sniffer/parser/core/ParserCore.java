package edu.hfut.sniffer.parser.core;

import static edu.hfut.frame.domain.ReaderConstant.PROTOCOL_TCP;

import java.util.Collection;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.hfut.frame.domain.Flow;
import edu.hfut.frame.domain.Frame;
import edu.hfut.frame.domain.FrameConstant;
import edu.hfut.frame.domain.SequencePayload;
import edu.hfut.sniffer.cache.MemoryCache;
import edu.hfut.sniffer.parser.domain.Buffer;
import edu.hfut.sniffer.parser.domain.ChainBuffer;
import edu.hfut.sniffer.parser.domain.ProcessStatus;
import edu.hfut.sniffer.parser.domain.Protocol;
import edu.hfut.sniffer.payload.parser.IPayloadParser;
import edu.hfut.sniffer.payload.parser.ftp.FtpPayLoadParser;
import edu.hfut.sniffer.payload.parser.http.HttpPayloadParser;
import edu.hfut.sniffer.payload.parser.imap.ImapPayloadParser;
import edu.hfut.sniffer.payload.parser.pop3.Pop3PayloadParser;
import edu.hfut.sniffer.payload.parser.smtp.SmtpPayloadParser;

/**
 * 解析数据帧
 * @author donglei
 * @date: 2016年5月4日 上午9:50:36
 */
public class ParserCore {

	private static final Logger logger = LoggerFactory.getLogger(ParserCore.class);

	/**
	 * 缓存TCP数据块
	 */
	private MemoryCache<Flow, SequencePayload> cache;

	/**
	 * 缓存数据帧的AWK
	 */
	private MemoryCache<Flow, Long> awks;

	/**
	 * 缓存TCP_FLAGS PUSH为TRUE的起始frame，用于去重（比如SMTP、pop3、imap等）
	 */
	private MemoryCache<Flow, Frame> lastFrames;

	private TcpProtocolMapper protocolMapper;

	/**
	 * just for log
	 */
	private int count = 0;

	public ParserCore() {
		this.cache = new MemoryCache<>();
		this.awks = new MemoryCache<>();
		this.lastFrames = new MemoryCache<>();
		this.protocolMapper = new TcpProtocolMapper();
		this.protocolMapper.register(Protocol.FTP, new FtpPayLoadParser(this.protocolMapper));
		this.protocolMapper.register(Protocol.HTTP, new HttpPayloadParser());
		this.protocolMapper.register(Protocol.SMTP, new SmtpPayloadParser());
		this.protocolMapper.register(Protocol.POP3, new Pop3PayloadParser());
		this.protocolMapper.register(Protocol.IMAP, new ImapPayloadParser());
	}

	public void parse(Frame frame) {

		// 顺序的TCP流合并,暂时只处理TCP
		if (PROTOCOL_TCP == frame.getTransProto()) {

			Flow flow = new Flow(frame);

			if (frame.getPayload().length > 0) {
				Long seq = frame.getSeq();
				SequencePayload sequencePayload = new SequencePayload(seq, frame.getPayload());
				try {
					if (isConsequent(frame, flow)) {
						this.cache.add(flow, sequencePayload);
						this.awks.add(flow, frame.getAwk());
					} else {
						this.cache.delete(flow);
						this.awks.delete(flow);
						this.lastFrames.delete(flow);
						this.cache.add(flow, sequencePayload);
						this.awks.add(flow, frame.getAwk());
						this.lastFrames.add(flow, frame);
					}
				} catch (ExecutionException e) {
					logger.error(e.getMessage());
				}
			}
			count++;
			if (count % 100 == 0) {
				logger.info("cache count : " + this.cache.size());
				logger.info("cache stats : \n" + this.cache.toString());
				logger.info("awks count : " + this.awks.size());
				logger.info("awks stats : \n" + this.cache.toString());
			}

			if ((Boolean) frame.getFlags(FrameConstant.TCP_FLAG_FIN)
					|| (Boolean) frame.getFlags(FrameConstant.TCP_FLAG_PSH)) {
				TreeSet<SequencePayload> fragments = this.cache.invalidate(flow);

				if (fragments != null && fragments.size() > 0) {
					frame.addFlags(FrameConstant.REASSEMBLED_TCP_FRAGMENTS, fragments.size());
					SequencePayload concats = SequencePayload.concat(fragments);
					byte[] packetPayload = concats.getPayload();
					if (packetPayload.length > 0) {
						TreeSet<Frame> lastF = this.lastFrames.members(flow);
						if (lastF != null && !lastF.isEmpty()) {
							frame = lastF.first();
						} else {
							logger.error("The last frames should not be empty. There must be some mistakes!");
						}
						ProcessStatus status = sendToApplicationLayer(frame, packetPayload);
						if (status == ProcessStatus.OK) {
							this.awks.delete(flow);
							this.lastFrames.delete(flow);
						} else {
							try {
								this.cache.add(flow, concats);
							} catch (ExecutionException e) {
								logger.error("Concat fragments can't be push back! ERROR: {}", e.getMessage());
							}
						}
					} else {
						/**
						 * TCP 会不保证数据包有序接受吗？？
						 *    YES: 则这块代码无效
						 *     NO: 则将取出的数据包放回，等待未接受数据包
						 */
						if (fragments.size() < 100) {
							for (SequencePayload fragment : fragments) {
								try {
									this.cache.add(flow, fragment);
								} catch (ExecutionException e) {
									logger.error("Fragments can't be put back! ERROR: {}", e.getMessage());
								}
							}
						}
					}
				}
				fragments = null;
			}
		}
	}

	private Protocol forecastProtocol(byte[] payload) {
		byte[] codes = new byte[4];
		if (payload.length > 4) {
			System.arraycopy(payload, 0, codes, 0, 4);
		}
		String code = new String(codes);
		if (code.matches("(HTTP|GET |POST)")) {
			return Protocol.HTTP;
		} else if (code.matches("")) {
		}
		return null;

	}

	private ProcessStatus sendToApplicationLayer(Frame frame, byte[] packetPayload) {

		logger.info("frame : " + frame.toString());

		Protocol protocol = this.protocolMapper.map(frame);
		if (protocol == null) {
			protocol = forecastProtocol(packetPayload);
			if (protocol == null) {
				logger.info("{} can't map a valid protocol", frame);
				return ProcessStatus.OK;
			}
		}

		Collection<IPayloadParser> parsers = this.protocolMapper.getTcpProcessors(protocol);
		if (parsers == null) {
			logger.info("{} has't a valid PayloadParser !", protocol.name());
			return ProcessStatus.OK;
		}
		for (IPayloadParser parser : parsers) {
			ProcessStatus status = parser.processPacketPayload(frame, packetPayload);
			if (status == ProcessStatus.OK) {
				return ProcessStatus.OK;
			}
		}
		return ProcessStatus.MORE;
	}

	@SuppressWarnings("unused")
	private void nonStandardPort(Protocol protocol, byte[] payload) {
		if (protocol == Protocol.HTTP) {
			Buffer buffer = new ChainBuffer(payload);
			int length = buffer.bytesBefore(new byte[] { 0x0d, 0x0a });
			if (length != 0) {
				byte[] reply = new byte[length];
				buffer.gets(reply, 0, length);
				String str = new String(reply);
				String head = str.length() > 4 ? str.substring(0, 4) : "";
				if (str.toLowerCase().contains("ftp") || head.equalsIgnoreCase("USER") || head.equalsIgnoreCase("PASS")
						|| head.equalsIgnoreCase("PWD") || head.equalsIgnoreCase("LIST")
						|| head.equalsIgnoreCase("PORT") || head.equalsIgnoreCase("RETR")
						|| head.equalsIgnoreCase("STOR")) {

				}
			}
		}
	}

	private boolean isConsequent(Frame frame, Flow flow) {
		Collection<Long> allreadyAwks = this.awks.members(flow);
		if (allreadyAwks != null) {
			for (Long allreadyAwk : allreadyAwks) {
				if (allreadyAwk != frame.getAwk()) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

}
