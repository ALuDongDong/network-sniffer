package edu.hfut.frame.domain;

import java.util.HashMap;
import java.util.Map;

import com.google.common.base.Objects;

/**
 * 数据帧信息
 * @author donglei
 * @date: 2016年4月26日 下午8:27:26
 */
public class Frame implements Comparable<Frame> {

	// 帧时间
	private long timestamp;

	// 链路层
	private String srcMac;
	private String desMac;

	// 网络层
	private String interProto;
	private String srcIp;
	private String desIp;
	private long id;

	// 传输层
	private String transProto;
	private int srcPort;
	private int desPort;
	private long seq;
	private long awk;

	// 负载
	private byte[] payload;

	// TCP/IP flags
	private Map<String, Object> flags;

	private Frame(FrameBuilder builder) {
		this.timestamp = builder.timestamp;
		this.srcMac = builder.srcMac;
		this.desMac = builder.desMac;
		this.interProto = builder.interProto;
		this.srcIp = builder.srcIp;
		this.desIp = builder.desIp;
		this.id = builder.id;
		this.transProto = builder.transProto;
		this.srcPort = builder.srcPort;
		this.desPort = builder.desPort;
		this.seq = builder.seq;
		this.awk = builder.awk;
		this.payload = builder.payload;
		this.flags = builder.flags;
	}

	@Override
	public int compareTo(Frame o) {
		if (o != null) {
			return (int) (this.timestamp - o.timestamp);
		}
		return 1;
	}

	@Override
	public String toString() {
		return Objects.toStringHelper(Frame.class).add("timestamp", this.timestamp).add("srcMac", this.srcMac)
				.add("desMac", this.desMac).add("interproto", this.interProto).add("srcIp", this.srcIp)
				.add("desIp", this.desIp).add("id", this.id).add("transProto", this.transProto)
				.add("srcPort", this.srcPort)
				.add("desPort", this.desPort).add("seq", this.seq).add("awk", this.awk).add("flags", this.flags)
				.add("payload.length", this.payload.length).toString();
	}

	public long getTimestamp() {
		return timestamp;
	}

	public String getSrcMac() {
		return srcMac;
	}

	public String getDesMac() {
		return desMac;
	}

	public String getInterProto() {
		return interProto;
	}

	public String getSrcIp() {
		return srcIp;
	}

	public String getDesIp() {
		return desIp;
	}

	public long getId() {
		return id;
	}

	public String getTransProto() {
		return transProto;
	}

	public int getSrcPort() {
		return srcPort;
	}

	public int getDesPort() {
		return desPort;
	}

	public long getSeq() {
		return seq;
	}

	public long getAwk() {
		return awk;
	}

	public byte[] getPayload() {
		return payload;
	}

	public Object getFlags(String key) {
		return this.flags.get(key);
	}

	public void addFlags(String key, Object value) {
		this.flags.put(key, value);
	}

	public static class FrameBuilder {
		// 帧时间
		private long timestamp;

		// 链路层
		private String srcMac;
		private String desMac;

		// 网络层
		private String interProto;
		private String srcIp;
		private String desIp;
		private long id;

		// 网络层协议
		private String transProto;
		private int srcPort;
		private int desPort;
		private long seq;
		private long awk;

		// 负载
		private byte[] payload;

		// TCP/IP flags
		private Map<String, Object> flags = new HashMap<>();

		public FrameBuilder addFlags(String key, Object value) {
			flags.put(key, value);
			return this;
		}

		public FrameBuilder setTimestamp(long timestamp) {
			this.timestamp = timestamp;
			return this;
		}

		public FrameBuilder setSrcMac(String srcMac) {
			this.srcMac = srcMac;
			return this;
		}

		public FrameBuilder setDesMac(String desMac) {
			this.desMac = desMac;
			return this;
		}

		public FrameBuilder setInterProto(String interProto) {
			this.interProto = interProto;
			return this;
		}

		public FrameBuilder setSrcIp(String srcIp) {
			this.srcIp = srcIp;
			return this;
		}

		public FrameBuilder setDesIp(String desIp) {
			this.desIp = desIp;
			return this;
		}

		public FrameBuilder setId(long id) {
			this.id = id;
			return this;
		}

		public FrameBuilder setTransProto(String transProto) {
			this.transProto = transProto;
			return this;
		}

		public FrameBuilder setSrcPort(int srcPort) {
			this.srcPort = srcPort;
			return this;
		}

		public FrameBuilder setDesPort(int desPort) {
			this.desPort = desPort;
			return this;
		}

		public FrameBuilder setSeq(long seq) {
			this.seq = seq;
			return this;
		}

		public FrameBuilder setAwk(long awk) {
			this.awk = awk;
			return this;
		}

		public FrameBuilder setPayload(byte[] payload) {
			this.payload = payload;
			return this;
		}

		public long getTimestamp() {
			return timestamp;
		}

		public String getSrcMac() {
			return srcMac;
		}

		public String getDesMac() {
			return desMac;
		}

		public String getInterProto() {
			return interProto;
		}

		public String getSrcIp() {
			return srcIp;
		}

		public String getDesIp() {
			return desIp;
		}

		public String getTransProto() {
			return transProto;
		}

		public int getSrcPort() {
			return srcPort;
		}

		public int getDesPort() {
			return desPort;
		}

		public long getSeq() {
			return seq;
		}

		public long getAwk() {
			return awk;
		}

		public byte[] getPayload() {
			return payload;
		}

		public Object getFlags(String key) {
			return this.flags.get(key);
		}

		public long getId() {
			return id;
		}

		public Frame build() {
			return new Frame(this);
		}

	}

	public static void main(String[] args) {
		FrameBuilder builder = new FrameBuilder();
		builder.setAwk(10000);
		builder.setPayload(new byte[0]);
		Frame f = builder.build();
		System.out.println(f);
	}

}
