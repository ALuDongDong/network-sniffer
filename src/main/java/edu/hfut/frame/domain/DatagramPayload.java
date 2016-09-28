package edu.hfut.frame.domain;

import com.google.common.base.Objects;
import com.google.common.collect.ComparisonChain;

/**
 * UDP传输负载
 * @author donglei
 * @date: 2016年5月4日 上午10:11:50
 */
public class DatagramPayload implements Comparable<DatagramPayload> {
	private Long offset;
	private byte[] payload;

	public DatagramPayload(Long offset, byte[] payload) {
		this.offset = offset;
		this.payload = payload;
	}

	public Long getOffset() {
		return offset;
	}

	public byte[] getPayload() {
		return payload;
	}

	@Override
	public int compareTo(DatagramPayload o) {
		return ComparisonChain.start().compare(this.offset, o.offset).compare(this.payload.length, o.payload.length)
				.result();
	}

	public boolean linked(DatagramPayload o) {
		if (this.offset + this.payload.length == o.offset) {
			return true;
		}
		if (o.offset + o.payload.length == this.offset) {
			return true;
		}
		return false;
	}

	@Override
	public String toString() {
		return Objects.toStringHelper(this.getClass()).add("offset", this.offset).add("len", this.payload.length)
				.toString();
	}
}