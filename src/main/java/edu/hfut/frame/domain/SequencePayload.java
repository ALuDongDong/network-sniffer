package edu.hfut.frame.domain;

import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Objects;
import com.google.common.collect.ComparisonChain;
import com.google.common.primitives.Bytes;

/**
 * TCP传输负载
 * @author donglei
 * @date: 2016年5月4日 上午10:10:07
 */
public class SequencePayload implements Comparable<SequencePayload> {

	private static final Logger logger = LoggerFactory.getLogger(SequencePayload.class);

	private Long seq;
	private byte[] payload;

	public SequencePayload(Long seq, byte[] payload) {
		this.seq = seq;
		this.payload = payload;
	}

	public static SequencePayload concat(TreeSet<SequencePayload> payloads) {
		byte[] totalPayload = new byte[0];
		long firstSeq = -1;
		SequencePayload prev = null;
		for (SequencePayload seqPayload : payloads) {
			if (firstSeq == -1) {
				firstSeq = seqPayload.seq;
			}
			if (prev != null && !seqPayload.linked(prev)) {
				logger.warn("Broken sequence chain between " + seqPayload + " and " + prev
						+ ". Returning empty payload.");
				totalPayload = new byte[0];
				break;
			}
			totalPayload = Bytes.concat(totalPayload, seqPayload.getPayload());
			prev = seqPayload;
		}
		return new SequencePayload(firstSeq, totalPayload);
	}

	public Long getSeq() {
		return seq;
	}

	public byte[] getPayload() {
		return payload;
	}

	@Override
	public int compareTo(SequencePayload o) {
		return ComparisonChain.start().compare(this.seq, o.seq).compare(this.payload.length, o.payload.length).result();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof SequencePayload) {
			SequencePayload other = (SequencePayload) obj;
			return this.compareTo(other) == 0;
		}
		return false;
	}

	public boolean linked(SequencePayload o) {
		if (this.seq + this.payload.length == o.seq) {
			return true;
		}
		if (o.seq + o.payload.length == this.seq) {
			return true;
		}
		return false;
	}

	@Override
	public String toString() {
		return Objects.toStringHelper(this.getClass()).add("seq", this.seq).add("len", this.payload.length).toString();
	}
}