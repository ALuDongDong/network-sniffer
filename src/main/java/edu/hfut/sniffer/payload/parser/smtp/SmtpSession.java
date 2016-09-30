package edu.hfut.sniffer.payload.parser.smtp;

import edu.hfut.sniffer.parser.domain.Buffer;
import edu.hfut.sniffer.parser.domain.ChainBuffer;

/**
 * @author donglei
 */
public class SmtpSession {
	private Buffer txBuffer;
	private Buffer rxBuffer;

	private boolean isDataMode;

	public SmtpSession() {
		txBuffer = new ChainBuffer();
		rxBuffer = new ChainBuffer();
	}

	public boolean isDataMode() {
		return isDataMode;
	}

	public void setDataMode(boolean isDataMode) {
		this.isDataMode = isDataMode;
	}

	public Buffer getTxBuffer() {
		return txBuffer;
	}

	public Buffer getRxBuffer() {
		return rxBuffer;
	}

	public void reset() {
		txBuffer = null;
		rxBuffer = null;

		txBuffer = new ChainBuffer();
		rxBuffer = new ChainBuffer();
	}

	public void resetTx() {
		txBuffer = null;
		txBuffer = new ChainBuffer();
	}

	public void resetRx() {
		rxBuffer = null;
		rxBuffer = new ChainBuffer();
	}

	public void clear() {
		txBuffer = null;
		rxBuffer = null;
	}
}