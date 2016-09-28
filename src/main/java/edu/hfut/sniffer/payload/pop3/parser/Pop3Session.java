package edu.hfut.sniffer.payload.pop3.parser;

import edu.hfut.sniffer.parser.domain.ChainBuffer;

/**
 * @author donglei
 */
public class Pop3Session {
	private ChainBuffer txBuffer;
	private ChainBuffer rxBuffer;

	private Pop3State state;

	private boolean isSkipRETRMessage = false;
	/* remark start point of e-mail */
	private boolean remarkStart = false;

	public Pop3Session() {
		txBuffer = new ChainBuffer();
		rxBuffer = new ChainBuffer();

		state = Pop3State.NONE;
	}

	public ChainBuffer getTxBuffer() {
		return txBuffer;
	}

	public ChainBuffer getRxBuffer() {
		return rxBuffer;
	}

	public Pop3State getState() {
		return state;
	}

	public void setState(Pop3State state) {
		this.state = state;
	}

	public boolean isSkipRETRMessage() {
		return isSkipRETRMessage;
	}

	public void setSkipRETRMessage(boolean isSkipRETRMessage) {
		this.isSkipRETRMessage = isSkipRETRMessage;
	}

	public boolean isRemarkStart() {
		return remarkStart;
	}

	public void setRemarkStart(boolean remarkStart) {
		this.remarkStart = remarkStart;
	}

	public void initEmailVars() {
		remarkStart = false;
	}

	public void clear() {
		txBuffer = null;
		rxBuffer = null;

		txBuffer = new ChainBuffer();
		rxBuffer = new ChainBuffer();
	}
}
