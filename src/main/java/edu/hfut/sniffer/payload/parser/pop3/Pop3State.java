package edu.hfut.sniffer.payload.parser.pop3;

/**
 * @author donglei
 */
public enum Pop3State {
	NONE, FIND_UIDL, FIND_LIST, FIND_TOP, FIND_RETR, FIND_DELE
};
