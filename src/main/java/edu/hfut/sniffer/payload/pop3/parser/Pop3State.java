package edu.hfut.sniffer.payload.pop3.parser;

/**
 * @author donglei
 */
public enum Pop3State {
	NONE, FIND_UIDL, FIND_LIST, FIND_TOP, FIND_RETR, FIND_DELE
};
