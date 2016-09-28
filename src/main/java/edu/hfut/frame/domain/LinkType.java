package edu.hfut.frame.domain;

/**
 * 链路类型
 * @author donglei
 * @date: 2016年4月26日 下午9:15:08
 */
public enum LinkType {

	NULL, EN10MB, RAW, LOOP, LINUX_SLL;

	public static LinkType getLinkType(long linkTypeVal) {
		switch ((int) linkTypeVal) {
		case 0:
			return LinkType.NULL;
		case 1:
			return LinkType.EN10MB;
		case 101:
			return LinkType.RAW;
		case 108:
			return LinkType.LOOP;
		case 113:
			return LinkType.LINUX_SLL;
		}
		return null;
	}

}
