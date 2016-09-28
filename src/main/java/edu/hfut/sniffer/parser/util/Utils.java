package edu.hfut.sniffer.parser.util;


import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;

import edu.hfut.frame.domain.Frame;

/**
 * 摘要信息提取工具类
 * @author donglei
 * @date: 2016年5月17日 下午3:30:02
 */
public class Utils {

	public static String md5(Frame frame) {
		String rowKey = Hashing.md5().newHasher().putLong(frame.getTimestamp())
				.putString(frame.getSrcIp(), Charsets.UTF_8).putInt(frame.getSrcPort())
				.putString(frame.getDesIp(), Charsets.UTF_8).putInt(frame.getDesPort()).hash().toString();
		return rowKey;
	}

}
