package edu.hfut.sniffer.parser.util;

/**
 * 异常日志工具类
 * @author donglei
 * @date: 2016年8月19日 下午5:14:10
 */
public class LogbackUtil {

	/**
	 * 对异常信息进行转换
	 */
	public static String expection2Str(Exception e) {
		StringBuilder result = new StringBuilder();
		result.append(e.getMessage() + "\n");
		for (StackTraceElement stack : e.getStackTrace()) {
			result.append(stack.toString() + "\n");
		}
		return result.toString();
	}

}
