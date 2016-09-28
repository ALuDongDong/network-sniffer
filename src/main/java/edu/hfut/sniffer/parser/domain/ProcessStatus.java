package edu.hfut.sniffer.parser.domain;

/**
 * 负载处理的状态
 *      OK: 处理完成，可以清理数据
 *      ERROR: 处理错误
 *      MORE: 暂不清理缓存，可能会存在更多的数据
 * @author donglei
 * @date: 2016年6月16日 下午3:55:50
 */
public enum ProcessStatus {

	OK, ERROR, MORE

}
