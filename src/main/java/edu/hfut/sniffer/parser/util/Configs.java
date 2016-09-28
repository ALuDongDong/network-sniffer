package edu.hfut.sniffer.parser.util;

import java.io.InputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 读取全局配置
 * @author donglei
 * @date: 2016年8月15日 下午10:04:23
 */
public class Configs {

	private static Logger logger = LoggerFactory.getLogger(Configs.class);

	public static final String OUTPUT_DIR = "output.dir";

	private static Properties WHOLE_PROPS = new Properties();

	static {
		logger.info("Load resource: config.properties");
		try (InputStream in = Configs.class.getClassLoader().getResourceAsStream("config.properties");) {
			WHOLE_PROPS.load(in);
		} catch (final Exception e) {
			logger.error("Exception:{}", LogbackUtil.expection2Str(e));
			throw new RuntimeException(e);
		}
	}

	public static String getProps(String configName) {
		return WHOLE_PROPS.getProperty(configName, "");
	}

}
