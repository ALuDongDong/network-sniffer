package edu.hfut.sniffer.cache;

import java.util.Collection;

/**
 * 缓存的接口实现
 * @author donglei
 * @date: 2016年5月3日 下午2:42:05
 */
public interface Cachable<K, V> {

	public boolean exists(K key);

	public void add(K key, V value) throws Exception;

	public Collection<V> invalidate(K key);

	public boolean delete(K key);

	public Collection<V> members(K key);

	public long size();

}
