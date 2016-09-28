package edu.hfut.sniffer.cache;

import java.util.Map.Entry;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

/**
 * 基于Guava实现的Cache
 * @author donglei
 * @date: 2016年5月3日 下午3:05:10
 * @param <K>
 * @param <V>
 */
public class MemoryCache<K, V> implements Cachable<K, V> {

	private static final Logger logger = LoggerFactory.getLogger(MemoryCache.class);

	private LoadingCache<K, TreeSet<V>> innerCache;

	public MemoryCache() {
		LoadingCache<K, TreeSet<V>> cache = CacheBuilder.newBuilder().concurrencyLevel(4)
				.expireAfterAccess(1, TimeUnit.MINUTES).maximumSize(1000)
				.removalListener(new RemovalListener<K, TreeSet<V>>() {

					@Override
					public void onRemoval(RemovalNotification<K, TreeSet<V>> notification) {
						//						logger.info(notification.getKey() + " was removed, cause is " + notification.getCause());

					}
				}).build(new CacheLoader<K, TreeSet<V>>() {

					@Override
					public TreeSet<V> load(K key) throws Exception {
						return new TreeSet<>();
					}
				});
		this.innerCache = cache;
	}

	@Override
	public boolean exists(K key) {
		return this.innerCache.getIfPresent(key) == null ? false : true;
	}

	@Override
	public void add(K key, V value) throws ExecutionException {
		TreeSet<V> values = this.innerCache.get(key);
		values.add(value);
		this.innerCache.put(key, values);
	}

	@Override
	public TreeSet<V> invalidate(K key) {
		TreeSet<V> values = this.innerCache.getIfPresent(key);
		this.innerCache.invalidate(key);
		return values;
	}

	@Override
	public boolean delete(K key) {
		try {
			this.innerCache.invalidate(key);
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	@Override
	public TreeSet<V> members(K key) {
		return this.innerCache.getIfPresent(key);
	}

	@Override
	public long size() {
		return this.innerCache.size();
	}

	@Override
	public String toString() {
		ConcurrentMap<K, TreeSet<V>> caches = this.innerCache.asMap();
		StringBuilder sBuilder = new StringBuilder();
		for (Entry<K, TreeSet<V>> entry : caches.entrySet()) {
			sBuilder.append(entry.getKey() + "\t" + entry.getValue().size() + "\n");
		}
		return sBuilder.toString();
	}

}
