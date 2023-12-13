package cache

import (
	"sync"
	"sync/atomic"
)

// 相对于FIFO算法立刻淘汰对象，该算法会检查待淘汰对象的引用标志位。如果对象被引用过，该对象引用位清零，
// 重新插入队列尾部，像新的对象一样；如果该对象未被引用过，则将被淘汰。
type secondChanceCache struct {
	table    map[string]*cacheItem
	items    []*cacheItem
	position int
	mutex    sync.RWMutex
}

type cacheItem struct {
	key        string      // string(serializedIdentity) or mspid.identityid
	value      interface{} // msp.Identity
	referenced int32
}

func newSecondChanceCache(cacheSize int) *secondChanceCache {
	return &secondChanceCache{
		position: 0,
		items:    make([]*cacheItem, cacheSize),
		table:    make(map[string]*cacheItem),
	}
}

func (scc *secondChanceCache) len() int {
	scc.mutex.RLock()
	defer scc.mutex.RUnlock()
	return len(scc.table)
}

// 传入的 key 是 secondChanceCache.table 的 key。
func (scc *secondChanceCache) get(key string) (interface{}, bool) {
	scc.mutex.RLock()
	defer scc.mutex.RUnlock()

	item, ok := scc.table[key]
	if !ok {
		return nil, false
	}
	atomic.StoreInt32(&item.referenced, 1)
	return item.value, true
}

func (scc *secondChanceCache) add(key string, value interface{}) {
	scc.mutex.Lock()
	defer scc.mutex.Unlock()

	if old, ok := scc.table[key]; ok {
		old.value = value
		atomic.StoreInt32(&old.referenced, 1)
		return
	}

	var item = &cacheItem{
		key:   key,
		value: value,
	}

	size := len(scc.items)
	num := len(scc.table)
	if num < size {
		scc.table[key] = item
		scc.items[num] = item // TODO 为什么不是 size
		return
	}

	for {
		victim := scc.items[scc.position]
		if atomic.LoadInt32(&victim.referenced) == 0 {
			delete(scc.table, victim.key)
			scc.table[key] = item
			scc.items[scc.position] = item
			scc.position = (scc.position + 1) % size
			return
		}
		atomic.StoreInt32(&victim.referenced, 0)
		scc.position = (scc.position + 1) % size
	}
}
