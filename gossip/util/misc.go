package util

import (
	"math/rand"
	"reflect"
	"sync"
	"time"
)

// misc: 混杂的

var r *rand.Rand

func init() {
	r = rand.New(rand.NewSource(time.Now().Unix()))
}

func RandomUint64() uint64 {
	return r.Uint64()
}

func RandomIntn(n int) int {
	return r.Intn(n)
}

// GetRandomIndices 将 [0,highestIndex] 区间内的所有数字打乱，然后取前
// indiceCount 个数字返回。
func GetRandomIndices(indiceCount, highestIndex int) []int {
	if highestIndex+1 < indiceCount {
		return nil
	}

	return r.Perm(highestIndex + 1)[:indiceCount]
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type Set struct {
	items map[interface{}]struct{}
	mutex *sync.RWMutex
}

func NewSet() *Set {
	return &Set{
		mutex: &sync.RWMutex{},
		items: make(map[interface{}]struct{}),
	}
}

func (s *Set) Add(item interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.items[item] = struct{}{}
}

func (s *Set) Exists(item interface{}) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	_, exists := s.items[item]
	return exists
}

func (s *Set) Size() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return len(s.items)
}

func (s *Set) Remove(item interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.items, item)
}

func (s *Set) Clear() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.items = make(map[interface{}]struct{})
}

func (s *Set) ToArray() []interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	res := make([]interface{}, len(s.items))
	i := 0
	for item := range s.items {
		res[i] = item
		i++
	}
	return res
}

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type Equals func(a interface{}, b interface{}) bool

func IndexInSlice(array interface{}, o interface{}, equals Equals) int {
	arr := reflect.ValueOf(array)
	for i := 0; i < arr.Len(); i++ {
		if equals(arr.Index(i).Interface(), o) {
			return i
		}
	}
	return -1
}

func Contains(s string, arr []string) bool {
	for _, item := range arr {
		if s == item {
			return true
		}
	}
	return false
}
