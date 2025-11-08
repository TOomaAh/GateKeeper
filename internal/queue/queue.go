package queue

import "sync"

type IPQueue struct {
	mutex  *sync.RWMutex
	ipScan map[string]*sync.RWMutex
}

func NewIPQueue() *IPQueue {
	return &IPQueue{
		mutex:  &sync.RWMutex{},
		ipScan: make(map[string]*sync.RWMutex),
	}
}

func (q *IPQueue) Get(key string) *sync.RWMutex {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if value, ok := q.ipScan[key]; ok {
		return value
	}

	mutex := &sync.RWMutex{}
	q.ipScan[key] = mutex

	return mutex
}

func (q *IPQueue) Remove(key string) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	delete(q.ipScan, key)
}
