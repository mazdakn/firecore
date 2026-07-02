package counter

import "sync/atomic"

func New() *Counter {
	return &Counter{}
}

// Counter is a thread-safe counter using atomic operations
type Counter struct {
	value atomic.Uint64
}

// Increment atomically increments the counter by 1
func (c *Counter) Increment() {
	c.value.Add(1)
}

// Get atomically returns the current counter value
func (c *Counter) Get() uint64 {
	return c.value.Load()
}

// Reset atomically resets the counter to 0
func (c *Counter) Reset() {
	c.value.Store(0)
}
