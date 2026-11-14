package stats

import "sync/atomic"

// Counter is an implementation of stats.Counter.
type Counter struct {
	value  int64
	record func(int64)
}

// Value implements stats.Counter.
func (c *Counter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

// Set implements stats.Counter.
func (c *Counter) Set(newValue int64) int64 {
	// StatsService resets only the upstream-compatible, volatile view. Durable
	// accounting records Add events separately and is never reset by this API.
	return atomic.SwapInt64(&c.value, newValue)
}

// Add implements stats.Counter.
func (c *Counter) Add(delta int64) int64 {
	if c.record != nil {
		c.record(delta)
	}
	return atomic.AddInt64(&c.value, delta)
}
