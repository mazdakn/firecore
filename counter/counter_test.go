package counter

import (
	"sync"
	"testing"
)

func TestCounterIncrement(t *testing.T) {
	c := &Counter{}

	// Initially, counter should be 0
	if got := c.Get(); got != 0 {
		t.Errorf("c.Get() = %d; want 0", got)
	}

	// Increment once
	c.Increment()
	if got := c.Get(); got != 1 {
		t.Errorf("c.Get() = %d; want 1", got)
	}

	// Increment again
	c.Increment()
	if got := c.Get(); got != 2 {
		t.Errorf("c.Get() = %d; want 2", got)
	}
}

func TestCounterAdd(t *testing.T) {
	c := &Counter{}

	// Initially, counter should be 0
	if got := c.Get(); got != 0 {
		t.Errorf("c.Get() = %d; want 0", got)
	}

	// Add a value
	c.Add(42)
	if got := c.Get(); got != 42 {
		t.Errorf("c.Get() = %d; want 42", got)
	}

	// Add again, accumulating
	c.Add(8)
	if got := c.Get(); got != 50 {
		t.Errorf("c.Get() = %d; want 50", got)
	}

	// Adding 0 is a no-op
	c.Add(0)
	if got := c.Get(); got != 50 {
		t.Errorf("c.Get() = %d; want 50", got)
	}
}

func TestCounterReset(t *testing.T) {
	c := &Counter{}

	// Increment a few times
	c.Increment()
	c.Increment()
	c.Increment()
	if got := c.Get(); got != 3 {
		t.Errorf("c.Get() = %d; want 3", got)
	}

	// Reset counter
	c.Reset()
	if got := c.Get(); got != 0 {
		t.Errorf("c.Get() = %d; want 0", got)
	}

	// Increment after reset
	c.Increment()
	if got := c.Get(); got != 1 {
		t.Errorf("c.Get() = %d; want 1", got)
	}
}

func TestCounterConcurrency(t *testing.T) {
	c := &Counter{}

	// Concurrently increment counter to test thread-safety
	numGoroutines := 100
	incrementsPerGoroutine := 100
	expectedCount := uint64(numGoroutines * incrementsPerGoroutine)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				c.Increment()
			}
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Verify the counter is correct
	if got := c.Get(); got != expectedCount {
		t.Errorf("c.Get() = %d; want %d", got, expectedCount)
	}
}
