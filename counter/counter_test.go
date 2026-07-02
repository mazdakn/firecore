package counter

import (
	"sync"
	"testing"

	. "github.com/onsi/gomega"
)

func TestCounterIncrement(t *testing.T) {
	RegisterTestingT(t)

	c := &Counter{}

	// Initially, counter should be 0
	Expect(c.Get()).To(Equal(uint64(0)))

	// Increment once
	c.Increment()
	Expect(c.Get()).To(Equal(uint64(1)))

	// Increment again
	c.Increment()
	Expect(c.Get()).To(Equal(uint64(2)))
}

func TestCounterReset(t *testing.T) {
	RegisterTestingT(t)

	c := &Counter{}

	// Increment a few times
	c.Increment()
	c.Increment()
	c.Increment()
	Expect(c.Get()).To(Equal(uint64(3)))

	// Reset counter
	c.Reset()
	Expect(c.Get()).To(Equal(uint64(0)))

	// Increment after reset
	c.Increment()
	Expect(c.Get()).To(Equal(uint64(1)))
}

func TestCounterConcurrency(t *testing.T) {
	RegisterTestingT(t)

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
	Expect(c.Get()).To(Equal(expectedCount))
}
