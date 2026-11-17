package set

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// set is a generic set data type.
type set[T comparable] struct {
	items map[T]struct{}
}

// New returns an empty set.
func New[T comparable]() *set[T] {
	return &set[T]{items: make(map[T]struct{})}
}

// Add inserts item into the set.
func (s *set[T]) Add(item T) {
	s.items[item] = struct{}{}
}

// Delete removes item from the set.
func (s *set[T]) Delete(item T) {
	delete(s.items, item)
}

// Exists reports whether item is present in the set.
func (s *set[T]) Exists(item T) bool {
	_, ok := s.items[item]
	return ok
}

// keys returns a slice of all items in the set.
func (s *set[T]) keys() []T {
	return slices.Collect(maps.Keys(s.items))
}

// formatSetStrings formats an already-ordered slice of entry strings as a
// single bare value when len == 1, or a brace-enclosed comma-separated list
// (e.g. "{a,b}" or "{}" when empty).
func formatSetStrings(entries []string) string {
	if len(entries) == 1 {
		return entries[0]
	}
	return "{" + strings.Join(entries, ",") + "}"
}

// formatSortedStrings sorts entries in place and formats them via
// formatSetStrings.
func formatSortedStrings(entries []string) string {
	slices.Sort(entries)
	return formatSetStrings(entries)
}

// formatStringers formats an already-ordered slice of fmt.Stringer values via
// formatSetStrings.
func formatStringers[T fmt.Stringer](items []T) string {
	if len(items) == 1 {
		return items[0].String()
	}
	strs := make([]string, len(items))
	for i, item := range items {
		strs[i] = item.String()
	}
	return formatSetStrings(strs)
}
