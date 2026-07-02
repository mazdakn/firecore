package set

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
