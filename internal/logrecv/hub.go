package logrecv

import "sync"

type Hub[T any] struct {
	mu   sync.Mutex
	subs map[*hubSubscription[T]]struct{}
}

type hubSubscription[T any] struct {
	ch   chan T
	once sync.Once
}

func NewHub[T any]() *Hub[T] {
	return &Hub[T]{subs: make(map[*hubSubscription[T]]struct{})}
}

func (h *Hub[T]) Subscribe(buffer int) (<-chan T, func()) {
	if buffer <= 0 {
		buffer = 1
	}
	sub := &hubSubscription[T]{ch: make(chan T, buffer)}

	h.mu.Lock()
	h.subs[sub] = struct{}{}
	h.mu.Unlock()

	return sub.ch, func() {
		sub.once.Do(func() {
			h.mu.Lock()
			delete(h.subs, sub)
			close(sub.ch)
			h.mu.Unlock()
		})
	}
}

func (h *Hub[T]) Publish(value T) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for sub := range h.subs {
		select {
		case sub.ch <- value:
		default:
		}
	}
}
