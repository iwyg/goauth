package firewall

import "testing"

func TestAsyncDispatchWhenStopped(t *testing.T) {
	dispatcher := NewEventDispatcher()
	handlerA := func(ev Event) {

	}

	handlerB := func(ev Event) {
		ev.Stop()
	}

	dispatcher.Add(handlerA, 100)
	dispatcher.Add(handlerB, 300)

}
