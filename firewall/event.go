package firewall

import (
	"log"
	"net/http"
	"sort"
	"sync"
)

type Event interface {
	Name() string
	IsStopped() bool
	Stop()
	Request() *http.Request
	start() <-chan struct{}
}

type AuthenticationResult interface {
	Request() *http.Request
}

func (e *authenticationResultEvent) Request() *http.Request {
	return e.request
}

type authenticationResultEvent struct {
	event
	request *http.Request
}

func NewAuthenticationResult(r *http.Request) AuthenticationResult {
	e := &authenticationResultEvent{
		request: r,
	}

	return e
}

type Handler func(ev Event)

func (h *Handler) Name() string {
	return "foo"
}

type HandlerRegistry interface {
	Add(h Handler, priority int)
}

type Dispatcher interface {
	Dispatch(event Event)
	DispatchAsync(event Event)
}

type event struct {
	name    string
	stopped bool
	req     *http.Request
	res     *http.Response
	chs     chan struct{}
	shc     chan struct{}
}

func NewEvent(name string, req *http.Request) Event {
	e := &event{name: name, stopped: false, chs: make(chan struct{}, 1), shc: make(chan struct{}, 1), req: req}

	return e
}

func (e *event) Request() *http.Request {
	return e.req
}

func (e *event) Name() string {
	return e.name
}
func (e *event) start() <-chan struct{} {
	return e.shc
}

func (e *event) Stop() {
	e.shc <- struct{}{}
	e.stopped = true
}

func (e *event) IsStopped() bool {
	return e.stopped
}

func NewEventDispatcher() *DefaultDispatcher {
	d := &DefaultDispatcher{handlers: make(map[int][]Handler, 0)}
	d.isSorted = false
	d.wg = &sync.WaitGroup{}
	d.mu = &sync.RWMutex{}
	return d
}

type DefaultDispatcher struct {
	handlers map[int][]Handler
	mu       *sync.RWMutex
	wg       *sync.WaitGroup
	sorted   []int
	isSorted bool
}

func (d *DefaultDispatcher) getSorted() []int {
	if d.isSorted {
		return d.sorted
	}

	var sorted []int

	for key := range d.handlers {
		sorted = append(sorted, key)
	}

	d.sorted = sorted

	sort.Sort(sort.Reverse(sort.IntSlice(d.sorted)))
	d.isSorted = true

	return d.sorted
}

func (d *DefaultDispatcher) Dispatch(e Event) {
	for _, k := range d.getSorted() {
		for _, h := range d.handlers[k] {
			if e.IsStopped() {
				return
			}
			h(e)
		}
	}
}

func (d *DefaultDispatcher) digest(done <-chan struct{}, stopped <-chan struct{}, event Event, h Handler) {
	if event.IsStopped() {
		return
	}
	handle := func(e Event) {
		if e.IsStopped() {
			return
		}
		var mu sync.RWMutex
		mu.Lock()
		h(e)
		mu.Unlock()
		log.Printf("shit handled…\n")
	}

	handle(event)

}

func (d *DefaultDispatcher) doAggregate(done <-chan struct{}, stopped <-chan struct{}) <-chan Handler {
	var hs []Handler
	for _, i := range d.getSorted() {
		hs = append(hs, d.handlers[i]...)
	}

	out := make(chan Handler, len(hs))

	go func() {
		defer close(out)
		for _, h := range hs {
			select {
			case <-stopped:
				return
			case <-done:
				return
			default:
				out <- h
			}
		}
	}()

	return out

}
func (d *DefaultDispatcher) aggregateHandlers(done <-chan struct{}, stopped <-chan struct{}, event Event) {

	var wg sync.WaitGroup

	handler := d.doAggregate(done, stopped)

	for h := range handler {
		wg.Add(1)

		go func(handler Handler) {
			defer wg.Done()
			select {
			case <-done:
				return
			case <-stopped:
				return
			default:
				log.Println("handling shit…")
				d.digest(done, stopped, event, handler)
			}
		}(h)
	}

	go func() {
		wg.Wait()
	}()
}

func (d *DefaultDispatcher) DispatchAsync(e Event) {
	done := make(chan struct{}, 1)
	evc := e.start()

	go func() {
		for {
			select {
			case <-e.Request().Context().Done():
				log.Printf("sorry, done\n")
				done <- struct{}{}
			}
		}
	}()

	d.aggregateHandlers(done, evc, e)
}

func (d *DefaultDispatcher) Add(h Handler, priority int) {
	d.isSorted = false
	d.handlers[priority] = append(d.handlers[priority], h)
}
