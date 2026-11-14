package p2p

import (
	"sort"
	"sync"
)

type Runtime struct {
	mu           sync.RWMutex
	coordinators map[string]*Coordinator
}

func NewRuntime() *Runtime {
	return &Runtime{
		coordinators: make(map[string]*Coordinator),
	}
}

func (r *Runtime) Start() error {
	return nil
}

func (r *Runtime) Stop() error {
	r.Reset()
	return nil
}

func (r *Runtime) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.coordinators = make(map[string]*Coordinator)
}

func (r *Runtime) Register(namespace string, adapter Adapter) *Coordinator {
	if r == nil || namespace == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	coordinator, exists := r.coordinators[namespace]
	if !exists {
		coordinator = NewCoordinator(adapter)
		r.coordinators[namespace] = coordinator
		return coordinator
	}

	coordinator.SetAdapter(adapter)
	return coordinator
}

func (r *Runtime) Ensure(namespace string) *Coordinator {
	if r == nil || namespace == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	coordinator, exists := r.coordinators[namespace]
	if !exists {
		coordinator = NewCoordinator(nil)
		r.coordinators[namespace] = coordinator
	}
	return coordinator
}

func (r *Runtime) Get(namespace string) (*Coordinator, bool) {
	if r == nil || namespace == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	coordinator, ok := r.coordinators[namespace]
	return coordinator, ok
}

func (r *Runtime) ListNamespaces() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	namespaces := make([]string, 0, len(r.coordinators))
	for namespace := range r.coordinators {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	return namespaces
}

func (r *Runtime) GetSessionStatus(namespace, sessionID string) (SessionStatus, bool) {
	coordinator, ok := r.Get(namespace)
	if !ok || coordinator == nil {
		return SessionStatusNew, false
	}
	return coordinator.GetSessionStatus(sessionID)
}

func (r *Runtime) SnapshotNamespace(namespace string) map[string]SessionStatus {
	coordinator, ok := r.Get(namespace)
	if !ok || coordinator == nil {
		return nil
	}
	return coordinator.SnapshotSessionStatuses()
}

func (r *Runtime) Snapshot() map[string]map[string]SessionStatus {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	coordinators := make(map[string]*Coordinator, len(r.coordinators))
	for namespace, coordinator := range r.coordinators {
		coordinators[namespace] = coordinator
	}
	r.mu.RUnlock()

	out := make(map[string]map[string]SessionStatus, len(coordinators))
	for namespace, coordinator := range coordinators {
		if coordinator == nil {
			continue
		}
		out[namespace] = coordinator.SnapshotSessionStatuses()
	}
	return out
}

func (r *Runtime) SnapshotNamespaceSessions(namespace string) map[string]*Session {
	coordinator, ok := r.Get(namespace)
	if !ok || coordinator == nil {
		return nil
	}
	return coordinator.SnapshotSessions()
}

func (r *Runtime) GetNamespaceSession(namespace, sessionID string) (*Session, bool) {
	coordinator, ok := r.Get(namespace)
	if !ok || coordinator == nil {
		return nil, false
	}
	return coordinator.GetSessionSnapshot(sessionID)
}

func (r *Runtime) SnapshotSessions() map[string]map[string]*Session {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	coordinators := make(map[string]*Coordinator, len(r.coordinators))
	for namespace, coordinator := range r.coordinators {
		coordinators[namespace] = coordinator
	}
	r.mu.RUnlock()

	out := make(map[string]map[string]*Session, len(coordinators))
	for namespace, coordinator := range coordinators {
		if coordinator == nil {
			continue
		}
		out[namespace] = coordinator.SnapshotSessions()
	}
	return out
}
