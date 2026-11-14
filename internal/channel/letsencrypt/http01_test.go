package letsencrypt

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildHTTP01ChallengePathRejectsEmptyToken(t *testing.T) {
	if _, err := BuildHTTP01ChallengePath("   "); err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestLockDomainSerializesSameDomain(t *testing.T) {
	le := &LetsEncrypt{
		domainLocks: make(map[string]*sync.Mutex),
	}

	var active int32
	var maxActive int32
	var wg sync.WaitGroup

	updateMax := func(v int32) {
		for {
			cur := atomic.LoadInt32(&maxActive)
			if v <= cur {
				return
			}
			if atomic.CompareAndSwapInt32(&maxActive, cur, v) {
				return
			}
		}
	}

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			unlock := le.lockDomain("api.example.com")
			defer unlock()

			current := atomic.AddInt32(&active, 1)
			updateMax(current)
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&active, -1)
		}()
	}

	wg.Wait()
	if got := atomic.LoadInt32(&maxActive); got != 1 {
		t.Fatalf("same-domain lock is not serialized, max active=%d", got)
	}
}
