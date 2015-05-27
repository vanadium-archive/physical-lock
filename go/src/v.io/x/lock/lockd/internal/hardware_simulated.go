// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !arm

package internal

import (
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"sync"

	"v.io/x/lock"
)

type hw struct {
	mu     sync.Mutex
	status lock.LockStatus // GUARDED_BY(mu)
}

func init() {
	hw := &hw{status: lock.Unlocked}
	sigch := make(chan os.Signal)
	signal.Notify(sigch, os.Interrupt)
	go func() {
		for range sigch {
			fmt.Fprintln(os.Stderr, "simulated: externally initiated status change")
			if hw.Status() == lock.Locked {
				hw.setStatus(lock.Unlocked)
				continue
			}
			hw.setStatus(lock.Locked)
		}
	}()
	hardware = hw
	fmt.Fprintln(os.Stderr, "Using simulated hardware. Simulate external locking/unlocking with: kill -SIGINT", os.Getpid())
}

func (hw *hw) Status() lock.LockStatus {
	hw.mu.Lock()
	defer hw.mu.Unlock()
	return hw.status
}

func (hw *hw) SetStatus(status lock.LockStatus) error {
	// Randomly fail with 10% chance, just for fun.
	if rand.Intn(10) == 1 {
		return fmt.Errorf("simulated error: lock failed to toggle - check the door")
	}
	hw.setStatus(status)
	return nil
}

func (hw *hw) setStatus(status lock.LockStatus) {
	hw.mu.Lock()
	hw.status = status
	hw.mu.Unlock()
}
