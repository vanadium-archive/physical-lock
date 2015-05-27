// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm

package internal

import (
	"fmt"
	"sync"
	"time"

	"github.com/davecheney/gpio"
	"github.com/davecheney/gpio/rpi"

	"v.io/x/lock"
)

const toggleWaitTime = 5 * time.Second

type hw struct {
	relay   gpio.Pin
	monitor gpio.Pin
	mu      sync.Mutex // To allow for only one SetStatus invocation at a time.
}

func init() {
	relay, err := gpio.OpenPin(rpi.GPIO17, gpio.ModeOutput)
	if err != nil {
		panic(err)
	}
	relay.Clear()

	monitor, err := gpio.OpenPin(rpi.GPIO22, gpio.ModeInput)
	if err != nil {
		relay.Close()
		panic(err)
	}

	hardware = &hw{relay: relay, monitor: monitor}
}

func (hw *hw) Status() lock.LockStatus {
	if hw.monitor.Get() {
		return lock.Unlocked
	}
	return lock.Locked
}

func (hw *hw) SetStatus(status lock.LockStatus) error {
	hw.mu.Lock()
	defer hw.mu.Unlock()
	desired := (status == lock.Unlocked)
	// TODO(ashankar): Change this to work with an actual relay. Currently
	// simulating the "motor" with an active buzzer.
	defer hw.relay.Clear()
	hw.relay.Set()
	start := time.Now()
	for hw.monitor.Get() != desired {
		if d := time.Since(start); d > toggleWaitTime {
			return fmt.Errorf("lock state unchanged after %v: might be stuck. aborting.", d)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}
