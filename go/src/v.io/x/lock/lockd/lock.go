// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"sync"

	"v.io/v23/context"
	"v.io/v23/rpc"
	"v.io/v23/security"

	"v.io/x/lib/vlog"
	"v.io/x/lock"
)

type lockImpl struct {
	status lock.LockStatus
	mu     sync.RWMutex
}

func (l *lockImpl) Lock(ctx *context.T, call rpc.ServerCall) error {
	remoteBlessingNames, _ := security.RemoteBlessingNames(ctx, call.Security())
	vlog.Infof("Lock called by %q", remoteBlessingNames)

	defer l.mu.Unlock()
	l.mu.Lock()

	l.status = lock.Locked
	// Instruct the hardware to appropriately change state.

	vlog.Info("Updated lock to status: UNLOCKED")
	return nil
}

func (l *lockImpl) Unlock(ctx *context.T, call rpc.ServerCall) error {
	remoteBlessingNames, _ := security.RemoteBlessingNames(ctx, call.Security())
	vlog.Infof("Unlock called by %q", remoteBlessingNames)

	defer l.mu.Unlock()
	l.mu.Lock()

	l.status = lock.Unlocked
	// Instruct the hardware to appropriately change state.

	vlog.Info("Updated lock to status: UNLOCKED")
	return nil
}

func (l *lockImpl) Status(ctx *context.T, call rpc.ServerCall) (lock.LockStatus, error) {
	remoteBlessingNames, _ := security.RemoteBlessingNames(ctx, call.Security())
	vlog.Infof("Status called by %q", remoteBlessingNames)

	defer l.mu.RUnlock()
	l.mu.RLock()

	return l.status, nil
}

func newLock() lock.LockServerStub {
	// At the moment we always create the lock object in locked state.
	// For a real device, the lock would be initialized based on the state
	// determined by the hardware sensors.
	return lock.LockServer(&lockImpl{status: lock.Locked})
}
