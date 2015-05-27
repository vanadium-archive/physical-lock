// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"v.io/v23/context"
	"v.io/v23/rpc"
	"v.io/v23/security"

	"v.io/x/lib/vlog"
	"v.io/x/lock"

	"v.io/x/lock/lockd/internal"
)

type lockImpl struct {
	hw internal.Hardware
}

func (l *lockImpl) Lock(ctx *context.T, call rpc.ServerCall) error {
	remoteBlessingNames, _ := security.RemoteBlessingNames(ctx, call.Security())
	vlog.Infof("Lock called by %q", remoteBlessingNames)
	return l.hw.SetStatus(lock.Locked)
}

func (l *lockImpl) Unlock(ctx *context.T, call rpc.ServerCall) error {
	remoteBlessingNames, _ := security.RemoteBlessingNames(ctx, call.Security())
	vlog.Infof("Unlock called by %q", remoteBlessingNames)
	return l.hw.SetStatus(lock.Unlocked)
}

func (l *lockImpl) Status(ctx *context.T, call rpc.ServerCall) (lock.LockStatus, error) {
	remoteBlessingNames, _ := security.RemoteBlessingNames(ctx, call.Security())
	vlog.Infof("Status called by %q", remoteBlessingNames)
	return l.hw.Status(), nil
}

func newLock() lock.LockServerStub {
	return lock.LockServer(&lockImpl{hw: internal.GetHardware()})
}
