// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"

	"v.io/v23"
	"v.io/v23/context"
	"v.io/v23/naming"
	"v.io/v23/security"
	"v.io/x/lib/vlog"
	"v.io/x/lock/locklib"
)

var unclaimedLockNhSuffix = "unclaimed-lock-" + fmt.Sprintf("%d", rand.Intn(1000000))

// startServer checks whether the lock has been claimed and then appropriately
// starts the server.
//
// Returns the callback to be invoked to shutdown the server on success, or
// an error on failure
func startServer(ctx *context.T, configDir string) (func(), error) {
	// The lock is claimed if and only if there exists a file in the
	// config directory from a previous claim.
	if isLockClaimed(configDir) {
		return startLockServer(ctx, configDir)
	}

	claimed, stopUnclaimedLock, err := startUnclaimedLockServer(ctx, configDir)
	if err != nil {
		return nil, err
	}

	stop := make(chan struct{})
	stopped := make(chan struct{})
	go waitToBeClaimedAndStartLockServer(ctx, configDir, stopUnclaimedLock, claimed, stop, stopped)
	return func() {
		close(stop)
		<-stopped
	}, nil
}

func startUnclaimedLockServer(ctx *context.T, configDir string) (<-chan struct{}, func(), error) {
	// Start a local mounttable where the unclaimed lock server would
	// be mounted, and make this mounttable visible in the local
	// neighborhood.
	mtName, stopMT, err := locklib.StartMounttable(ctx, configDir, locklib.LockNhPrefix+unclaimedLockNhSuffix)
	if err != nil {
		return nil, nil, err
	}
	ctx, _, err = v23.WithNewNamespace(ctx, mtName)
	if err != nil {
		stopMT()
		return nil, nil, err
	}
	claimed := make(chan struct{})
	_, server, err := v23.WithNewServer(ctx, lockObjectName(ctx), newUnclaimedLock(claimed, configDir), security.AllowEveryone())
	if err != nil {
		stopMT()
		return nil, nil, err
	}
	stopUnclaimedLock := func() {
		vlog.Infof("Stopping unclaimed lock server...")
		server.Stop()
		vlog.Infof("Stopped unclaimed lock server...")
		stopMT()
	}
	vlog.Infof("Started unclaimed lock server\n")
	vlog.Infof("ENDPOINT: %v\n", server.Status().Endpoints[0].Name())
	return claimed, stopUnclaimedLock, nil
}

func startLockServer(ctx *context.T, configDir string) (func(), error) {
	lockNhSuffix := fmt.Sprintf("%v", v23.GetPrincipal(ctx).BlessingStore().Default())
	// Start a local mounttable where the lock server would be
	// mounted, and make this mounttable visible in the local
	// neighborhood.
	mtName, stopMT, err := locklib.StartMounttable(ctx, configDir, locklib.LockNhPrefix+lockNhSuffix)
	if err != nil {
		return nil, err
	}
	ctx, _, err = v23.WithNewNamespace(ctx, mtName)
	if err != nil {
		stopMT()
		return nil, err
	}
	_, server, err := v23.WithNewServer(ctx, lockObjectName(ctx), newLock(), security.DefaultAuthorizer())
	if err != nil {
		stopMT()
		return nil, err
	}
	stopLock := func() {
		vlog.Infof("Stopping lock server...")
		server.Stop()
		vlog.Infof("Stopped lock server...")
		stopMT()
	}
	vlog.Infof("Started lock server\n")
	vlog.Infof("ENDPOINT: %v\n", server.Status().Endpoints[0].Name())
	return stopLock, nil
}

func waitToBeClaimedAndStartLockServer(ctx *context.T, configDir string, stopUnclaimedLock func(), claimed, stop <-chan struct{}, stopped chan<- struct{}) {
	defer close(stopped)
	select {
	case <-claimed:
		stopUnclaimedLock()
	case <-stop:
		stopUnclaimedLock()
		return
	}
	stopLock, err := startLockServer(ctx, configDir)
	if err != nil {
		vlog.Errorf("Failed to start lock server after it was claimed: %v", err)
		return
	}
	defer stopLock()
	<-stop // Wait to be stopped
}

func lockObjectName(ctx *context.T) string {
	nsroots := v23.GetNamespace(ctx).Roots()
	if len(nsroots) == 0 {
		return ""
	}
	return naming.Join(nsroots[0], locklib.LockSuffix)
}
