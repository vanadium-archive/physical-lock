// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"v.io/v23"
	"v.io/v23/context"
	"v.io/v23/rpc"
	"v.io/v23/security"
	"v.io/v23/verror"

	"v.io/x/lib/vlog"
	"v.io/x/lock"
)

const (
	claimFileName        = "claimed_lock"
	keyBlessingExtension = "key"
)

type unclaimedLock struct {
	configDir string
	claimed   chan<- struct{} // GUARDED_BY(mu)

	// Mutex to ensure that a successful claim can happen at most once.
	mu sync.Mutex
}

func (ul *unclaimedLock) Claim(ctx *context.T, call rpc.ServerCall, name string) (security.Blessings, error) {
	vlog.Infof("Claim called by %q", call.Security().RemoteBlessings())
	if strings.ContainsAny(name, security.ChainSeparator) {
		// TODO(ataly, ashankar): We have to error out in this case because of the current
		// neighborhood setup wherein the neighborhood-name of a claimed lock's mounttable is
		// the same as the locks's name. Since neighborhood-names aren't allowed to contain
		// slashes, we have to disallow slashes in the lock name as well.
		return security.Blessings{}, NewErrInvalidLockName(ctx, name, security.ChainSeparator)
	}

	var (
		principal   = v23.GetPrincipal(ctx)
		origDefault = principal.BlessingStore().Default()
		restore     = func() error {
			// TODO(ataly): Remove roots of current default blessing if needed
			// (i.e., if current default != origDefault).
			if err := principal.BlessingStore().SetDefault(origDefault); err != nil {
				return verror.Convert(verror.ErrInternal, ctx, err)
			}
			return nil
		}
	)

	defer ul.mu.Unlock()
	ul.mu.Lock()

	if ul.claimed == nil {
		return security.Blessings{}, NewErrLockAlreadyClaimed(ctx)
	}

	keyBlessing, err := ul.makeKey(principal, name, call.Security().RemoteBlessings().PublicKey())
	if err != nil {
		restore()
		return security.Blessings{}, verror.Convert(verror.ErrInternal, ctx, err)
	}

	// Create a file in the config directory to indicate that lock has been claimed.
	f, err := os.Create(filepath.Join(ul.configDir, claimFileName))
	if err != nil {
		restore()
		return security.Blessings{}, verror.Convert(verror.ErrInternal, ctx, err)
	}
	f.Close()

	close(ul.claimed)
	ul.claimed = nil
	vlog.Infof("Lock successfullly claimed with name %q", name)
	return keyBlessing, nil
}

func (ul *unclaimedLock) makeKey(principal security.Principal, name string, remoteKey security.PublicKey) (security.Blessings, error) {
	lockBlessing, err := principal.BlessSelf(name)
	if err != nil {
		return security.Blessings{}, err
	}

	if err := principal.BlessingStore().SetDefault(lockBlessing); err != nil {
		return security.Blessings{}, err
	}
	if err := security.AddToRoots(principal, lockBlessing); err != nil {
		return security.Blessings{}, err
	}

	// Add a caveat to the "key" blessing so that it can only be used to talking
	// to this lock object.
	// TODO(ataly): Add a client-only caveat as well so that someone who obtains
	// this blessing or an extension of it cannot maliciously (or accidentally)
	// start a server with this blessing (such a server could impersonate this
	// lock object).
	peerPattern := security.BlessingPattern(name)
	onlyThisLockCav, err := security.NewCaveat(security.PeerBlessingsCaveat, []security.BlessingPattern{peerPattern})
	if err != nil {
		return security.Blessings{}, err
	}
	keyBlessing, err := principal.Bless(remoteKey, lockBlessing, keyBlessingExtension, onlyThisLockCav)
	if err != nil {
		return security.Blessings{}, err
	}
	return keyBlessing, nil
}

func isLockClaimed(configDir string) bool {
	if _, err := os.Stat(filepath.Join(configDir, claimFileName)); err == nil {
		return true
	}
	return false
}

func newUnclaimedLock(claimed chan<- struct{}, configDir string) lock.UnclaimedLockServerStub {
	return lock.UnclaimedLockServer(&unclaimedLock{configDir: configDir, claimed: claimed})
}
