// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"strings"

	"v.io/v23"
	"v.io/v23/context"
	"v.io/v23/security"

	"v.io/x/lib/cmdline"
	"v.io/x/lib/vlog"
)

func isValidLockName(lockName string) bool {
	// TODO(ataly): HACK!! We should either store the set of valid names
	// in a file that is managed by this client or somehow note in the
	// blessing store whether a peer pattern is the name of a lock object.
	return lockName != string(security.AllPrincipals) && !strings.ContainsAny(lockName, security.ChainSeparator)
}

func isKeyValidForLock(ctx *context.T, key security.Blessings, lockName string) bool {
	bp := security.BlessingPattern(lockName + security.ChainSeparator + "key")
	for _, b := range security.BlessingNames(v23.GetPrincipal(ctx), key) {
		if bp.MatchedBy(b) {
			return true
		}
	}
	return false
}

func keyForLock(ctx *context.T, lockName string) (security.Blessings, error) {
	// We could simply return  v23.GetPrincipal(ctx).BlessingStore().ForPeer(lock)
	// however this would also include any blessings tagged for a peer pattern
	// is matched by 'lock'. Therefore we iterate over all the blessings
	// and pick the specific ones that are meant for 'lock'.
	var ret security.Blessings
	for _, b := range v23.GetPrincipal(ctx).BlessingStore().PeerBlessings() {
		if isKeyValidForLock(ctx, b, lockName) {
			if union, err := security.UnionOfBlessings(ret, b); err != nil {
				vlog.Errorf("UnionOfBlessings(%v, %v) failed: %v, dropping latter blessing", ret, b, err)
			} else {
				ret = union
			}
		}
	}
	if ret.IsZero() {
		return security.Blessings{}, fmt.Errorf("no available key for lock %v", lockName)
	}
	return ret, nil
}

func saveKeyForLock(ctx *context.T, key security.Blessings, lockName string) error {
	if isKeyValidForLock(ctx, key, lockName) {
		return fmt.Errorf("key %v is not valid for lock %v", key, lockName)
	}
	p := v23.GetPrincipal(ctx)
	if _, err := p.BlessingStore().Set(key, security.BlessingPattern(lockName)); err != nil {
		return fmt.Errorf("failed to save key %v for lock %v", key, lockName)
	}
	if err := security.AddToRoots(p, key); err != nil {
		return fmt.Errorf("failed to save key %v for lock %v", key, lockName)
	}
	return nil
}

func readFromStdin(env *cmdline.Env, prompt string) (string, error) {
	fmt.Fprintf(env.Stdout, "%v ", prompt)
	os.Stdout.Sync()
	// Cannot use bufio because that may "lose" data beyond the line (the
	// remainder in the buffer).
	// Do the inefficient byte-by-byte scan for now - shouldn't be a problem
	// given the common use case. If that becomes a problem, switch to bufio
	// and share the bufio.Reader between multiple calls to readFromStdin.
	buf := make([]byte, 0, 100)
	r := make([]byte, 1)
	for {
		n, err := env.Stdin.Read(r)
		if n == 1 && r[0] == '\n' {
			break
		}
		if n == 1 {
			buf = append(buf, r[0])
			continue
		}
		if err != nil {
			return "", err
		}
	}
	return strings.TrimSpace(string(buf)), nil
}
