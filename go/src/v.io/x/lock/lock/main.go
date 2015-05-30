// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"v.io/v23"
	"v.io/v23/context"
	"v.io/v23/naming"
	"v.io/v23/options"
	"v.io/v23/security"
	"v.io/x/lib/cmdline"
	"v.io/x/lock"
	"v.io/x/lock/locklib"

	"v.io/x/ref/lib/v23cmd"
	_ "v.io/x/ref/runtime/factories/static"
)

var (
	lockNhNamePrefix = path.Join("nh", locklib.LockNhPrefix)
	cmdScan          = &cmdline.Command{
		Runner: v23cmd.RunnerFunc(runScan),
		Name:   "scan",
		Short:  "Scan the neighborhood for lock devices",
		Long: `
Globs over the neighborhood to find lock devices (both claimed
and unclaimed).
`,
	}
	cmdClaim = &cmdline.Command{
		Runner: v23cmd.RunnerFunc(runClaim),
		Name:   "claim",
		Short:  "Claim the specified lock with the provided name",
		Long: `
Claims the specified unclaimed lock with the provided name, and authorizes the
principal executing this command to access the claimed lock.
`,
		ArgsName: "<lock> <name>",
		ArgsLong: `
<lock> is the name of the unclaimed lock.
<name> is a name that you'd like to give to the lock, for example,
"my_front_door" or "123_main_street.
`,
	}
	cmdLock = &cmdline.Command{
		Runner: v23cmd.RunnerFunc(runLock),
		Name:   "lock",
		Short:  "Lock the specified lock",
		Long: `
Locks the specified lock.
`,
		ArgsName: "<lock>",
		ArgsLong: `
<lock> is the name of the lock.
`,
	}
	cmdUnlock = &cmdline.Command{
		Runner: v23cmd.RunnerFunc(runUnlock),
		Name:   "unlock",
		Short:  "Unlock the specified lock",
		Long: `
Unlocks the specified lock.
`,
		ArgsName: "<lock>",
		ArgsLong: `
<lock> is the name of the lock.
`,
	}
	cmdStatus = &cmdline.Command{
		Runner: v23cmd.RunnerFunc(runStatus),
		Name:   "status",
		Short:  "Print the current status of the specified lock",
		Long: `
Prints the current status of the specified lock.
`,
		ArgsName: "<lock>",
		ArgsLong: `
<lock> is the name of the lock.
`,
	}
	cmdListKeys = &cmdline.Command{
		Runner: v23cmd.RunnerFunc(runListKeys),
		Name:   "listkeys",
		Short:  "List the set of available keys",
		Long: `
Lists the set of available physical-lock keys and the names of the locks
to which they apply.

Each line of the list is of the form
<lock name> <key>

TODO(ataly, ashankar): Also print additional information such as when and
from whom was the key obtained.
`,
	}
)

func runScan(ctx *context.T, env *cmdline.Env, args []string) error {
	ctx, stop, err := withLocalNamespace(ctx)
	if err != nil {
		return err
	}
	defer stop()

	lockGlobPattern := lockNhNamePrefix + "*"
	locksFound := make(map[string]bool)
	fmt.Println("Scanning for Locks...")
	for {
		ch, err := v23.GetNamespace(ctx).Glob(ctx, lockGlobPattern)
		if err != nil {
			return err
		}
		for v := range ch {
			switch entry := v.(type) {
			case *naming.GlobReplyEntry:
				if name, servers := entry.Value.Name, entry.Value.Servers; len(name) != 0 && !locksFound[name] && len(servers) != 0 {
					epStr, _ := naming.SplitAddressName(servers[0].Server)
					ep, err := v23.NewEndpoint(epStr)
					if err != nil {
						continue
					}

					locksFound[name] = true
					printLockName(name, ep.BlessingNames())
				}
			}
		}
	}
}

func printLockName(name string, blessings []string) {
	if !strings.HasPrefix(name, lockNhNamePrefix) {
		return
	}
	lockName := strings.TrimPrefix(name, lockNhNamePrefix)

	if len(blessings) != 0 {
		fmt.Printf("%v [owned by %v]\n", lockName, blessings)
	} else {
		fmt.Printf("%v\n", lockName)
	}
}

func runClaim(ctx *context.T, env *cmdline.Env, args []string) error {
	if numargs := len(args); numargs != 2 {
		return fmt.Errorf("requires exactly two arguments <lock>, <name>, provided %d", numargs)
	}
	lockName, name := args[0], args[1]

	ctx, stop, err := withLocalNamespace(ctx)
	if err != nil {
		return err
	}
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	// TODO(ataly): We should not skip server endpoint authorization while
	// claiming locks but instead fetch the blessing root of the lock manufacturer
	// from an authoritative source and then appropriately authenticate the server.
	b, err := lock.UnclaimedLockClient(lockObjName(lockName)).Claim(ctx, name, options.SkipServerEndpointAuthorization{})
	if err != nil {
		return err
	}

	p := v23.GetPrincipal(ctx)
	if err := p.AddToRoots(b); err != nil {
		return fmt.Errorf("failed to add (key) blessing (%v) to roots: %v", b, err)
	}
	if _, err := p.BlessingStore().Set(b, security.BlessingPattern(name)); err != nil {
		return fmt.Errorf("failed to set (key) blessing (%v) for peer %v: %v", b, name, err)
	}
	fmt.Printf("Claimed lock: %v and received key: %v\n", lockName, b)
	return nil
}

func runLock(ctx *context.T, env *cmdline.Env, args []string) error {
	return updateStatus(ctx, args, lock.Locked)
}

func runUnlock(ctx *context.T, env *cmdline.Env, args []string) error {
	return updateStatus(ctx, args, lock.Unlocked)
}

func updateStatus(ctx *context.T, args []string, status lock.LockStatus) error {
	if numargs := len(args); numargs != 1 {
		return fmt.Errorf("requires exactly one arguments <lock>, provided %d", numargs)
	}
	lockName := args[0]

	ctx, stop, err := withLocalNamespace(ctx)
	if err != nil {
		return err
	}
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if status == lock.Locked {
		err = lock.LockClient(lockObjName(lockName)).Lock(ctx)
	} else {
		err = lock.LockClient(lockObjName(lockName)).Unlock(ctx)
	}
	if err != nil {
		return err
	}

	fmt.Printf("Updated lock %v to status: %v\n", lockName, status)
	return nil
}

func runStatus(ctx *context.T, env *cmdline.Env, args []string) error {
	if numargs := len(args); numargs != 1 {
		return fmt.Errorf("requires exactly one arguments <lock>, provided %d", numargs)
	}
	lockName := args[0]

	ctx, stop, err := withLocalNamespace(ctx)
	if err != nil {
		return err
	}
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	status, err := lock.LockClient(lockObjName(lockName)).Status(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("lock %v is: %v\n", lockName, status)
	return nil
}

func runListKeys(ctx *context.T, env *cmdline.Env, args []string) error {
	peerBlessings := v23.GetPrincipal(ctx).BlessingStore().PeerBlessings()
	const format = "%-30s   %s\n"

	fmt.Printf(format, "Lock", "Key")
	for lock, key := range peerBlessings {
		if !isValidLockName(string(lock)) {
			continue
		}
		if !isKeyValidForLock(ctx, key, string(lock)) {
			continue
		}
		fmt.Printf(format, lock, key)
	}
	return nil
}

// Starts a mounttable server for listening to lock server location
// advertisements, and returns a new context derived from the provided
// one by attaching a namespace instance rooted at the started
// mounttable server.
func withLocalNamespace(ctx *context.T) (*context.T, func(), error) {
	configDir, err := ioutil.TempDir("", "mounttable-config")
	if err != nil {
		return nil, nil, err
	}
	// TODO(ataly): Currently a non-empty neighborhood name must be provided
	// to StartMounttable in order to make it listen to MDNS advertisements.
	// This has the downside that it also makes the started mounttable
	// adverstised itself under the provided name. Below the string "ignore"
	// is used as the neighborhood name in order to easily identify (and ignore)
	// the namespace under it in other mounttables. The right solution is to
	// start the mounttable so that it only listens to MDNS advertisements but
	// does not advertise itself.
	mtName, stopMT, err := locklib.StartMounttable(ctx, configDir, "ignore")
	if err != nil {
		os.RemoveAll(configDir)
		return nil, nil, err
	}

	stop := func() {
		stopMT()
		os.RemoveAll(configDir)
	}

	ctx, _, err = v23.WithNewNamespace(ctx, mtName)
	if err != nil {
		stop()
		return nil, nil, err
	}
	return ctx, stop, nil
}

func lockObjName(lockName string) string {
	return path.Join(lockNhNamePrefix+lockName, locklib.LockSuffix)
}

func isValidLockName(lock string) bool {
	// TODO(ataly): HACK!! We should either store the set of valid names
	// in a file that is managed by this client or somehow note in the
	// blessing store whether a peer pattern is the name of a lock object.
	return lock != string(security.AllPrincipals) && !strings.ContainsAny(string(lock), security.ChainSeparator)
}

func isKeyValidForLock(ctx *context.T, key security.Blessings, lock string) bool {
	bp := security.BlessingPattern(lock + security.ChainSeparator + "key")
	for b, _ := range v23.GetPrincipal(ctx).BlessingsInfo(key) {
		if bp.MatchedBy(b) {
			return true
		}
	}
	return false
}

func main() {
	cmdline.HideGlobalFlagsExcept()
	root := &cmdline.Command{
		Name:  "lock",
		Short: "claim and manage locks",
		Long: `
Command lock claims and manages lock devices.
`,
		Children: []*cmdline.Command{cmdScan, cmdClaim, cmdLock, cmdUnlock, cmdStatus, cmdListKeys},
	}
	cmdline.Main(root)
}
