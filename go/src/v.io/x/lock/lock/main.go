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
	"v.io/v23/rpc"
	"v.io/v23/security"
	"v.io/v23/verror"

	"v.io/x/lib/cmdline"
	"v.io/x/lock"
	"v.io/x/lock/locklib"
	"v.io/x/ref/lib/v23cmd"
	_ "v.io/x/ref/runtime/factories/roaming"
)

const (
	// TODO(ataly): Define these conventions in the README
	recvKeySuffix          = "recvkey"
	lockUserNhPrefix       = "user-"
	lockUserNhGlobPrefix   = "nh/user-"
	vanadiumBlessingPrefix = "dev.v.io:u"
)

var (
	flagSendKeyExpiry time.Duration

	lockNhGlobPrefix = path.Join("nh", locklib.LockNhPrefix)
	cmdScan          = &cmdline.Command{
		Runner: v23cmd.RunnerFunc(runScan),
		Name:   "scan",
		Short:  "Scan the neighborhood for lock devices",
		Long: `
Searches for lock devices (both claimed and unclaimed) nearby.
`,
	}
	cmdUsers = &cmdline.Command{
		Runner: v23cmd.RunnerFunc(runUsers),
		Name:   "users",
		Short:  "Scan the neighborhood for physical-lock users",
		Long: `
Searches for physical-lock users nearby.
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
<lock> <key>

TODO(ataly, ashankar): Also print additional information such as when and
from whom was the key obtained.
`,
	}
	cmdRecvKey = &cmdline.Command{
		Runner: v23cmd.RunnerFunc(runRecvKey),
		Name:   "recvkey",
		Short:  "Receive keys to locks sent by another user",
		Long: `
Allows another physical-lock user to send a physical-lock key to this
client.

This command sets up the invoker (this process) to wait for a key to be
sent to this process. On receiving such a key, the process prints out the
key and lock name specified by the sender and asks for the invoker's
permission to save the key.

If permission is granted then the key is saved and the process returns,
otherwise the key is discarded and the command continues to wait for other
keys.
`,
	}
	cmdSendKey = &cmdline.Command{
		Runner: v23cmd.RunnerFunc(runSendKey),
		Name:   "sendkey",
		Short:  "Send keys to other users",
		Long: `
Allows this client to send a physical-lock key to another physical-lock user
present in the neighbordhood (See also: users).

An expiration time can be set on the key via the --for flag.
`,
		ArgsName: "<lock> <user> <category>",
		ArgsLong: `
<lock> is the name of the physical-lock whose key must be sent,
<user> is the physical-lock user to whom the key must be sent, and
<category> is how you'd like to classify the user (e.g., "friend",
"spouse", "colleague", etc.)
`,
	}
)

func runScan(ctx *context.T, env *cmdline.Env, args []string) error {
	ctx, stop, err := withLocalNamespace(ctx, "", lockUserNhName(ctx))
	if err != nil {
		return err
	}
	defer stop()

	fmt.Println("Scanning for Locks...")
	if err := doGlob(ctx, lockNhGlobPrefix); err != nil {
		return err
	}
	return nil
}

func runUsers(ctx *context.T, env *cmdline.Env, args []string) error {
	ctx, stop, err := withLocalNamespace(ctx, "", lockUserNhName(ctx))
	if err != nil {
		return err
	}
	defer stop()

	fmt.Println("Scanning for Users...")
	if err := doGlob(ctx, lockUserNhGlobPrefix); err != nil {
		return err
	}
	return nil
}

func doGlob(ctx *context.T, globPrefix string) error {
	globPattern := globPrefix + "*"
	found := make(map[string]bool)
	for {
		ch, err := v23.GetNamespace(ctx).Glob(ctx, globPattern)
		if err != nil {
			return err
		}
		for v := range ch {
			switch entry := v.(type) {
			case *naming.GlobReplyEntry:
				if name, servers := entry.Value.Name, entry.Value.Servers; len(name) != 0 && !found[name] && len(servers) != 0 {
					epStr, _ := naming.SplitAddressName(servers[0].Server)
					ep, err := v23.NewEndpoint(epStr)
					if err != nil {
						continue
					}

					found[name] = true
					printName(name, globPrefix, ep.BlessingNames())
				}
			}
		}
	}
}

func printName(name, prefix string, blessings []string) {
	if !strings.HasPrefix(name, prefix) {
		return
	}
	name = strings.TrimPrefix(name, prefix)

	if len(blessings) != 0 {
		fmt.Printf("%v [owned by %v]\n", name, blessings)
	} else {
		fmt.Printf("%v\n", name)
	}
}

func runClaim(ctx *context.T, env *cmdline.Env, args []string) error {
	if numargs := len(args); numargs != 2 {
		return fmt.Errorf("requires exactly two arguments <lock>, <name>, provided %d", numargs)
	}
	lockName, name := args[0], args[1]

	ctx, stop, err := withLocalNamespace(ctx, "", lockUserNhName(ctx))
	if err != nil {
		return err
	}
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	// TODO(ataly): We should not skip server endpoint authorization while
	// claiming locks but instead fetch the blessing root of the lock manufacturer
	// from an authoritative source and then appropriately authenticate the server.
	b, err := lock.UnclaimedLockClient(lockObjName(lockName)).Claim(
		ctx,
		name,
		options.ServerAuthorizer{security.AllowEveryone()})
	if err != nil {
		return err
	}

	p := v23.GetPrincipal(ctx)
	if err := security.AddToRoots(p, b); err != nil {
		return fmt.Errorf("failed to add (key) blessing (%v) to roots: %v", b, err)
	}
	if _, err := p.BlessingStore().Set(b, security.BlessingPattern(name)); err != nil {
		return fmt.Errorf("failed to set (key) blessing (%v) for peer %v: %v", b, name, err)
	}
	fmt.Printf("Claimed lock: %v as %v and received key: %v\n", lockName, name, b)
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

	ctx, stop, err := withLocalNamespace(ctx, "", lockUserNhName(ctx))
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

	ctx, stop, err := withLocalNamespace(ctx, "", lockUserNhName(ctx))
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
	const format = "%-30s   %s (Expires: %s)\n"

	fmt.Printf(format, "Lock", "Key", "<expiry time>")
	for lock, key := range peerBlessings {
		if !isValidLockName(string(lock)) {
			continue
		}
		if !isKeyValidForLock(ctx, key, string(lock)) {
			continue
		}
		var (
			expiresIn string
			now       = time.Now()
		)
		if exp := key.Expiry(); !exp.IsZero() && exp.Before(now) {
			// TODO(ataly): Remove the key from the blessing
			// store.
			continue
		} else if exp.IsZero() {
			expiresIn = "NEVER"
		} else {
			expiresIn = fmt.Sprintf("in %v", exp.Sub(now))
		}
		fmt.Printf(format, lock, key, expiresIn)
	}
	return nil
}

func runRecvKey(ctx *context.T, env *cmdline.Env, args []string) error {
	ctx, stop, err := withLocalNamespace(ctx, "", lockUserNhName(ctx))
	if err != nil {
		return err
	}
	defer stop()

	service := &recvKeyService{
		env:    env,
		notify: make(chan error),
	}
	ctx, cancel := context.WithCancel(ctx)
	_, server, err := v23.WithNewServer(ctx, recvKeySuffix, service, security.AllowEveryone())
	if err != nil {
		return fmt.Errorf("failed to create server to receive keys: %v", err)
	}
	defer func() {
		cancel()
		<-server.Closed()
	}()
	fmt.Println("Waiting for keys")
	return <-service.notify
}

func runSendKey(ctx *context.T, env *cmdline.Env, args []string) error {
	if numargs := len(args); numargs != 3 {
		return fmt.Errorf("requires exactly three arguments <lock> <user> <category>, provided %d", numargs)
	}
	lockName, user, category := args[0], args[1], args[2]

	ctx, stop, err := withLocalNamespace(ctx, "", lockUserNhName(ctx))
	if err != nil {
		return err
	}
	defer stop()

	key, err := keyForLock(ctx, lockName)
	if err != nil {
		return err
	}

	fmt.Printf("Sending key %v (extended with %v) to user %v\n", key, category, user)
	client := v23.GetClient(ctx)
	granter := &granter{lockName: lockName, key: key, category: category, expiry: flagSendKeyExpiry, user: user}
	if err := client.Call(ctx, recvKeyObjName(user), "Grant", []interface{}{lockName}, nil, granter); err != nil {
		return fmt.Errorf("failed to send key to %q: %v", user, err)
	}
	return nil
}

// Starts a mounttable server and returns a new context derived from
// the provided one by attaching a namespace instance rooted at the
// started mounttable server.
func withLocalNamespace(ctx *context.T, mtName, nhName string) (*context.T, func(), error) {
	configDir, err := ioutil.TempDir("", "mounttable-config")
	if err != nil {
		return nil, nil, err
	}
	mtName, stopMT, err := locklib.StartMounttable(ctx, configDir, nhName)
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

// vUser returns a comma-separated string of user identities obtained
// from the provided blessing names.
//
// For each blessing name, vUser checks if it matches the pattern
// 'vanadiumBlessingPrefix' and if so constructs the user identity by
// stripping off 'vanadiumBlessingPrefix' from the blessing name.
// Otherwise the user identity is simply the blessing name.
//
// In all case, the user identity is converted into a valid neighborhood-name
// by replacing slahes with "@@".
// TODO(ataly): Try to use conventions.GetClientUserIds instead.
func vUser(bNames ...string) string {
	nhFriendly := func(b string) string {
		return strings.Replace(b, security.ChainSeparator, "@@", -1)
	}
	users := make([]string, len(bNames))
	for i, b := range bNames {
		if !security.BlessingPattern(vanadiumBlessingPrefix).MatchedBy(b) {
			users[i] = nhFriendly(b)
			continue
		}
		users[i] = nhFriendly(strings.TrimPrefix(b, vanadiumBlessingPrefix+security.ChainSeparator))
	}
	return strings.Join(users, ",")
}

func lockUserNhName(ctx *context.T) string {
	var (
		principal    = v23.GetPrincipal(ctx)
		blessings, _ = principal.BlessingStore().Default()
		bNames       = security.BlessingNames(principal, blessings)
	)
	return lockUserNhPrefix + vUser(bNames...)
}

func recvKeyObjName(user string) string {
	return path.Join(lockUserNhGlobPrefix+user, recvKeySuffix)
}

func lockObjName(lockName string) string {
	return path.Join(lockNhGlobPrefix+lockName, locklib.LockSuffix)
}

func main() {
	cmdSendKey.Flags.DurationVar(&flagSendKeyExpiry, "for", 0, "Duration of key validity (zero implies no expiration)")
	cmdline.HideGlobalFlagsExcept()
	root := &cmdline.Command{
		Name:  "lock",
		Short: "claim and manage locks",
		Long: `
Command lock claims and manages lock devices.
`,
		Children: []*cmdline.Command{cmdScan, cmdUsers, cmdClaim, cmdLock, cmdUnlock, cmdStatus, cmdListKeys, cmdRecvKey, cmdSendKey},
	}
	cmdline.Main(root)
}

type recvKeyService struct {
	principal security.Principal
	env       *cmdline.Env
	notify    chan error
}

func (r *recvKeyService) confirmRecvKey() bool {
	text, err := readFromStdin(r.env, `Do you want to save this key? (YES to confirm)`)
	if err != nil || strings.ToUpper(text) != "YES" {
		return false
	}
	return true
}

func (r *recvKeyService) Grant(ctx *context.T, call rpc.ServerCall, lockName string) error {
	key := call.GrantedBlessings()
	remoteBlessingNames, _ := security.RemoteBlessingNames(ctx, call.Security())

	fmt.Printf("Received key %v for lock %v from user %v\n", key, lockName, vUser(remoteBlessingNames...))
	if !r.confirmRecvKey() {
		return NewErrKeyRejected(ctx, fmt.Sprintf("%v", key), lockName)
	}

	if err := saveKeyForLock(ctx, key, lockName); err != nil {
		return verror.Convert(verror.ErrInternal, ctx, err)
	}
	fmt.Println("Key successfully saved")
	r.notify <- nil
	return nil
}

type granter struct {
	lockName string
	key      security.Blessings
	category string
	expiry   time.Duration
	user     string
}

func (g *granter) Grant(ctx *context.T, call security.Call) (security.Blessings, error) {
	// Verify that the remote end's blessings encapsulates the
	// same user identity as g.user.
	remoteBlessingNames, _ := security.RemoteBlessingNames(ctx, call)
	authorized := false
	for _, b := range remoteBlessingNames {
		if vUser(b) == g.user {
			authorized = true
		}
	}
	if !authorized {
		return security.Blessings{}, fmt.Errorf("remote end presented blessings %v, want a blessing for user %v", remoteBlessingNames, g.user)
	}

	peerPattern := security.BlessingPattern(g.lockName)
	onlyThisLockCav, err := security.NewCaveat(security.PeerBlessingsCaveat, []security.BlessingPattern{peerPattern})
	if err != nil {
		return security.Blessings{}, fmt.Errorf("failed to create peer blessings caveat for key: %v", err)
	}

	caveats := []security.Caveat{onlyThisLockCav}
	if g.expiry != 0 {
		expiryCav, err := security.NewExpiryCaveat(time.Now().Add(g.expiry))
		if err != nil {
			return security.Blessings{}, fmt.Errorf("failed to create expiration caveat for key: %v", err)
		}
		caveats = append(caveats, expiryCav)
	}
	return call.LocalPrincipal().Bless(call.RemoteBlessings().PublicKey(), g.key, g.category, caveats[0], caveats[1:]...)
}

func (*granter) RPCCallOpt() {}
