// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package locklib

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"v.io/v23"
	"v.io/v23/context"
	"v.io/v23/security"
	"v.io/v23/security/access"
	"v.io/v23/services/mounttable"

	"v.io/x/lib/vlog"
	"v.io/x/ref/services/mounttable/mounttablelib"
)

const (
	permsFile = "mounttable.perms"
	// LockSuffix is the name under which a lock server is mounted in its
	// mounttable.
	LockSuffix = "lock"
	// LockNeighborhoodPrefix is a prefix of the name in the local
	// neighborhood on which a lock server's mounttable is made
	// visible.
	LockNhPrefix = "lock-"
)

// StartMounttable starts a local mounttable server with an authorization
// policy that allows all principals to "Resolve" names, but restricts all
// other operations to the principal specified by the provided context.
//
// The mounttable makes itself visible in the local neighborhood under the
// name LockNeighborhoodPrefix + <nhName>.
//
// Returns the endpoint of the mounttable server and a callback to
// be invoked to shutdown the mounttable server on success, or an error
// on failure.
func StartMounttable(ctx *context.T, configDir string, nhName string) (string, func(), error) {
	if len(configDir) == 0 {
		return "", nil, errors.New("could not start mounttable, config directory not provided")
	}
	permFilePath := filepath.Join(configDir, permsFile)
	if err := initPermissions(permFilePath); err != nil {
		return "", nil, fmt.Errorf("could not initialize permissions file (%v) for mounttable: %v", permFilePath, err)
	}
	mtName, stopMT, err := mounttablelib.StartServers(ctx, v23.GetListenSpec(ctx), "", nhName, permFilePath, "", "mounttable")
	if err != nil {
		vlog.Errorf("mounttablelib.StartServers failed: %v", err)
		return "", nil, err
	}
	vlog.Infof("Started local mounttable at: %v", mtName)
	return mtName, func() {
		vlog.Infof("Stopping mounttable...")
		stopMT()
		vlog.Infof("Stopped mounttable.")
	}, nil
}

func initPermissions(permFilePath string) error {
	f, err := os.OpenFile(permFilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()

	perm := make(map[string]access.Permissions)
	perm[""] = make(access.Permissions)
	perm[""].Add(security.AllPrincipals, string(mounttable.Resolve))
	perm[""].Add(security.AllPrincipals, string(mounttable.Read))

	if err := json.NewEncoder(f).Encode(perm); err != nil {
		return err
	}
	return nil
}
