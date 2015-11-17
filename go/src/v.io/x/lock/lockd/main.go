// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"os"

	"v.io/v23/context"

	"v.io/x/lib/cmdline"
	"v.io/x/ref/lib/signals"
	"v.io/x/ref/lib/v23cmd"
	_ "v.io/x/ref/runtime/factories/roaming"
)

var configDir string

func main() {
	cmdRoot.Flags.StringVar(&configDir, "config-dir", "", "Directory where the lock configuration files are stored. It will be created if it does not exist.")
	cmdline.HideGlobalFlagsExcept()
	cmdline.Main(cmdRoot)
}

var cmdRoot = &cmdline.Command{
	Runner: v23cmd.RunnerFunc(runLockD),
	Name:   "lockd",
	Short:  "Runs the lockd server",
	Long: `
Command lockd runs the lockd server, which implements the UnclaimedLock or the Lock interface depending
on the files in the configuration directory.
`,
}

func runLockD(ctx *context.T, env *cmdline.Env, args []string) error {
	if len(configDir) == 0 {
		return errors.New("--config-dir must be specified")
	}
	if finfo, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, os.FileMode(0700)); err != nil {
			return fmt.Errorf("could not create configuration directory %v: %v", configDir, err)
		}
	} else if err != nil || !finfo.IsDir() {
		return fmt.Errorf("--config-dir=%v is not a directory", configDir)
	}

	shutdown, err := startServer(ctx, configDir)
	if err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}
	<-signals.ShutdownOnSignals(ctx)
	shutdown()
	return nil
}
