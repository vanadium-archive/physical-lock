// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Silly binary to test our the Hardware interface implementation without the
// rest of the lock implementation.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"v.io/x/lock"
	"v.io/x/lock/lockd/internal"
)

func main() {
	hw := internal.GetHardware()
	fmt.Println("Commands are 'status', 'lock', 'unlock' or 'quit'")
	bio := bufio.NewReader(os.Stdin)

	for {
		fmt.Fprintf(os.Stdout, "> ")
		os.Stdout.Sync()
		line, _, err := bio.ReadLine()
		if err != nil {
			fmt.Println("ERROR:", err)
			return
		}
		cmd := strings.ToLower(strings.TrimSpace(string(line)))
		switch {
		case strings.HasPrefix(cmd, "s"):
			fmt.Println(hw.Status())
		case strings.HasPrefix(cmd, "l"):
			if err := hw.SetStatus(lock.Locked); err != nil {
				fmt.Println("ERROR:", err)
			}
		case strings.HasPrefix(cmd, "u"):
			if err := hw.SetStatus(lock.Unlocked); err != nil {
				fmt.Println("ERROR:", err)
			}
		case strings.HasPrefix(cmd, "q"), strings.HasPrefix(cmd, "x"):
			return
		default:
			fmt.Printf("ERROR: unrecognized command %q\n", cmd)
		}
	}
}
