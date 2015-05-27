// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import "v.io/x/lock"

var hardware Hardware // The single global instance of Hardware, initialized by init()

// Hardware abstracts the interface for physically manipulating the lock.
type Hardware interface {
	// Status returns the current state of the lock.
	Status() lock.LockStatus

	// SetStatus changes the state of the lock to the provided one.
	SetStatus(s lock.LockStatus) error
}

// GetHardware returns the singleton instance of Hardware
func GetHardware() Hardware { return hardware }
