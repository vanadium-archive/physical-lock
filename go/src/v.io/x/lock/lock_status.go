// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lock

func (l LockStatus) String() string {
	if l == Locked {
		return "LOCKED"
	}
	return "UNLOCKED"
}
