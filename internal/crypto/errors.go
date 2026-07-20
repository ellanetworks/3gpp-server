// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import "errors"

var (
	ErrMACFailure    = errors.New("AUTN MAC failure")
	ErrSQNOutOfRange = errors.New("SQN out of range")
)
