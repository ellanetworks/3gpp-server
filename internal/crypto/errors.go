// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import "errors"

var (
	// ErrMACFailure is returned when the AUTN MAC does not verify. It is the
	// trigger for an Authentication Failure with EMM cause #20 (TS 24.301
	// §5.4.2.6 a) or 5GMM cause #20 (TS 24.501 §5.4.1.3.7 c), both "MAC failure".
	ErrMACFailure = errors.New("AUTN MAC failure")
	// ErrSQNOutOfRange is returned when the recovered SQN is older than the
	// stored value. It is the trigger for an Authentication Failure with EMM
	// cause #21 (TS 24.301 §5.4.2.6 c) or 5GMM cause #21 (TS 24.501 §5.4.1.3.7 f),
	// both "synch failure", carrying the AUTS from ComputeAUTS.
	ErrSQNOutOfRange = errors.New("SQN out of range")
)
