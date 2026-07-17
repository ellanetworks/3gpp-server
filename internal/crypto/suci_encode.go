// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

func ParseSUPI(supi string, mncLength int) (mcc, mnc, msin string, err error) {
	const prefix = "imsi-"
	if len(supi) < len(prefix)+10 {
		return "", "", "", fmt.Errorf("SUPI too short: %s", supi)
	}
	if supi[:len(prefix)] != prefix {
		return "", "", "", fmt.Errorf("SUPI must start with 'imsi-': %s", supi)
	}
	digits := supi[len(prefix):]
	if len(digits) < 15 {
		return "", "", "", fmt.Errorf("IMSI must be at least 15 digits: %s", supi)
	}
	if mncLength < 2 || mncLength > 3 {
		mncLength = 2
	}
	mcc = digits[:3]
	mnc = digits[3 : 3+mncLength]
	msin = digits[3+mncLength:]

	return mcc, mnc, msin, nil
}

func EncodeSuci(msin, mcc, mnc, routingIndicator string, hnPubKey HomeNetworkPublicKey) ([]byte, error) {
	protScheme, err := strconv.ParseUint(hnPubKey.ProtectionScheme, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid protection scheme: %v", err)
	}

	hnPubKeyId, err := strconv.ParseUint(hnPubKey.PublicKeyID, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid public key ID: %v", err)
	}

	var schemeOutput []byte
	if protScheme == 0 {
		schemeOutput, err = hex.DecodeString(Tbcd(msin))
		if err != nil {
			return nil, fmt.Errorf("TBCD encoding error: %v", err)
		}
	} else {
		suci, err := CipherSuci(msin, mcc, mnc, routingIndicator, hnPubKey)
		if err != nil {
			return nil, fmt.Errorf("SUCI cipher error: %v", err)
		}
		schemeOutput, err = hex.DecodeString(suci.SchemeOutput)
		if err != nil {
			return nil, fmt.Errorf("scheme output decode error: %v", err)
		}
	}

	buffer := make([]byte, 8+len(schemeOutput))
	buffer[0] = 1

	plmnID, err := getMccAndMncInOctets(mcc, mnc)
	if err != nil {
		return nil, err
	}
	copy(buffer[1:], plmnID)

	routingInd, err := getRoutingIndicatorInOctets(routingIndicator)
	if err != nil {
		return nil, err
	}
	copy(buffer[4:], routingInd)

	buffer[6] = byte(protScheme)
	buffer[7] = byte(hnPubKeyId)
	copy(buffer[8:], schemeOutput)

	return buffer, nil
}

func getMccAndMncInOctets(mccStr, mncStr string) ([]byte, error) {
	mcc := reverseStr(mccStr)
	mnc := reverseStr(mncStr)

	var res string
	if len(mnc) == 2 {
		res = fmt.Sprintf("%c%cf%c%c%c", mcc[1], mcc[2], mcc[0], mnc[0], mnc[1])
	} else {
		res = fmt.Sprintf("%c%c%c%c%c%c", mcc[1], mcc[2], mnc[0], mcc[0], mnc[1], mnc[2])
	}

	return hex.DecodeString(res)
}

func getRoutingIndicatorInOctets(routingIndicator string) ([]byte, error) {
	if len(routingIndicator) == 0 {
		routingIndicator = "0"
	}
	if len(routingIndicator) > 4 {
		return nil, fmt.Errorf("routing indicator must be 4 digits maximum: %s", routingIndicator)
	}

	ri := []byte(routingIndicator)
	for len(ri) < 4 {
		ri = append(ri, 'F')
	}

	for i := 1; i < len(ri); i += 2 {
		ri[i-1], ri[i] = ri[i], ri[i-1]
	}

	return hex.DecodeString(string(ri))
}

func reverseStr(s string) string {
	var aux string
	for _, v := range s {
		aux = string(v) + aux
	}
	return aux
}

func DeriveSNN(mcc, mnc string) string {
	if len(mnc) == 2 {
		return "5G:mnc0" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
	}
	return "5G:mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
}

func BuildSuciString(mcc, mnc, routingIndicator, protScheme, pubKeyID string, suciBuffer []byte) string {
	schemeOutput := hex.EncodeToString(suciBuffer[8:])
	return fmt.Sprintf("suci-0-%s-%s-%s-%s-%s-%s", mcc, mnc, routingIndicator, protScheme, pubKeyID, schemeOutput)
}
