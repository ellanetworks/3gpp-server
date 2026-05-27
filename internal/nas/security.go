package nas

import (
	"fmt"

	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/security"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

func EncodeNasPduWithSecurity(ue *store.UEContext, pdu []byte, securityHeaderType uint8) ([]byte, error) {
	m := gonas.NewMessage()
	if err := m.PlainNasDecode(&pdu); err != nil {
		return nil, fmt.Errorf("plain NAS decode: %v", err)
	}

	m.SecurityHeader = gonas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    securityHeaderType,
	}

	return nasEncode(ue, m, securityHeaderType)
}

func nasEncode(ue *store.UEContext, msg *gonas.Message, securityHeaderType uint8) ([]byte, error) {
	if securityHeaderType == gonas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext ||
		securityHeaderType == gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext {
		ue.ULCount = 0
		ue.DLCount = 0
	}

	sequenceNumber := uint8(ue.ULCount & 0xff)

	payload, err := msg.PlainNasEncode()
	if err != nil {
		return nil, fmt.Errorf("plain NAS encode: %v", err)
	}

	if securityHeaderType != gonas.SecurityHeaderTypeIntegrityProtected &&
		securityHeaderType != gonas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext {
		if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.ULCount, security.Bearer3GPP,
			security.DirectionUplink, payload); err != nil {
			return nil, fmt.Errorf("NAS encrypt: %v", err)
		}
	}

	payload = append([]byte{sequenceNumber}, payload...)

	mac32, err := security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.ULCount, security.Bearer3GPP, security.DirectionUplink, payload)
	if err != nil {
		return nil, fmt.Errorf("NAS MAC: %v", err)
	}

	payload = append(mac32, payload...)
	msgSecurityHeader := []byte{msg.ProtocolDiscriminator, msg.SecurityHeaderType}
	payload = append(msgSecurityHeader, payload...)

	ue.ULCount++

	return payload, nil
}

func DecodeSecuredNAS(ue *store.UEContext, message []byte) (*NASResponse, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("empty NAS PDU")
	}

	resp := &NASResponse{
		RawHex: encodeHex(message),
	}

	secHeaderType := gonas.GetSecurityHeaderType(message) & 0x0f
	resp.SecurityHeaderType = securityHeaderTypeToString(secHeaderType)

	if secHeaderType == gonas.SecurityHeaderTypePlainNas {
		return Decode(message)
	}

	if len(message) < 7 {
		return nil, fmt.Errorf("secured NAS too short: %d bytes", len(message))
	}

	sequenceNumber := message[6]
	payload := make([]byte, len(message)-7)
	copy(payload, message[7:])

	cph := false
	newSecurityContext := false

	switch secHeaderType {
	case gonas.SecurityHeaderTypeIntegrityProtected:
	case gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered:
		cph = true
	case gonas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext:
		newSecurityContext = true
	case gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext:
		cph = true
		newSecurityContext = true
	}

	dlSQN := uint8(ue.DLCount & 0xff)
	if dlSQN > sequenceNumber {
		ue.DLCount = (ue.DLCount & 0xffffff00) + 0x100 + uint32(sequenceNumber)
	} else {
		ue.DLCount = (ue.DLCount & 0xffffff00) + uint32(sequenceNumber)
	}

	if cph && ue.SecurityContextAvailable {
		if err := security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.DLCount, security.Bearer3GPP,
			security.DirectionDownlink, payload); err != nil {
			return nil, fmt.Errorf("NAS decrypt: %v", err)
		}
	}

	m := new(gonas.Message)
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)

	if err := m.PlainNasDecode(&payloadCopy); err != nil {
		return nil, fmt.Errorf("NAS decode after decrypt: %v", err)
	}

	if newSecurityContext && m.GmmMessage != nil {
		if m.GmmHeader.GetMessageType() == gonas.MsgTypeSecurityModeCommand {
			ue.CipheringAlg = m.SelectedNASSecurityAlgorithms.GetTypeOfCipheringAlgorithm()
			ue.IntegrityAlg = m.SelectedNASSecurityAlgorithms.GetTypeOfIntegrityProtectionAlgorithm()

			if err := deriveAlgKeys(ue); err != nil {
				return nil, fmt.Errorf("derive algorithm keys: %v", err)
			}

			ue.DLCount = 0
			ue.SecurityContextAvailable = true
		}
	}

	if m.GmmMessage == nil {
		resp.MessageType = "unknown"
		return resp, nil
	}

	msgType := m.GmmMessage.GetMessageType()
	resp.MessageType = gmmMessageTypeName(msgType)

	switch msgType {
	case gonas.MsgTypeSecurityModeCommand:
		decodeSecurityModeCommand(m, resp)
	case gonas.MsgTypeRegistrationAccept:
		decodeRegistrationAccept(m, resp)
	case gonas.MsgTypeAuthenticationRequest:
		decodeAuthenticationRequest(m, resp)
	case gonas.MsgTypeRegistrationReject:
		decodeRegistrationReject(m, resp)
	case gonas.MsgTypeIdentityRequest:
		decodeIdentityRequest(m, resp)
	}

	return resp, nil
}

func deriveAlgKeys(ue *store.UEContext) error {
	return deriveAlgKeysFromKamf(ue.CipheringAlg, ue.Kamf, &ue.KnasEnc, ue.IntegrityAlg, &ue.KnasInt)
}

func deriveAlgKeysFromKamf(cipheringAlg uint8, kamf []byte, knasEnc *[16]uint8, integrityAlg uint8, knasInt *[16]uint8) error {
	if len(kamf) == 0 {
		return fmt.Errorf("kamf is empty")
	}

	return crypto.AlgorithmKeyDerivation(cipheringAlg, kamf, knasEnc, integrityAlg, knasInt)
}

func encodeHex(data []byte) string {
	const hextable = "0123456789abcdef"
	dst := make([]byte, len(data)*2)
	for i, v := range data {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}
