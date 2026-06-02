package api

import (
	nasTypes "github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
)

type CreateGnBRequest struct {
	AMFAddress   string `json:"amf_address"`
	GnBN2Address string `json:"gnb_n2_address"`
	MCC          string `json:"mcc"`
	MNC          string `json:"mnc"`
	TAC          string `json:"tac"`
	GnbID        string `json:"gnb_id"`
	Name         string `json:"name"`
	SST          int32  `json:"sst"`
	SD           string `json:"sd,omitempty"`

	Slices []SliceInput `json:"slices,omitempty"`

	// Override: if provided, send these IEs instead of auto-building from the fields above.
	NGSetupIEs []ngap.IE `json:"ng_setup_ies,omitempty"`
}

type SliceInput struct {
	SST int32  `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

type CreateGnBResponse struct {
	GnBID           string             `json:"gnb_id"`
	NGSetupResponse *ngap.NGAPResponse `json:"ng_setup_response"`
}

// SendGnBNGAPRequest is the JSON body for a gNB-level (non-UE-associated) NGAP
// message sent on the gNB's existing N2 association.
type SendGnBNGAPRequest struct {
	MessageType string `json:"message_type"`

	// RawNGAPPDU, when set, is written verbatim onto the N2 association with no
	// encoding or validation, and message_type is ignored — letting a test send
	// any NGAP PDU, well-formed or not. WaitFor lists downlink message types to
	// block for (empty = fire-and-forget); TimeoutMs bounds that wait.
	RawNGAPPDU *string  `json:"raw_ngap_pdu,omitempty"`
	WaitFor    []string `json:"wait_for,omitempty"`
	TimeoutMs  int      `json:"timeout_ms,omitempty"`

	// NG Reset: when ResetUEIDs is empty the whole NG interface is reset
	// (ResetType nG-Interface); otherwise only the listed UEs' associations are
	// reset (ResetType partOfNG-Interface).
	ResetUEIDs []string `json:"reset_ue_ids,omitempty"`

	// Handover (target gNB side): the AMF/RAN UE NGAP IDs identifying the UE
	// association, and the admitted PDU sessions for Handover Request Acknowledge.
	AmfUeNgapID *int64               `json:"amf_ue_ngap_id,omitempty"`
	RanUeNgapID *int64               `json:"ran_ue_ngap_id,omitempty"`
	PDUSessions []HandoverPDUSession `json:"pdu_sessions,omitempty"`
}

// HandoverPDUSession is an admitted PDU session in a Handover Request
// Acknowledge, carrying the target gNB's downlink GTP tunnel.
type HandoverPDUSession struct {
	ID     int64  `json:"id"`
	DLTeid uint32 `json:"dl_teid,omitempty"`
	DLIP   string `json:"dl_ip,omitempty"`
}

// AwaitRequest waits for an unsolicited downlink NGAP message (one the core
// sends without a triggering uplink, e.g. Handover Request, Handover Command,
// UE Context Release Command) to arrive on the gNB's N2 association.
type AwaitRequest struct {
	MessageTypes []string `json:"message_types"`
	TimeoutMs    int      `json:"timeout_ms,omitempty"`
}

type GnBStateResponse struct {
	ID    string `json:"id"`
	MCC   string `json:"mcc"`
	MNC   string `json:"mnc"`
	TAC   string `json:"tac"`
	GnbID string `json:"gnb_id"`
	Name  string `json:"name"`
	SST   int32  `json:"sst"`
	SD    string `json:"sd,omitempty"`
}

type CreateUERequest struct {
	SUPI             string `json:"supi"`
	K                string `json:"k"`
	OPc              string `json:"opc"`
	Amf              string `json:"amf,omitempty"`
	Sqn              string `json:"sqn,omitempty"`
	SST              int32  `json:"sst,omitempty"`
	SD               string `json:"sd,omitempty"`
	DNN              string `json:"dnn,omitempty"`
	RoutingIndicator string `json:"routing_indicator,omitempty"`
	ProtectionScheme string `json:"protection_scheme,omitempty"`
	PublicKeyID      string `json:"public_key_id,omitempty"`
	PublicKeyHex     string `json:"public_key_hex,omitempty"`
	PDUSessionID     uint8  `json:"pdu_session_id,omitempty"`
	PDUSessionType   uint8  `json:"pdu_session_type,omitempty"`
	IMEISV           string `json:"imeisv,omitempty"`
}

type CreateUEResponse struct {
	UEID        string `json:"ue_id"`
	SUPI        string `json:"supi"`
	SUCI        string `json:"suci"`
	RanUeNgapID int64  `json:"ran_ue_ngap_id"`
}

type UEStateResponse struct {
	ID               string `json:"id"`
	SUPI             string `json:"supi"`
	SUCI             string `json:"suci"`
	MCC              string `json:"mcc"`
	MNC              string `json:"mnc"`
	RanUeNgapID      int64  `json:"ran_ue_ngap_id"`
	AmfUeNgapID      int64  `json:"amf_ue_ngap_id"`
	K                string `json:"k"`
	OPc              string `json:"opc"`
	Amf              string `json:"amf"`
	Sqn              string `json:"sqn"`
	Snn              string `json:"snn"`
	DNN              string `json:"dnn,omitempty"`
	SST              int32  `json:"sst,omitempty"`
	SD               string `json:"sd,omitempty"`
	ProtectionScheme string `json:"protection_scheme"`
	RoutingIndicator string `json:"routing_indicator"`
	IMEISV           string `json:"imeisv,omitempty"`
}

type PatchUERequest struct {
	K           *string `json:"k,omitempty"`
	OPc         *string `json:"opc,omitempty"`
	Amf         *string `json:"amf,omitempty"`
	Sqn         *string `json:"sqn,omitempty"`
	AmfUeNgapID *int64  `json:"amf_ue_ngap_id,omitempty"`
	DNN         *string `json:"dnn,omitempty"`
	SST         *int32  `json:"sst,omitempty"`
	SD          *string `json:"sd,omitempty"`
	IMEISV      *string `json:"imeisv,omitempty"`
}

type SendNGAPRequest = nasTypes.NASRequest

type SendNGAPResponse struct {
	NGAP *ngap.NGAPResponse    `json:"ngap"`
	NAS  *nasTypes.NASResponse `json:"nas,omitempty"`
}
