package api

import (
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	nasTypes "github.com/ellanetworks/3gpp-server/internal/nas"
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

	// NG Reset: when ResetUEIDs is empty the whole NG interface is reset
	// (ResetType nG-Interface); otherwise only the listed UEs' associations are
	// reset (ResetType partOfNG-Interface).
	ResetUEIDs []string `json:"reset_ue_ids,omitempty"`
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
	K                *string `json:"k,omitempty"`
	OPc              *string `json:"opc,omitempty"`
	Amf              *string `json:"amf,omitempty"`
	Sqn              *string `json:"sqn,omitempty"`
	AmfUeNgapID      *int64  `json:"amf_ue_ngap_id,omitempty"`
	DNN              *string `json:"dnn,omitempty"`
	SST              *int32  `json:"sst,omitempty"`
	SD               *string `json:"sd,omitempty"`
	IMEISV           *string `json:"imeisv,omitempty"`
}

type SendNGAPRequest = nasTypes.NASRequest

type SendNGAPResponse struct {
	NGAP *ngap.NGAPResponse   `json:"ngap"`
	NAS  *nasTypes.NASResponse `json:"nas,omitempty"`
}
