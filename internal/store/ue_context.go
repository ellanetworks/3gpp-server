package store

// UEContext is a placeholder for Phase 1. Full implementation comes in Phase 2.
type UEContext struct {
	ID          string `json:"id"`
	RanUeNgapID int64  `json:"ran_ue_ngap_id"`
	AmfUeNgapID int64  `json:"amf_ue_ngap_id"`
}
