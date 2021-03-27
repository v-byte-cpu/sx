package icmp

type Response struct {
	Type uint8 `json:"type"`
	Code uint8 `json:"code"`
}
