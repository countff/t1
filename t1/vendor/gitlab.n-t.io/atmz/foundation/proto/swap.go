package proto

import "strings"

func (m *Swap) TokenSymbol() string {
	parts := strings.Split(m.Token, "_")
	return parts[0]
}
