package proto

import "github.com/btcsuite/btcutil/base58"

func (m *Address) AddrString() string {
	return base58.CheckEncode(m.Address[1:], m.Address[0])
}

func (m *AclResponse) Addr() (out [32]byte) {
	if m.Address == nil {
		return [32]byte{}
	}
	copy(out[:], m.Address.Address.Address[:32])
	return out
}
