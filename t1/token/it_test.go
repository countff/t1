package token

import (
	"errors"
	"gitlab.n-t.io/atmz/foundation/core/types"
)

var groups = []Group{
	{
		ID:       "203009",
		Emission: 10000000000000,
		Maturity: "21.09.2030 22:00:00",
		Note:     "Test note",
	}, {
		ID:       "203010",
		Emission: 100000000000000,
		Maturity: "21.10.2030 22:00:00",
		Note:     "Test note",
	}, {
		ID:       "203011",
		Emission: 200000000000000,
		Maturity: "21.11.2030 22:00:00",
		Note:     "Test note",
	}, {
		ID:       "203012",
		Emission: 50000000000000,
		Maturity: "08.12.2030 22:00:00",
		Note:     "Test note",
	}, {
		ID:       "203101",
		Emission: 50000000000000,
		Maturity: "01.01.2030 01:00:00",
		Note:     "Test note",
	},
}

type IT struct {
	IndustrialToken
}

// NBTxInitialize - initializes chaincode
func (it *IT) NBTxInitialize(sender types.Sender) error {
	if !sender.Equal(it.Issuer()) {
		return errors.New("unauthorized")
	}

	return it.Initialize(groups)
}
