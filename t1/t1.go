package main

import (
	"errors"
	"log"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"gitlab.project-karma.com/atomyze/library/go/foundation/core"

	"gitlab.project-karma.com/atomyze/library/go/foundationn/core/types"
//	ind "gitlab.n-t.io/industrial/token"
	ind "gitlab.n-t.io/t1/t1/token"
)

// IT - industrial token base struct
type IT struct {
	ind.IndustrialToken
}

var groups = []ind.Group{{
	ID:       "07122020",
	Emission: 1800000000,
	Maturity: "07.12.2020 00:00:00",
	Note:     "Test note",
}, {
	ID:       "05012021",
	Emission: 1800000000,
	Maturity: "05.01.2021 00:00:00",
	Note:     "Test note",
}, {
	ID:       "05022021",
	Emission: 1800000000,
	Maturity: "05.02.2021 00:00:00",
	Note:     "Test note",
}, {
	ID:       "05032021",
	Emission: 1800000000,
	Maturity: "05.03.2021 00:00:00",
	Note:     "Test note",
}, {
	ID:       "05042021",
	Emission: 1800000000,
	Maturity: "05.04.2021 00:00:00",
	Note:     "Test note",
}, {
	ID:       "05052021",
	Emission: 1800000000,
	Maturity: "05.05.2021 00:00:00",
	Note:     "Test note",
}, {
	ID:       "07062021",
	Emission: 1800000000,
	Maturity: "07.06.2021 00:00:00",
	Note:     "Test note",
}, {
	ID:       "05072021",
	Emission: 1800000000,
	Maturity: "05.07.2021 00:00:00",
	Note:     "Test note",
}, {
	ID:       "05082021",
	Emission: 1800000000,
	Maturity: "05.08.2021 00:00:00",
	Note:     "Test note",
}, {
	ID:       "06092021",
	Emission: 1800000000,
	Maturity: "06.09.2021 00:00:00",
	Note:     "Test note",
}, {
	ID:       "30092021",
	Emission: 1800000000,
	Maturity: "30.09.2021 00:00:00",
	Note:     "Test note",
}, {
	ID:       "31102021",
	Emission: 1800000000,
	Maturity: "31.10.2021 00:00:00",
	Note:     "Test note",
},
}

const (
	timeFormat = "02.01.2006 15:04:05"
)

// NBTxInitialize - initializes chaincode
func (it *IT) NBTxInitialize(sender types.Sender) error {
	if !sender.Equal(it.Issuer()) {
		return errors.New("unauthorized")
	}

	return it.Initialize(groups)
}

func main() {
	ft := &IT{
		ind.IndustrialToken{
			Name:            "Industrial Token",
			Symbol:          "INDUSTRIAL",
			Decimals:        8,
			UnderlyingAsset: "Cobalt",
			DeliveryForm:    "Cobalt Nornickel cut 1x1",
			UnitOfMeasure:   "MT",
			TokensForUnit:   "1",
			PaymentTerms:    "Non-prepaid",
			Price:           "Floating",
		},
	}

	cc, err := core.NewChainCode(ft, "org0", nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := shim.Start(cc); err != nil {
		log.Fatal(err)
	}
}
