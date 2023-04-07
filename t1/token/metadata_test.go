package token

import (
	"encoding/json"
	"fmt"
	"gitlab.n-t.io/atmz/foundation/golang-math-big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gitlab.n-t.io/atmz/foundation/core"
	ma "gitlab.n-t.io/atmz/foundation/mock"
)

func Test_ChangeMetadata(t *testing.T) {
	mock := ma.NewLedger(t)
	issuer := mock.NewWallet()
	user := mock.NewWallet()

	it := &IT{
		IndustrialToken{
			Name:            "Industrial Token",
			Symbol:          "IT",
			Decimals:        8,
			UnderlyingAsset: "Cobalt",
			DeliveryForm:    "Cobalt Nornickel cut 1x1",
			UnitOfMeasure:   "MT",
			TokensForUnit:   "1",
			PaymentTerms:    "Non-prepaid",
			Price:           "Floating",
		},
	}

	mock.NewChainCode("it", it, &core.ContractOptions{}, issuer.Address())
	issuer.OtfNbInvoke("it", "initialize")

	metadata, err := json.MarshalIndent(mock.IndustrialMetadata("it"), "", "  ")
	assert.NoError(t, err)
	fmt.Println(string(metadata))

	issuer.SignedInvoke("it", "changeGroupNote", "203012", "Note changed")

	timeOld, err := time.Parse(timeFormat, "08.12.2030 22:00:00")
	assert.NoError(t, err)

	time1, err := time.Parse(timeFormat, "30.01.2032 02:00:00")
	assert.NoError(t, err)

	time2, err := time.Parse(timeFormat, "05.01.2032 01:00:00")
	assert.NoError(t, err)

	md := mock.IndustrialMetadata("it")
	assert.Contains(t, md.Groups, ma.MetadataGroup{
		Name:         "203012",
		Amount:       new(big.Int).SetUint64(50000000000000),
		MaturityDate: timeOld,
		Note:         "Note changed",
	})

	req1 := user.SignedInvoke("it", "createMCRequest", "203012", "30.01.2032 02:00:00", "Test Ref 1")
	req2 := user.SignedInvoke("it", "createMCRequest", "203101", "05.01.2032 01:00:00", "Test Ref 2")

	list := parseMCList(t, user.Invoke("it", "mCRequestsList"))
	assert.Equal(t, 2, len(list))

	assert.Contains(t, list, MaturityChangeRequest{
		TransactionID: req1,
		UserAddress:   user.AddressType(),
		GroupName:     "203012",
		MaturityDate:  time1,
		Ref:           "Test Ref 1",
	})
	assert.Contains(t, list, MaturityChangeRequest{
		TransactionID: req2,
		UserAddress:   user.AddressType(),
		GroupName:     "203101",
		MaturityDate:  time2,
		Ref:           "Test Ref 2",
	})

	issuer.SignedInvoke("it", "denyMCRequest", req1)
	issuer.SignedInvoke("it", "acceptMCRequest", req2, "ref3")

	md = mock.IndustrialMetadata("it")
	assert.Contains(t, md.Groups, ma.MetadataGroup{
		Name:         "203101",
		Amount:       new(big.Int).SetUint64(50000000000000),
		MaturityDate: time2,
		Note:         "Test note",
	})

	metadata, err = json.MarshalIndent(mock.IndustrialMetadata("it"), "", "  ")
	assert.NoError(t, err)
	fmt.Println(string(metadata))
}

func parseMCList(t *testing.T, data string) (out []MaturityChangeRequest) {
	assert.NoError(t, json.Unmarshal([]byte(data), &out))
	return
}
