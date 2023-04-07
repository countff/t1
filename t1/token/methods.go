package token

import (
	"errors"
	"fmt"
	"gitlab.n-t.io/atmz/foundation/core"
	"gitlab.n-t.io/atmz/foundation/golang-math-big"
	"time"

	"gitlab.n-t.io/atmz/foundation/core/types"
	"gitlab.n-t.io/atmz/foundation/proto"
)

type metadata struct {
	Name            string          `json:"name"`
	Symbol          string          `json:"symbol"`
	Decimals        uint            `json:"decimals"`
	UnderlyingAsset string          `json:"underlying_asset"`
	Issuer          string          `json:"issuer"`
	DeliveryForm    string          `json:"deliveryForm"`
	UnitOfMeasure   string          `json:"unitOfMeasure"`
	TokensForUnit   string          `json:"tokensForUnit"`
	PaymentTerms    string          `json:"paymentTerms"`
	Price           string          `json:"price"`
	Methods         []string        `json:"methods"`
	Groups          []MetadataGroup `json:"groups"`
	Fee             fee             `json:"fee"`
	Rates           []metadataRate  `json:"rates"`
}

// MetadataGroup struct
type MetadataGroup struct {
	Name         string    `json:"name"`
	Amount       *big.Int  `json:"amount"`
	MaturityDate time.Time `json:"maturityDate"`
	Note         string    `json:"note"`
}

type fee struct {
	Address  string   `json:"address"`
	Currency string   `json:"currency"`
	Fee      *big.Int `json:"fee"`
	Floor    *big.Int `json:"floor"`
	Cap      *big.Int `json:"cap"`
}

type metadataRate struct {
	DealType string   `json:"deal_type"`
	Currency string   `json:"currency"`
	Rate     *big.Int `json:"rate"`
	Min      *big.Int `json:"min"`
	Max      *big.Int `json:"max"`
}

// QueryMetadata returns token metadata
func (it *IndustrialToken) QueryMetadata() (metadata, error) {
	if err := it.loadConfigUnlessLoaded(); err != nil {
		return metadata{}, err
	}
	m := metadata{
		Name:            it.Name,
		Symbol:          it.Symbol,
		Decimals:        it.Decimals,
		UnderlyingAsset: it.UnderlyingAsset,
		DeliveryForm:    it.DeliveryForm,
		UnitOfMeasure:   it.UnitOfMeasure,
		TokensForUnit:   it.TokensForUnit,
		PaymentTerms:    it.PaymentTerms,
		Price:           it.Price,
		Issuer:          it.Issuer().String(),
		Methods:         it.GetMethods(),
	}
	for _, group := range it.config.Groups {
		m.Groups = append(m.Groups, MetadataGroup{
			Name:         group.Id,
			Amount:       new(big.Int).SetBytes(group.Emission),
			MaturityDate: time.Unix(group.Maturity, 0),
			Note:         group.Note,
		})
	}
	if len(it.config.FeeAddress) == 32 {
		m.Fee.Address = types.AddrFromBytes(it.config.FeeAddress).String()
	}
	if it.config.Fee != nil {
		m.Fee.Currency = it.config.Fee.Currency
		m.Fee.Fee = new(big.Int).SetBytes(it.config.Fee.Fee)
		m.Fee.Floor = new(big.Int).SetBytes(it.config.Fee.Floor)
		m.Fee.Cap = new(big.Int).SetBytes(it.config.Fee.Cap)
	}
	for _, r := range it.config.Rates {
		m.Rates = append(m.Rates, metadataRate{
			DealType: r.DealType,
			Currency: r.Currency,
			Rate:     new(big.Int).SetBytes(r.Rate),
			Min:      new(big.Int).SetBytes(r.Min),
			Max:      new(big.Int).SetBytes(r.Max),
		})
	}
	return m, nil
}

// ChangeGroupMetadata changes metadata for a group of token
func (it *IndustrialToken) ChangeGroupMetadata(groupName string, maturityDate time.Time, note string) error {
	if err := it.loadConfigUnlessLoaded(); err != nil {
		return err
	}
	if !it.config.Initialized {
		return errors.New("token is not initialized")
	}
	notFound := true
	for _, group := range it.config.Groups {
		if group.Id == groupName {
			notFound = false
			bChanged := false

			nilTime := time.Time{}

			if maturityDate != nilTime && maturityDate != time.Unix(group.Maturity, 0) {
				bChanged = true
				group.Maturity = maturityDate.Unix()
			}

			if note != "" && note != group.Note {
				bChanged = true
				group.Note = note
			}

			if bChanged {
				return it.saveConfig()
			}

			break
		}
	}
	if notFound {
		return fmt.Errorf("token group %s not found", groupName)
	}

	return nil
}

// QueryIndustrialBalanceOf - returns balance of the token for user address
func (it *IndustrialToken) QueryIndustrialBalanceOf(address types.Address) (map[string]string, error) {
	return it.IndustrialBalanceGet(address)
}

// QueryAllowedBalanceOf - returns allowed balance of the token for user address
func (it *IndustrialToken) QueryAllowedBalanceOf(address types.Address, token string) (*big.Int, error) {
	return it.AllowedBalanceGet(token, address)
}

// QueryDocumentsList - returns list of emission documents
func (it *IndustrialToken) QueryDocumentsList() ([]core.Doc, error) {
	return core.DocumentsList(it.GetStub())
}

// TxAddDocs - adds docs to a token
func (it *IndustrialToken) TxAddDocs(sender types.Sender, rawDocs string) error {
	if !sender.Equal(it.Issuer()) {
		return errors.New("unathorized")
	}

	return core.AddDocs(it.GetStub(), rawDocs)
}

// TxDeleteDoc - deletes doc from state
func (it *IndustrialToken) TxDeleteDoc(sender types.Sender, docID string) error {
	if !sender.Equal(it.Issuer()) {
		return errors.New("unathorized")
	}

	return core.DeleteDoc(it.GetStub(), docID)
}

// TxSetRate sets token rate to an asset for a type of deal
func (it *IndustrialToken) TxSetRate(sender types.Sender, dealType string, currency string, rate *big.Int) error {
	if !sender.Equal(it.Issuer()) {
		return errors.New("unauthorized")
	}
	// TODO - check if it may be helpful in business logic
	if rate.Sign() == 0 {
		return errors.New("trying to set rate = 0")
	}
	if it.Symbol == currency {
		return errors.New("currency is equals token: it is impossible")
	}
	if err := it.loadConfigUnlessLoaded(); err != nil {
		return err
	}
	for i, r := range it.config.Rates {
		if r.DealType == dealType && r.Currency == currency {
			it.config.Rates[i].Rate = rate.Bytes()
			return it.saveConfig()
		}
	}
	it.config.Rates = append(it.config.Rates, &proto.TokenRate{
		DealType: dealType,
		Currency: currency,
		Rate:     rate.Bytes(),
		Max:      new(big.Int).SetUint64(0).Bytes(), //todo maybe needs different solution
		Min:      new(big.Int).SetUint64(0).Bytes(),
	})
	return it.saveConfig()
}

// TxSetLimits sets limits for a deal type and an asset
func (it *IndustrialToken) TxSetLimits(sender types.Sender, dealType string, currency string, min *big.Int, max *big.Int) error {
	if !sender.Equal(it.Issuer()) {
		return errors.New("unauthorized")
	}
	if min.Cmp(max) > 0 && max.Cmp(big.NewInt(0)) > 0 {
		return errors.New("min limit is greater than max limit")
	}
	if err := it.loadConfigUnlessLoaded(); err != nil {
		return err
	}
	unknownDealType := true
	for i, r := range it.config.Rates {
		if r.DealType == dealType {
			unknownDealType = false
			if r.Currency == currency {
				it.config.Rates[i].Max = max.Bytes()
				it.config.Rates[i].Min = min.Bytes()
				return it.saveConfig()
			}
		}
	}
	if unknownDealType {
		return fmt.Errorf("unknown DealType. Rate for deal type %s and currency %s was not set", dealType, currency)
	}
	return fmt.Errorf("unknown currency. Rate for deal type %s and currency %s was not set", dealType, currency)
}

// TxDeleteRate - deletes rate from state
func (it *IndustrialToken) TxDeleteRate(sender types.Sender, dealType string, currency string) error {
	if !sender.Equal(it.Issuer()) {
		return errors.New("unauthorized")
	}
	if it.Symbol == currency {
		return errors.New("currency is equals token: it is impossible")
	}
	if err := it.loadConfigUnlessLoaded(); err != nil {
		return err
	}
	for i, r := range it.config.Rates {
		if r.DealType == dealType && r.Currency == currency {
			it.config.Rates = append(it.config.Rates[:i], it.config.Rates[i+1:]...)
			return it.saveConfig()
		}
	}

	return nil
}
