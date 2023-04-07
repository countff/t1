package token

import (
	"errors"
	"strings"
	"time"
//        "gitlab.project-karma.com/atomyze/library/go/foundation"
//        "gitlab.n-t.io/atmz/foundation"
        "gitlab.project-karma.com/atomyze/library/go/foundation/core"
	"gitlab.project-karma.com/atomyze/library/go/foundation/core/types"
	"gitlab.project-karma.com/atomyze/library/go/foundation/golang-math-big"
	"gitlab.project-karma.com/atomyze/library/go/foundation/proto"

	pb "github.com/golang/protobuf/proto"
)

// Group base struct
type Group struct {
	ID       string
	Emission uint64
	Maturity string
	Note     string
}

// ITInterface - base method for an industrial token prototype
type ITInterface interface {
	core.BaseContractInterface
}

// IndustrialToken base struct
type IndustrialToken struct {
	core.BaseContract
	Name            string
	Symbol          string
	Decimals        uint
	UnderlyingAsset string
	DeliveryForm    string
	UnitOfMeasure   string
	TokensForUnit   string
	PaymentTerms    string
	Price           string

	config *proto.Industrial
}

// GetID returns token id
func (it *IndustrialToken) GetID() string {
	return it.Symbol
}

func (it *IndustrialToken) Issuer() types.Address {
	addr, err := types.AddrFromBase58Check(it.GetInitArg(0))
	if err != nil {
		panic(err)
	}
	return addr
}

func (it *IndustrialToken) FeeSetter() types.Address {
	addr, err := types.AddrFromBase58Check(it.GetInitArg(1))
	if err != nil {
		panic(err)
	}
	return addr
}

func (it *IndustrialToken) FeeAddressSetter() types.Address {
	addr, err := types.AddrFromBase58Check(it.GetInitArg(2))
	if err != nil {
		panic(err)
	}
	return addr
}

func (it *IndustrialToken) loadConfigUnlessLoaded() error {
	data, err := it.GetStub().GetState("tokenMetadata")
	if err != nil {
		return err
	}
	if it.config == nil {
		it.config = &proto.Industrial{}
	}

	if len(data) == 0 {
		return nil
	}
	return pb.Unmarshal(data, it.config)
}

func (it *IndustrialToken) saveConfig() error {
	data, err := pb.Marshal(it.config)
	if err != nil {
		return err
	}
	return it.GetStub().PutState("tokenMetadata", data)
}

// Initialize - token initialization
func (it *IndustrialToken) Initialize(groups []Group) error {
	if err := it.loadConfigUnlessLoaded(); err != nil {
		return err
	}

	if it.config.Initialized {
		return nil
	}

	var industrialGroups []*proto.IndustrialGroup
	for _, group := range groups {
		if strings.Contains(group.ID, ",") {
			return errors.New("wrong group name")
		}

		maturity, err := time.Parse(timeFormat, group.Maturity)
		if err != nil {
			return err
		}
		industrialGroups = append(industrialGroups, &proto.IndustrialGroup{
			Id:       group.ID,
			Maturity: maturity.Unix(),
			Emission: new(big.Int).SetUint64(group.Emission).Bytes(),
			Note:     group.Note,
		})
	}

	it.config.Groups = industrialGroups
	it.config.Initialized = true

	for _, x := range industrialGroups {
		if err := it.IndustrialBalanceAdd(it.Symbol+"_"+x.Id, it.Issuer(), new(big.Int).SetBytes(x.Emission), "initial emit"); err != nil {
			return err
		}
	}

	return it.saveConfig()
}
