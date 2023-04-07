package types

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"gitlab.n-t.io/atmz/foundation/core/helpers"
	big "gitlab.n-t.io/atmz/foundation/golang-math-big"
	pb "gitlab.n-t.io/atmz/foundation/proto"
)

// Address might be more complicated structure
// contains fields like isIndustrial bool or isMultisig bool
type Address pb.Address

func AddrFromBytes(in []byte) Address {
	addr := Address{}
	addrBytes := make([]byte, 32)
	copy(addrBytes, in[:32])
	addr.Address = addrBytes
	return addr
}

func AddrFromBase58Check(in string) (Address, error) {
	value, ver, err := base58.CheckDecode(in)
	if err != nil {
		return Address{}, err
	}
	addr := Address{}
	addrBytes := make([]byte, 32)
	copy(addrBytes, append([]byte{ver}, value...)[:32])
	addr.Address = addrBytes
	return addr, nil
}

func AddrFromBase58CheckForced(in string) Address {
	addr, err := AddrFromBase58Check(in)
	if err != nil {
		panic(err)
	}
	return addr
}

func (a Address) Equal(b Address) bool {
	return bytes.Equal(a.Address[:], b.Address[:])
}

func (a Address) Bytes() []byte {
	return a.Address
}

func (a Address) String() string {
	return base58.CheckEncode(a.Address[1:], a.Address[0])
}

func (a Address) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

func (a Address) PrepareToSave(stub shim.ChaincodeStubInterface, in string) (string, error) {
	accInfo, err := helpers.GetAccountInfo(stub, in)
	if err != nil {
		return "", err
	}
	if accInfo.BlackListed {
		return "", fmt.Errorf("address %s is blacklisted", in)
	}
	return in, nil
}

func (a Address) ConvertToCall(stub shim.ChaincodeStubInterface, in string) (Address, error) {
	// only this called in batch
	//var addr pb.Address
	//err := proto.Unmarshal([]byte(in), &addr)
	//return Address(addr), err
	return AddrFromBase58Check(in)
}

func (a *Address) UnmarshalJSON(data []byte) error {
	var tmp string
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	*a, err = AddrFromBase58Check(tmp)
	return err
}

func (a Address) IsUserIdSame(b Address) bool {
	if a.UserID == "" || b.UserID == "" {
		return false
	}
	return a.UserID == b.UserID
}

type Sender struct {
	addr Address
}

func (s *Sender) Address() Address {
	return s.addr
}

func (s *Sender) Equal(addr Address) bool {
	return bytes.Equal(s.addr.Address[:], addr.Address[:])
}

func (s Sender) ConvertToCall(stub shim.ChaincodeStubInterface, in string) (Sender, error) {
	var addr pb.Address
	data, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return Sender{}, err
	}
	err = proto.Unmarshal(data, &addr)
	return Sender{addr: Address(addr)}, err
}

type Hex []byte

func (h Hex) ConvertToCall(stub shim.ChaincodeStubInterface, in string) (Hex, error) {
	value, err := hex.DecodeString(in)
	return value, err
}

type MultiSwapAssets struct {
	Assets []*MultiSwapAsset
}

type MultiSwapAsset struct {
	Group  string `json:"group,omitempty"`
	Amount string `json:"amount,omitempty"`
}

func ConvertToAsset(in []*MultiSwapAsset) ([]*pb.Asset, error) {
	if in == nil {
		return nil, errors.New("assets can't be nil")
	}

	var assets []*pb.Asset

	for _, item := range in {
		value, ok := new(big.Int).SetString(item.Amount, 10)
		if !ok {
			return nil, fmt.Errorf("couldn't convert %s to bigint", item.Amount)
		}
		if value.Cmp(big.NewInt(0)) < 0 {
			return nil, fmt.Errorf("value %s should be positive", item.Amount)
		}

		asset := pb.Asset{}
		asset.Amount = value.Bytes()
		asset.Group = item.Group
		assets = append(assets, &asset)
	}

	return assets, nil
}

func (n MultiSwapAssets) ConvertToCall(stub shim.ChaincodeStubInterface, in string) (MultiSwapAssets, error) {
	assets := MultiSwapAssets{}
	err := json.Unmarshal([]byte(in), &assets)
	if err != nil {
		return assets, err
	}
	return assets, nil
}
