package core

import (
	"encoding/hex"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"gitlab.n-t.io/atmz/foundation/core/types"
	"gitlab.n-t.io/atmz/foundation/golang-math-big"
	pb "gitlab.n-t.io/atmz/foundation/proto"
	"log"
	"sort"
)

type BaseContract struct {
	id           string
	stub         shim.ChaincodeStubInterface
	methods      []string
	allowedMspId string
	atomyzeSKI   []byte
	initArgs     []string
}

func (bc *BaseContract) baseContractInit(cc BaseContractInterface) {
	bc.id = cc.GetID()
}

func (bc *BaseContract) GetStub() shim.ChaincodeStubInterface {
	return bc.stub
}

func (bc *BaseContract) GetCreatorSKI() string {
	stub, ok := bc.stub.(*batchTxStub)
	if ok {
		return stub.creatorSKI
	}
	log.Println("Couldn't get creatorSKI because stub is not batchTxStub")
	return ""
}

func (bc *BaseContract) GetMethods() []string {
	return bc.methods
}

func (bc *BaseContract) addMethod(mm string) {
	bc.methods = append(bc.methods, mm)
	sort.Strings(bc.methods)
}

func (bc *BaseContract) setStubAndInitArgs(stub shim.ChaincodeStubInterface, allowedMspId string, atomyzeSKI []byte, args []string) {
	bc.stub = stub
	bc.allowedMspId = allowedMspId
	bc.atomyzeSKI = atomyzeSKI
	bc.initArgs = args
}

func (bc *BaseContract) GetAllowedMspId() string {
	return bc.allowedMspId
}

func (bc *BaseContract) GetAtomyzeSKI() []byte {
	return bc.atomyzeSKI
}

func (bc *BaseContract) GetInitArg(idx int) string {
	return bc.initArgs[idx]
}

func (bc *BaseContract) GetInitArgsLen() int {
	return len(bc.initArgs)
}

func (bc *BaseContract) QueryGetNonce(owner types.Address) (string, error) {
	prefix := hex.EncodeToString([]byte{byte(StateKeyNonce)})
	key, err := bc.stub.CreateCompositeKey(prefix, []string{owner.String()})
	if err != nil {
		return "", err
	}

	data, err := bc.stub.GetState(key)
	if err != nil {
		return "", err
	}
	existed := new(big.Int).SetBytes(data)
	return existed.String(), nil
}

type BaseContractInterface interface {
	GetStub() shim.ChaincodeStubInterface
	addMethod(string)
	setStubAndInitArgs(shim.ChaincodeStubInterface, string, []byte, []string)
	GetID() string
	baseContractInit(BaseContractInterface)

	TokenBalanceTransfer(from types.Address, to types.Address, amount *big.Int, reason string) error
	AllowedBalanceTransfer(token string, from types.Address, to types.Address, amount *big.Int, reason string) error

	TokenBalanceGet(address types.Address) (*big.Int, error)
	TokenBalanceAdd(address types.Address, amount *big.Int, reason string) error
	TokenBalanceSub(address types.Address, amount *big.Int, reason string) error

	AllowedBalanceGet(token string, address types.Address) (*big.Int, error)
	AllowedBalanceAdd(token string, address types.Address, amount *big.Int, reason string) error
	AllowedBalanceSub(token string, address types.Address, amount *big.Int, reason string) error

	AllowedBalanceGetAll(address types.Address) (map[string]string, error)

	tokenBalanceAdd(address types.Address, amount *big.Int, token string) error

	IndustrialBalanceGet(address types.Address) (map[string]string, error)
	IndustrialBalanceTransfer(token string, from types.Address, to types.Address, amount *big.Int, reason string) error
	IndustrialBalanceAdd(token string, address types.Address, amount *big.Int, reason string) error
	IndustrialBalanceSub(token string, address types.Address, amount *big.Int, reason string) error

	AllowedIndustrialBalanceAdd(address types.Address, industrialAssets []*pb.Asset, reason string) error
	AllowedIndustrialBalanceSub(address types.Address, industrialAssets []*pb.Asset, reason string) error
	AllowedIndustrialBalanceTransfer(from types.Address, to types.Address, industrialAssets []*pb.Asset, reason string) error
}
