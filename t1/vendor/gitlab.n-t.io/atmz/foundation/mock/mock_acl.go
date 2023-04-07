package mock

import (
	"bytes"
	"encoding/json"
	"github.com/btcsuite/btcutil/base58"
	"gitlab.n-t.io/atmz/foundation/proto"
	"golang.org/x/crypto/sha3"
	"sort"
	"strings"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"

	pb "github.com/golang/protobuf/proto"
)

type mockACL struct{}

func (acl *mockACL) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}
func (acl *mockACL) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	fn, args := stub.GetFunctionAndParameters()
	switch fn {
	case "checkKeys":
		keys := strings.Split(args[0], "/")
		binPubKeys := make([][]byte, len(keys))
		for i, k := range keys {
			binPubKeys[i] = base58.Decode(k)
		}
		sort.Slice(binPubKeys, func(i, j int) bool {
			return bytes.Compare(binPubKeys[i], binPubKeys[j]) < 0
		})

		hashed := sha3.Sum256(bytes.Join(binPubKeys, []byte("")))
		data, err := pb.Marshal(&proto.AclResponse{
			Account: &proto.AccountInfo{
				KycHash:    "123",
				GrayListed: false,
			},
			Address: &proto.SignedAddress{
				Address: &proto.Address{Address: hashed[:]},
				SignaturePolicy: &proto.SignaturePolicy{
					N: 2,
				},
			},
		})
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(data)
	case "getAccountInfo":
		data, err := json.Marshal(&proto.AccountInfo{
			KycHash:     "123",
			GrayListed:  false,
			BlackListed: false,
		})
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(data)
	default:
		panic("should not be here")
	}
	return shim.Success(nil)
}
