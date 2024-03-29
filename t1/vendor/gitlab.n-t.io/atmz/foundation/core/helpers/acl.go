package helpers

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	pb "gitlab.n-t.io/atmz/foundation/proto"
	"strings"
)

const (
	accInfoPrefix         = "accountinfo"
	replaceTxChangePrefix = "replacetx"
	signedTxChangePrefix  = "signedtx"
)

// AddAddrIfChanged looks to ACL for pb.Address saved for specific pubkeys and checks addr changed or not (does have pb.Address SignedTx field or not)
// if address changed in ACL, we commit it to token channel too
func AddAddrIfChanged(stub shim.ChaincodeStubInterface, addrMsgFromAcl *pb.SignedAddress) error {
	// check if it multisig and it's pubkeys changed or not
	if addrMsgFromAcl.Address.IsMultisig {
		chngTx, err := shim.CreateCompositeKey(replaceTxChangePrefix, []string{base58.CheckEncode(addrMsgFromAcl.Address.Address[1:], addrMsgFromAcl.Address.Address[0])})
		if err != nil {
			return err
		}
		signedChangeTxBytes, err := stub.GetState(chngTx)
		if err != nil {
			return err
		}
		// if there is no public key change transaction in the token channel, but such a transaction is present in the ACL
		if len(signedChangeTxBytes) == 0 && len(addrMsgFromAcl.SignaturePolicy.ReplaceKeysSignedTx) != 0 {
			m, err := json.Marshal(addrMsgFromAcl.SignaturePolicy.ReplaceKeysSignedTx)
			err = stub.PutState(chngTx, m)
			if err != nil {
				return err
			}
			// if public key change transaction is present in both channels
		} else if len(signedChangeTxBytes) != 0 && len(addrMsgFromAcl.SignaturePolicy.ReplaceKeysSignedTx) != 0 {
			var signedChangeTx []string
			if err = json.Unmarshal(signedChangeTxBytes, &signedChangeTx); err != nil {
				return fmt.Errorf("failed to unmarshal replace tx: %s", err)
			}
			for index, replaceTx := range addrMsgFromAcl.SignaturePolicy.ReplaceKeysSignedTx {
				if replaceTx != signedChangeTx[index] {
					// pubkeys in multisig already changed, put new pb.SignedAddress to token channel too
					m, err := json.Marshal(addrMsgFromAcl.SignaturePolicy.ReplaceKeysSignedTx)
					err = stub.PutState(chngTx, m)
					if err != nil {
						return err
					}
					break
				}
			}
		}
	}

	chngTx, err := shim.CreateCompositeKey(signedTxChangePrefix, []string{base58.CheckEncode(addrMsgFromAcl.Address.Address[1:], addrMsgFromAcl.Address.Address[0])})
	if err != nil {
		return err
	}
	signedChangeTxBytes, err := stub.GetState(chngTx)
	if err != nil {
		return err
	}
	// if there is no public key change transaction in the token channel, but such a transaction is present in the ACL
	if len(signedChangeTxBytes) == 0 && len(addrMsgFromAcl.SignedTx) != 0 {
		m, err := json.Marshal(addrMsgFromAcl.SignedTx)
		err = stub.PutState(chngTx, m)
		if err != nil {
			return err
		}
		// if public key change transaction is present in both channels
	} else if len(signedChangeTxBytes) != 0 && len(addrMsgFromAcl.SignedTx) != 0 {
		var signedChangeTx []string
		if err = json.Unmarshal(signedChangeTxBytes, &signedChangeTx); err != nil {
			return fmt.Errorf("failed to unmarshal signed tx: %s", err)
		}
		// check if pb.SignedAddress from ACL has the same SignedTx as pb.SignedAddress saved in the token channel
		for index, changePubkeyTx := range addrMsgFromAcl.SignedTx {
			if changePubkeyTx != signedChangeTx[index] {
				// pubkey already changed, put new SignedTx to token channel too
				m, err := json.Marshal(addrMsgFromAcl.SignedTx)
				err = stub.PutState(chngTx, m)
				if err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}

func CheckACL(stub shim.ChaincodeStubInterface, keys []string) (*pb.AclResponse, error) {
	return GetAddress(stub, strings.Join(keys, "/"))
}

func GetAddress(stub shim.ChaincodeStubInterface, keys string) (*pb.AclResponse, error) {
	resp := stub.InvokeChaincode("acl", [][]byte{
		[]byte("checkKeys"),
		[]byte(keys),
	}, "acl")

	if resp.Status != 200 {
		return nil, errors.New(resp.Message)
	}

	if len(resp.Payload) == 0 {
		return nil, errors.New("empty response")
	}

	addrMsg := &pb.AclResponse{}
	if err := proto.Unmarshal(resp.Payload, addrMsg); err != nil {
		return nil, err
	}

	return addrMsg, nil
}

func GetAccountInfo(stub shim.ChaincodeStubInterface, addr string) (*pb.AccountInfo, error) {
	resp := stub.InvokeChaincode("acl", [][]byte{
		[]byte("getAccountInfo"),
		[]byte(addr),
	}, "acl")

	if resp.Status != 200 {
		return nil, errors.New(resp.Message)
	}
	if len(resp.Payload) == 0 {
		return nil, errors.New("empty response")
	}

	infoMsg := pb.AccountInfo{}
	if err := json.Unmarshal(resp.Payload, &infoMsg); err != nil {
		return nil, err
	}
	return &infoMsg, nil
}
