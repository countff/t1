package core

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"gitlab.n-t.io/atmz/foundation/core/types"
	"gitlab.n-t.io/atmz/foundation/golang-math-big"
	"gitlab.n-t.io/atmz/foundation/proto"
	"golang.org/x/crypto/sha3"
	"log"
	"runtime/debug"
	"strings"

	pb "github.com/golang/protobuf/proto"
)

const (
	userSideTimeout  = 10800 // 3 hours
	robotSideTimeout = 300   // 5 minutes
)

func swapAnswer(stub *batchStub, creatorSKI string, swap *proto.Swap) (r *proto.SwapResponse) {
	r = &proto.SwapResponse{Id: swap.Id, Error: &proto.ResponseError{Error: "panic swapAnswer"}}
	defer func() {
		if r := recover(); r != nil {
			log.Println("panic swapAnswer: " + hex.EncodeToString(swap.Id) + "\n" + string(debug.Stack()))
		}
	}()

	ts, err := stub.GetTxTimestamp()
	if err != nil {
		return &proto.SwapResponse{Id: swap.Id, Error: &proto.ResponseError{Error: err.Error()}}
	}
	txStub := stub.newTxStub(hex.EncodeToString(swap.Id), creatorSKI)

	swap.Creator = []byte("0000")
	swap.Timeout = ts.Seconds + robotSideTimeout

	switch {
	case swap.TokenSymbol() == swap.From:
		// nothing to do
	case swap.TokenSymbol() == swap.To:
		if err := GivenBalanceSub(txStub, swap.From, new(big.Int).SetBytes(swap.Amount)); err != nil {
			return &proto.SwapResponse{Id: swap.Id, Error: &proto.ResponseError{Error: err.Error()}}
		}
	default:
		return &proto.SwapResponse{Id: swap.Id, Error: &proto.ResponseError{Error: "incorrect swap"}}
	}

	if _, err := SwapSave(txStub, hex.EncodeToString(swap.Id), swap); err != nil {
		return &proto.SwapResponse{Id: swap.Id, Error: &proto.ResponseError{Error: err.Error()}}
	}
	writes, _ := txStub.Commit()
	return &proto.SwapResponse{Id: swap.Id, Writes: writes}
}

func swapRobotDone(stub *batchStub, creatorSKI string, swapID []byte, key string) (r *proto.SwapResponse) {
	r = &proto.SwapResponse{Id: swapID, Error: &proto.ResponseError{Error: "panic swapRobotDone"}}
	defer func() {
		if r := recover(); r != nil {
			log.Println("panic swapRobotDone: " + hex.EncodeToString(swapID) + "\n" + string(debug.Stack()))
		}
	}()

	txStub := stub.newTxStub(hex.EncodeToString(swapID), creatorSKI)
	s, err := SwapLoad(txStub, hex.EncodeToString(swapID))
	if err != nil {
		return &proto.SwapResponse{Id: swapID, Error: &proto.ResponseError{Error: err.Error()}}
	}
	hash := sha3.Sum256([]byte(key))
	if !bytes.Equal(s.Hash, hash[:]) {
		return &proto.SwapResponse{Id: swapID, Error: &proto.ResponseError{Error: "incorrect key"}}
	}

	if s.TokenSymbol() == s.From {
		if err := GivenBalanceAdd(txStub, s.To, new(big.Int).SetBytes(s.Amount)); err != nil {
			return &proto.SwapResponse{Id: swapID, Error: &proto.ResponseError{Error: err.Error()}}
		}
	}
	if err := SwapDel(txStub, hex.EncodeToString(swapID)); err != nil {
		return &proto.SwapResponse{Id: swapID, Error: &proto.ResponseError{Error: err.Error()}}
	}
	writes, _ := txStub.Commit()
	return &proto.SwapResponse{Id: swapID, Writes: writes}
}

func swapUserDone(bc BaseContractInterface, swapID string, key string) peer.Response {
	s, err := SwapLoad(bc.GetStub(), swapID)
	if err != nil {
		return shim.Error(err.Error())
	}
	hash := sha3.Sum256([]byte(key))
	if !bytes.Equal(s.Hash, hash[:]) {
		return shim.Error("incorrect key")
	}

	if bytes.Equal(s.Creator, s.Owner) {
		return shim.Error("incorrect swap")
	}
	if s.TokenSymbol() == s.From {
		if err := bc.AllowedBalanceAdd(s.Token, types.AddrFromBytes(s.Owner), new(big.Int).SetBytes(s.Amount), "swap"); err != nil {
			return shim.Error(err.Error())
		}
	} else {
		if err := bc.tokenBalanceAdd(types.AddrFromBytes(s.Owner), new(big.Int).SetBytes(s.Amount), s.Token); err != nil {
			return shim.Error(err.Error())
		}
	}
	if err := SwapDel(bc.GetStub(), swapID); err != nil {
		return shim.Error(err.Error())
	}
	e := strings.Join([]string{s.From, swapID, key}, "\t")
	if err := bc.GetStub().SetEvent("key", []byte(e)); err != nil {
		shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func (bc *BaseContract) QuerySwapGet(swapID string) (*proto.Swap, error) {
	swap, err := SwapLoad(bc.GetStub(), swapID)
	if err != nil {
		return nil, err
	}
	return swap, nil
}

func (bc *BaseContract) TxSwapBegin(sender types.Sender, token string, contractTo string, amount *big.Int, hash types.Hex) (string, error) {
	id, err := hex.DecodeString(bc.GetStub().GetTxID())
	if err != nil {
		return "", err
	}
	ts, err := bc.GetStub().GetTxTimestamp()
	if err != nil {
		return "", err
	}
	s := proto.Swap{
		Id:      id,
		Creator: sender.Address().Bytes(),
		Owner:   sender.Address().Bytes(),
		Token:   token,
		Amount:  amount.Bytes(),
		From:    bc.id,
		To:      contractTo,
		Hash:    hash,
		Timeout: ts.Seconds + userSideTimeout,
	}

	switch {
	case s.TokenSymbol() == s.From:
		if err := bc.tokenBalanceSub(types.AddrFromBytes(s.Owner), amount, s.Token); err != nil {
			return "", err
		}
	case s.TokenSymbol() == s.To:
		if err := bc.AllowedBalanceSub(s.Token, types.AddrFromBytes(s.Owner), amount, "swap"); err != nil {
			return "", err
		}
	default:
		return "", errors.New("incorrect swap")
	}

	_, err = SwapSave(bc.GetStub(), bc.GetStub().GetTxID(), &s)
	if err != nil {
		return "", err
	}

	if batchTxStub, ok := bc.stub.(*batchTxStub); ok {
		batchTxStub.swaps = append(batchTxStub.swaps, &s)
	}
	return bc.GetStub().GetTxID(), nil
}

func (bc *BaseContract) TxSwapCancel(sender types.Sender, swapID string) error {
	s, err := SwapLoad(bc.GetStub(), swapID)
	if err != nil {
		return err
	}
	if !bytes.Equal(s.Creator, sender.Address().Bytes()) {
		return errors.New("unauthorized")
	}
	ts, err := bc.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	if s.Timeout > ts.Seconds {
		return errors.New("wait for timeout to end")
	}
	switch {
	case bytes.Equal(s.Creator, s.Owner) && s.TokenSymbol() == s.From:
		if err := bc.tokenBalanceAdd(types.AddrFromBytes(s.Owner), new(big.Int).SetBytes(s.Amount), s.Token); err != nil {
			return err
		}
	case bytes.Equal(s.Creator, s.Owner) && s.TokenSymbol() == s.To:
		if err := bc.AllowedBalanceAdd(s.Token, types.AddrFromBytes(s.Owner), new(big.Int).SetBytes(s.Amount), "swap"); err != nil {
			return err
		}
	case bytes.Equal(s.Creator, []byte("0000")) && s.TokenSymbol() == s.To:
		if err := GivenBalanceAdd(bc.GetStub(), s.From, new(big.Int).SetBytes(s.Amount)); err != nil {
			return err
		}
	}
	if err := SwapDel(bc.GetStub(), swapID); err != nil {
		return err
	}
	return nil
}

func SwapLoad(stub shim.ChaincodeStubInterface, swapID string) (*proto.Swap, error) {
	key, err := stub.CreateCompositeKey("swaps", []string{swapID})
	if err != nil {
		return nil, err
	}
	data, err := stub.GetState(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, errors.New("swap doesn't exist")
	}
	var s proto.Swap
	if err := pb.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func SwapSave(stub shim.ChaincodeStubInterface, swapID string, s *proto.Swap) ([]byte, error) {
	key, err := stub.CreateCompositeKey("swaps", []string{swapID})
	if err != nil {
		return nil, err
	}
	data, err := pb.Marshal(s)
	if err != nil {
		return nil, err
	}
	return data, stub.PutState(key, data)
}

func SwapDel(stub shim.ChaincodeStubInterface, swapID string) error {
	key, err := stub.CreateCompositeKey("swaps", []string{swapID})
	if err != nil {
		return err
	}
	return stub.DelState(key)
}
