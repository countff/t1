package core

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	"gitlab.n-t.io/atmz/foundation/proto"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"

	pb "github.com/golang/protobuf/proto"

	"sort"
	"strings"
)

const batchKey = "batchTransactions"

func saveToBatch(stub shim.ChaincodeStubInterface, fn string, creatorSKI []byte, args []string) error {
	logger := Logger()
	txID := stub.GetTxID()
	key, err := stub.CreateCompositeKey(batchKey, []string{txID})
	if err != nil {
		logger.Errorf("Couldn't create composite key for tx %s: %s", txID, err.Error())
		return err
	}
	data, err := json.Marshal(append([]string{fn, hex.EncodeToString(creatorSKI)}, args...))
	if err != nil {
		logger.Errorf("Couldn't marshal transaction %s: %s", txID, err.Error())
		return err
	}
	return stub.PutState(key, data)
}

func loadFromBatch(stub shim.ChaincodeStubInterface, txID string) (string, string, []string, error) {
	logger := Logger()
	key, err := stub.CreateCompositeKey(batchKey, []string{txID})
	if err != nil {
		logger.Errorf("Couldn't create composite key for tx %s: %s", txID, err.Error())
		return "", "", nil, err
	}
	data, err := stub.GetState(key)
	if err != nil {
		logger.Errorf("Couldn't load transaction %s from state: %s", txID, err.Error())
		return "", "", nil, err
	}
	if len(data) == 0 {
		logger.Warningf("Transaction %s not found", txID)
		return "", "", nil, fmt.Errorf("transaction %s not found", txID)
	}
	var args []string
	if err := json.Unmarshal(data, &args); err != nil {
		logger.Errorf("Couldn't unmarshal transaction %s: %s", txID, err.Error())
		return "", "", nil, err
	}
	return args[0], args[1], args[2:], nil
}

func (cc *ChainCode) batchExecute(stub shim.ChaincodeStubInterface, creatorSKI string, dataIn string) peer.Response {
	logger := Logger()
	batchID := stub.GetTxID()
	batchStub := newBatchStub(stub)
	start := time.Now()
	defer func() {
		logger.Infof("batch %s elapsed time %d ms", batchID, time.Since(start).Milliseconds())
	}()

	response := proto.BatchResponse{}
	events := proto.BatchEvent{}

	var batch proto.Batch
	if err := pb.Unmarshal([]byte(dataIn), &batch); err != nil {
		logger.Errorf("Couldn't unmarshal batch %s: %s", batchID, err.Error())
		return shim.Error(err.Error())
	}

	for _, txID := range batch.TxIDs {
		resp, event := cc.batchedTxExecute(batchStub, txID)
		response.TxResponses = append(response.TxResponses, resp)
		events.Events = append(events.Events, event)
	}

	if !cc.disableSwaps {
		for _, swap := range batch.Swaps {
			response.SwapResponses = append(response.SwapResponses, swapAnswer(batchStub, creatorSKI, swap))
		}

		for _, swapKey := range batch.Keys {
			response.SwapKeyResponses = append(response.SwapKeyResponses, swapRobotDone(batchStub, creatorSKI, swapKey.Id, swapKey.Key))
		}
	}

	if !cc.disableMultiSwaps {
		for _, swap := range batch.MultiSwaps {
			response.SwapResponses = append(response.SwapResponses, multiSwapAnswer(batchStub, creatorSKI, swap))
		}

		for _, swapKey := range batch.MultiSwapsKeys {
			response.SwapKeyResponses = append(response.SwapKeyResponses, multiSwapRobotDone(batchStub, creatorSKI, swapKey.Id, swapKey.Key))
		}
	}

	if err := batchStub.Commit(); err != nil {
		logger.Errorf("Couldn't commit batch %s: %s", batchID, err.Error())
		return shim.Error(err.Error())
	}

	response.CreatedSwaps = batchStub.swaps
	response.CreatedMultiSwap = batchStub.multiSwaps

	data, err := pb.Marshal(&response)
	if err != nil {
		logger.Errorf("Couldn't marshal batch response %s: %s", batchID, err.Error())
		return shim.Error(err.Error())
	}
	eventData, err := pb.Marshal(&events)
	if err != nil {
		logger.Errorf("Couldn't marshal batch event %s: %s", batchID, err.Error())
		return shim.Error(err.Error())
	}
	if err := stub.SetEvent("batchExecute", eventData); err != nil {
		logger.Errorf("Couldn't set batch event %s: %s", batchID, err.Error())
		return shim.Error(err.Error())
	}
	return shim.Success(data)
}

type TxResponse struct {
	Method     string                    `json:"method"`
	Error      string                    `json:"error,omitempty"`
	Result     string                    `json:"result"`
	Events     map[string][]byte         `json:"events,omitempty"`
	Accounting []*proto.AccountingRecord `json:"accounting"`
}

func (cc *ChainCode) batchedTxExecute(stub *batchStub, binaryTxID []byte) (r *proto.TxResponse, e *proto.BatchTxEvent) {
	logger := Logger()
	start := time.Now()
	methodName := "unknown"

	txID := hex.EncodeToString(binaryTxID)
	defer func() {
		logger.Infof("batched method %s txid %s elapsed time %d ms", methodName, txID, time.Since(start).Milliseconds())
	}()

	r = &proto.TxResponse{Id: binaryTxID, Error: &proto.ResponseError{Error: "panic batchedTxExecute"}}
	e = &proto.BatchTxEvent{Id: binaryTxID, Error: &proto.ResponseError{Error: "panic batchedTxExecute"}}
	defer func() {
		if r := recover(); r != nil {
			logger.Criticalf("Tx %s panicked:\n%s", txID, string(debug.Stack()))
		}
	}()

	fn, creator, args, err := loadFromBatch(stub.ChaincodeStubInterface, txID)
	if err != nil {
		ee := proto.ResponseError{Error: fmt.Sprintf("function and args loading error: %s", err.Error())}
		return &proto.TxResponse{Id: binaryTxID, Method: fn, Error: &ee}, &proto.BatchTxEvent{Id: binaryTxID, Method: fn, Error: &ee}
	}
	methodName = fn

	defer batchedTxDelete(stub.ChaincodeStubInterface, txID)

	txStub := stub.newTxStub(txID, creator)
	method, exists := cc.methods[fn]
	if !exists {
		logger.Infof("Unknown method %s in tx %s", fn, txID)
		err := proto.ResponseError{Error: fmt.Sprintf("unknown method %s", fn)}
		return &proto.TxResponse{Id: binaryTxID, Method: fn, Error: &err}, &proto.BatchTxEvent{Id: binaryTxID, Method: fn, Error: &err}
	}

	response, err := cc.callMethod(txStub, method, args)
	if err != nil {
		ee := proto.ResponseError{Error: err.Error()}
		return &proto.TxResponse{Id: binaryTxID, Method: fn, Error: &ee}, &proto.BatchTxEvent{Id: binaryTxID, Method: fn, Error: &ee}
	}

	writes, events := txStub.Commit()

	sort.Slice(txStub.accounting, func(i, j int) bool {
		return strings.Compare(txStub.accounting[i].String(), txStub.accounting[j].String()) < 0
	})

	return &proto.TxResponse{
			Id:     binaryTxID,
			Method: fn,
			Writes: writes,
		},
		&proto.BatchTxEvent{
			Id:         binaryTxID,
			Method:     fn,
			Accounting: txStub.accounting,
			Events:     events,
			Result:     response,
		}
}

func batchedTxDelete(stub shim.ChaincodeStubInterface, txID string) {
	logger := Logger()
	key, err := stub.CreateCompositeKey(batchKey, []string{txID})
	if err != nil {
		logger.Errorf("Couldn't create batch key for tx %s: %s", txID, err.Error())
	}
	if err := stub.DelState(key); err != nil {
		logger.Errorf("Couldn't delete from state tx %s: %s", txID, err.Error())
	}
}
