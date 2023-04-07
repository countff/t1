package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	pb "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/pkg/errors"
	"gitlab.n-t.io/atmz/foundation/proto"
	"golang.org/x/crypto/sha3"
	"log"
	"reflect"
	"runtime/debug"
	"strings"
)

type ChainCode struct {
	contract          BaseContractInterface
	methods           map[string]*fn
	allowedMspId      string
	checkInvokerBy    cib
	disableSwaps      bool
	init              *proto.InitArgs
	disableMultiSwaps bool
}

func NewChainCode(cc BaseContractInterface, allowedMspId string, options *ContractOptions) (ChainCode, error) {
	cc.baseContractInit(cc)
	methods, err := ParseContract(cc, options)
	if err != nil {
		return ChainCode{}, err
	}

	out := ChainCode{contract: cc, allowedMspId: allowedMspId, methods: methods}

	if options != nil {
		out.checkInvokerBy = options.CheckInvokerBy
		out.disableSwaps = options.DisableSwaps
		out.disableMultiSwaps = options.DisableMultiSwaps
	}

	return out, nil
}

func (cc ChainCode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	creator, err := stub.GetCreator()
	if err != nil {
		return shim.Error(err.Error())
	}
	var identity msp.SerializedIdentity
	if err := pb.Unmarshal(creator, &identity); err != nil {
		return shim.Error(err.Error())
	}
	if identity.Mspid != cc.allowedMspId {
		return shim.Error("incorrect MSP Id")
	}
	b, _ := pem.Decode(identity.IdBytes)
	parsed, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return shim.Error(err.Error())
	}
	ouIsOk := false
	for _, ou := range parsed.Subject.OrganizationalUnit {
		if strings.ToLower(ou) == "admin" {
			ouIsOk = true
		}
	}
	if !ouIsOk {
		return shim.Error("incorrect sender's OU")
	}
	args := stub.GetStringArgs()
	if len(args) < 2 {
		return shim.Error("should set ski of atomyze and robot certs")
	}
	atomyzeSKI, err := hex.DecodeString(args[0])
	if err != nil {
		return shim.Error(err.Error())
	}
	robotSKI, err := hex.DecodeString(args[1])
	if err != nil {
		return shim.Error(err.Error())
	}
	data, err := pb.Marshal(&proto.InitArgs{
		AtomyzeSKI: atomyzeSKI,
		RobotSKI:   robotSKI,
		Args:       args[2:],
	})
	if err != nil {
		return shim.Error(err.Error())
	}
	if err := stub.PutState("__init", data); err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func (cc ChainCode) Invoke(stub shim.ChaincodeStubInterface) (r peer.Response) {
	r = shim.Error("panic invoke")
	defer func() {
		if r := recover(); r != nil {
			log.Println("panic invoke\n" + string(debug.Stack()))
		}
	}()

	if cc.init == nil {
		data, err := stub.GetState("__init")
		if err != nil {
			return shim.Error(err.Error())
		}
		var args proto.InitArgs
		if err := pb.Unmarshal(data, &args); err != nil {
			return shim.Error(err.Error())
		}
		cc.init = &args
	}

	_, err := hex.DecodeString(stub.GetTxID())
	if err != nil {
		return shim.Error(fmt.Sprintf("incorrect tx id %s", err.Error()))
	}

	creator, err := stub.GetCreator()
	if err != nil {
		return shim.Error(err.Error())
	}
	var identity msp.SerializedIdentity
	if err := pb.Unmarshal(creator, &identity); err != nil {
		return shim.Error(err.Error())
	}
	b, _ := pem.Decode(identity.IdBytes)
	parsed, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return shim.Error(err.Error())
	}
	pk := parsed.PublicKey.(*ecdsa.PublicKey)
	creatorSKI := sha256.Sum256(elliptic.Marshal(pk.Curve, pk.X, pk.Y))

	fn, args := stub.GetFunctionAndParameters()
	switch fn {
	case "batchExecute":
		hashedCert := sha3.Sum256(creator)
		if !bytes.Equal(hashedCert[:], cc.init.RobotSKI) &&
			!bytes.Equal(creatorSKI[:], cc.init.RobotSKI) {
			return shim.Error("unauthorized")
		}
		return cc.batchExecute(stub, hex.EncodeToString(creatorSKI[:]), args[0])
	case "swapDone":
		if cc.disableSwaps {
			return shim.Error("swaps disabled")
		}
		_, contract := copyContract(cc.contract, stub, cc.allowedMspId, cc.init.AtomyzeSKI, cc.init.Args)
		return swapUserDone(contract, args[0], args[1])
	case "multiSwapDone":
		if cc.disableMultiSwaps {
			return shim.Error("industrial swaps disabled")
		}
		_, contract := copyContract(cc.contract, stub, cc.allowedMspId, cc.init.AtomyzeSKI, cc.init.Args)
		return multiSwapUserDone(contract, args[0], args[1])
	}
	method, exists := cc.methods[fn]
	if !exists {
		return shim.Error("unknown method")
	}
	if !method.query {
		switch cc.checkInvokerBy {
		case CheckInvokerByMSP:
			if identity.Mspid != cc.allowedMspId {
				return shim.Error("your mspId isn't allowed to invoke")
			}
		case CheckInvokerBySKI:
			if !bytes.Equal(creatorSKI[:], cc.init.AtomyzeSKI) {
				return shim.Error("only specified certificate can invoke")
			}
		}
	}
	if method.noBatch {
		args, err := checkAuthIfNeeds(stub, method, fn, args, true)
		if err != nil {
			return shim.Error(err.Error())
		}
		args, err = doPrepareToSave(stub, method, args)
		if err != nil {
			return shim.Error(err.Error())
		}
		resp, err := cc.callMethod(stub, method, args)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(resp)
	}

	args, err = checkAuthIfNeeds(stub, method, fn, args, true)

	if err != nil {
		return shim.Error(err.Error())
	}
	args, err = doPrepareToSave(stub, method, args)
	if err != nil {
		return shim.Error(err.Error())
	}
	if err := saveToBatch(stub, fn, creatorSKI[:], args[:len(method.in)]); err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func (cc *ChainCode) callMethod(stub shim.ChaincodeStubInterface, method *fn, args []string) ([]byte, error) {
	values, err := doConvertToCall(stub, method, args)
	if err != nil {
		return nil, err
	}

	contract, _ := copyContract(cc.contract, stub, cc.allowedMspId, cc.init.AtomyzeSKI, cc.init.Args)

	out := method.fn.Call(append([]reflect.Value{contract}, values...))
	if method.out {
		errIface := out[1].Interface()
		if errIface != nil {
			err, ok := errIface.(error)
			if !ok {
				return nil, errors.New("assertion interface -> error is failed")
			}
			return nil, err
		}
		return json.Marshal(out[0].Interface())
	}
	errInt := out[0].Interface()
	if errInt != nil {
		err, ok := errInt.(error)
		if !ok {
			return nil, errors.New("assertion interface -> error is failed")
		}
		return nil, err
	}
	return nil, nil
}

func doConvertToCall(stub shim.ChaincodeStubInterface, method *fn, args []string) ([]reflect.Value, error) {
	if len(args) < len(method.in) {
		return nil, errors.New("incorrect number of arguments")
	}
	// todo check is args enough
	vArgs := make([]reflect.Value, len(method.in))
	for i := range method.in {
		var impl reflect.Value
		if method.in[i].kind.Kind().String() == "ptr" {
			impl = reflect.New(method.in[i].kind.Elem())
		} else {
			impl = reflect.New(method.in[i].kind).Elem()
		}

		res := method.in[i].convertToCall.Call([]reflect.Value{
			impl,
			reflect.ValueOf(stub), reflect.ValueOf(args[i]),
		})

		if res[1].Interface() != nil {
			err, ok := res[1].Interface().(error)
			if !ok {
				return nil, errors.New("assertion interface -> error is failed")
			}
			return nil, err
		}
		vArgs[i] = res[0]
	}
	return vArgs, nil
}

func doPrepareToSave(stub shim.ChaincodeStubInterface, method *fn, args []string) ([]string, error) {
	if len(args) < len(method.in) {
		return nil, errors.New("incorrect number of arguments")
	}
	kArgs := make([]string, len(method.in))
	for i := range method.in {
		var impl reflect.Value
		if method.in[i].kind.Kind().String() == "ptr" {
			impl = reflect.New(method.in[i].kind.Elem())
		} else {
			impl = reflect.New(method.in[i].kind).Elem()
		}

		var ok bool
		if method.in[i].prepareToSave.IsValid() {
			res := method.in[i].prepareToSave.Call([]reflect.Value{
				impl,
				reflect.ValueOf(stub), reflect.ValueOf(args[i]),
			})
			if res[1].Interface() != nil {
				err, ok := res[1].Interface().(error)
				if !ok {
					return nil, errors.New("assertion interface -> error is failed")
				}
				return nil, err
			}
			kArgs[i], ok = res[0].Interface().(string)
			if !ok {
				return nil, errors.New("assertion interface -> string is failed")
			}
			continue
		}

		// if method PrepareToSave doesn't exists
		// use ConvertToCall to check converting
		res := method.in[i].convertToCall.Call([]reflect.Value{
			impl,
			reflect.ValueOf(stub), reflect.ValueOf(args[i]),
		})
		if res[1].Interface() != nil {
			err, ok := res[1].Interface().(error)
			if !ok {
				return nil, errors.New("assertion interface -> error is failed")
			}
			return nil, err
		}

		kArgs[i] = args[i] // in this case we don't convert argument
	}
	return kArgs, nil
}

func copyContract(orig BaseContractInterface, stub shim.ChaincodeStubInterface, allowedMspId string, atomyzeSKI []byte, initArgs []string) (reflect.Value, BaseContractInterface) {
	copy := reflect.New(reflect.ValueOf(orig).Elem().Type())
	val := reflect.ValueOf(orig).Elem()
	for i := 0; i < val.NumField(); i++ {
		if copy.Elem().Field(i).CanSet() {
			copy.Elem().Field(i).Set(val.Field(i))
		}
	}
	contract := copy.Interface().(BaseContractInterface)
	contract.setStubAndInitArgs(stub, allowedMspId, atomyzeSKI, initArgs)
	return copy, contract
}
