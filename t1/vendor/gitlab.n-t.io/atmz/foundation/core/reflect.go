package core

import (
	"errors"
	"fmt"
	"reflect"
	"unicode"

	"gitlab.n-t.io/atmz/foundation/core/types"
)

type in struct {
	kind          reflect.Type
	prepareToSave reflect.Value
	convertToCall reflect.Value
}

type fn struct {
	fn        reflect.Value
	query     bool
	noBatch   bool
	needsAuth bool
	in        []in
	out       bool
}

func ParseContract(in BaseContractInterface, options *ContractOptions) (map[string]*fn, error) {
	out := make(map[string]*fn)
	t := reflect.TypeOf(in)
	for i := 0; i < t.NumMethod(); i++ {
		method := t.Method(i)
		nb := false
		query := false
		if options != nil && contains(options.DisabledFunctions, method.Name) {
			continue
		}
		if options != nil && options.DisableSwaps && (method.Name == "QuerySwapGet" ||
			method.Name == "TxSwapBegin" || method.Name == "TxSwapCancel") {
			continue
		}
		if options != nil && options.DisableMultiSwaps && (method.Name == "QueryMultiSwapGet" ||
			method.Name == "TxMultiSwapBegin" || method.Name == "TxMultiSwapCancel") {
			continue
		}
		if len(method.Name) > 4 && method.Name[0:4] == "NBTx" {
			nb = true
			method.Name = method.Name[4:]
		} else if len(method.Name) > 5 && method.Name[0:5] == "Query" {
			query = true
			nb = true
			method.Name = method.Name[5:]
		} else if len(method.Name) > 2 && method.Name[0:2] == "Tx" {
			method.Name = method.Name[2:]
		} else {
			continue
		}
		name := ToLowerFirstLetter(method.Name)
		out[name] = &fn{
			fn:      method.Func,
			noBatch: nb,
			query:   query,
		}
		if err := out[name].getInputs(method); err != nil {
			return nil, err
		}
		var err error
		out[name].out, err = checkOut(method)
		if err != nil {
			return nil, err
		}
		in.addMethod(name)
	}
	return out, nil
}

func (f *fn) getInputs(method reflect.Method) error {
	count := method.Type.NumIn()
	if method.Type.NumIn() > 1 && method.Type.In(1).String() == "types.Sender" {
		f.needsAuth = true
	}
	f.in = make([]in, count-1)
	for j := 1; j < count; j++ {
		inType := method.Type.In(j).String()

		in := in{kind: method.Type.In(j)}

		if m, ok := types.BaseTypes[inType]; ok {
			r := reflect.ValueOf(m)
			in.convertToCall = r
			f.in[j-1] = in
			continue
		}

		m, ok := method.Type.In(j).MethodByName("ConvertToCall")
		if !ok {
			return fmt.Errorf("unknown type: %s in method %s", method.Type.In(j).String(), method.Name)
		}
		if err := checkConvertationMethod(m, inType, "shim.ChaincodeStubInterface", "string", inType, "error"); err != nil {
			return err
		}
		in.convertToCall = m.Func

		if m, ok := method.Type.In(j).MethodByName("PrepareToSave"); ok {
			if err := checkConvertationMethod(m, inType, "shim.ChaincodeStubInterface", "string", "string", "error"); err != nil {
				return err
			}
			in.prepareToSave = m.Func
		}
		f.in[j-1] = in
	}
	return nil
}

func checkConvertationMethod(method reflect.Method, in0, in1, in2, out0, out1 string) error {
	tp := method.Type
	if tp.In(0).String() != in0 || tp.In(1).String() != in1 ||
		tp.In(2).String() != in2 || tp.Out(0).String() != out0 ||
		tp.Out(1).String() != out1 {
		return fmt.Errorf("method %s can not be convertor", method.Name)
	}
	return nil
}

func checkOut(method reflect.Method) (bool, error) {
	count := method.Type.NumOut()
	if count == 1 && method.Type.Out(0).String() == "error" {
		return false, nil
	}
	if count == 2 && method.Type.Out(1).String() == "error" {
		return true, nil
	}
	return false, errors.New("unknown output types " + method.Name)
}

func ToLowerFirstLetter(in string) string {
	return string(unicode.ToLower(rune(in[0]))) + in[1:]
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
