package mock

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"gitlab.n-t.io/atmz/foundation/core/types"
	"gitlab.n-t.io/atmz/foundation/golang-math-big"
	"io/ioutil"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	pb "github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"gitlab.n-t.io/atmz/foundation/core"
	"gitlab.n-t.io/atmz/foundation/proto"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

const batchRobotCert = "0a0a61746f6d797a654d535012d7062d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494943536a434341664367417749424167495241496b514e37444f456b6836686f52425057633157495577436759494b6f5a497a6a304541774977675963780a437a414a42674e5642415954416c56544d524d77455159445651514945777044595778705a6d3979626d6c684d525977464159445651514845773154595734670a526e4a68626d4e7063324e764d534d77495159445651514b45787068644739746558706c4c6e56686443356b624851755958527662586c365a53356a6144456d0a4d4351474131554541784d64593245755958527662586c365a533531595851755a4778304c6d463062323135656d5575593267774868634e4d6a41784d44457a0a4d4467314e6a41775768634e4d7a41784d4445784d4467314e6a4177576a42324d517377435159445651514745774a56557a45544d4245474131554543424d4b0a5132467361575a76636d3570595445574d4251474131554542784d4e5532467549455a795957356a61584e6a627a45504d4130474131554543784d47593278700a5a5735304d536b774a7759445651514444434256633256794d554268644739746558706c4c6e56686443356b624851755958527662586c365a53356a6144425a0a4d424d4742797147534d34394167454743437147534d3439417745484130494142427266315057484d51674d736e786263465a346f3579774b476e677830594e0a504b6270494335423761446f6a46747932576e4871416b5656723270697853502b4668497634434c634935633162473963365a375738616a5454424c4d4134470a41315564447745422f775145417749486744414d42674e5648524d4241663845416a41414d437347413155644977516b4d434b4149464b2f5335356c6f4865700a6137384441363173364e6f7433727a4367436f435356386f71462b37585172344d416f4743437147534d343942414d43413067414d4555434951436e6870476d0a58515664754b632b634266554d6b31494a6835354444726b3335436d436c4d657041533353674967596b634d6e5a6b385a42727179796953544d6466526248740a5a32506837364e656d536b62345651706230553d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a"
const userCert = `MIICSTCCAe+gAwIBAgIQW3KyKC2acfVxSNneRkHZPjAKBggqhkjOPQQDAjCBhzEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG
cmFuY2lzY28xIzAhBgNVBAoTGmF0b215emUudWF0LmRsdC5hdG9teXplLmNoMSYw
JAYDVQQDEx1jYS5hdG9teXplLnVhdC5kbHQuYXRvbXl6ZS5jaDAeFw0yMDEwMTMw
ODU2MDBaFw0zMDEwMTEwODU2MDBaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpD
YWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQLEwZjbGll
bnQxKTAnBgNVBAMMIFVzZXI5QGF0b215emUudWF0LmRsdC5hdG9teXplLmNoMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp5H9GVCTmUnVo8dHBTCT7cHmK4xn2X+Y
jJEsrbhodUt9GjUx04uOo05uRWhOI+O4fi0EEu+RSkx98hFUapWfRqNNMEswDgYD
VR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwKwYDVR0jBCQwIoAgUr9LnmWgd6lr
vwMDrWzo2i3evMKAKgJJXyioX7tdCvgwCgYIKoZIzj0EAwIDSAAwRQIhAPUozDTR
MOS4WBh87DbsJjI8gIuXPGXwoFXDQQhc2gz0AiAz9jt95z3MKnwj0dWPhjnzAGP8
8PrsVxYtGp6/TnpiPQ==`

type wallet struct {
	ledger *ledger
	pKey   ed25519.PublicKey
	sKey   ed25519.PrivateKey
	addr   string
}

// change private key, then public key will be derived and changed too
func (w *wallet) ChangeKeys(sKey ed25519.PrivateKey) error {
	w.sKey = sKey
	var ok bool
	w.pKey, ok = sKey.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("failed to derive public key from secret")
	}
	return nil

}

func (w *wallet) Address() string {
	return w.addr
}

func (w *wallet) PubKey() []byte {
	return w.pKey
}

func (w *wallet) SecretKey() []byte {
	return w.sKey
}

func (w *wallet) SetPubKey(pk ed25519.PublicKey) {
	w.pKey = pk
}

func (w *wallet) AddressType() types.Address {
	value, ver, err := base58.CheckDecode(w.addr)
	if err != nil {
		panic(err)
	}
	return types.Address{Address: append([]byte{ver}, value...)[:32]}
}

func (w *wallet) addBalance(stub *MockStub, amount *big.Int, balanceType core.StateKey, path ...string) {
	prefix := hex.EncodeToString([]byte{byte(balanceType)})
	key, err := stub.CreateCompositeKey(prefix, append([]string{w.Address()}, path...))
	assert.NoError(w.ledger.t, err)
	data := stub.State[key]
	balance := new(big.Int).SetBytes(data)
	newBalance := new(big.Int).Add(balance, amount)
	stub.PutBalanceToState(key, newBalance)
}

func (w *wallet) CheckGivenBalanceShouldBe(ch string, token string, expectedBalance uint64) {
	stub := w.ledger.stubs[ch]
	prefix := hex.EncodeToString([]byte{byte(core.StateKeyGivenBalance)})
	key, err := stub.CreateCompositeKey(prefix, []string{token})
	assert.NoError(w.ledger.t, err)
	bytes := stub.State[key]
	if bytes == nil && expectedBalance == 0 {
		return
	}
	actualBalanceInt := new(big.Int).SetBytes(bytes)
	expectedBalanceInt := new(big.Int).SetUint64(expectedBalance)
	assert.Equal(w.ledger.t, expectedBalanceInt, actualBalanceInt)
}

func (w *wallet) AddBalance(ch string, amount uint64) {
	w.addBalance(w.ledger.stubs[ch], new(big.Int).SetUint64(amount), core.StateKeyTokenBalance)
}

func (w *wallet) AddAllowedBalance(ch string, token string, amount uint64) {
	w.addBalance(w.ledger.stubs[ch], new(big.Int).SetUint64(amount), core.StateKeyAllowedBalance, token)
}

func (w *wallet) AddGivenBalance(ch string, givenBalanceChannel string, amount uint64) {
	stub := w.ledger.stubs[ch]
	prefix := hex.EncodeToString([]byte{byte(core.StateKeyGivenBalance)})
	key, err := stub.CreateCompositeKey(prefix, []string{givenBalanceChannel})
	assert.NoError(w.ledger.t, err)
	newBalance := new(big.Int).SetUint64(amount)
	stub.PutBalanceToState(key, newBalance)
}

func (w *wallet) AddTokenBalance(ch string, token string, amount uint64) {
	parts := strings.Split(token, "_")
	if len(parts) > 1 {
		w.addBalance(w.ledger.stubs[ch], new(big.Int).SetUint64(amount), core.StateKeyTokenBalance, parts[1])
	} else {
		w.addBalance(w.ledger.stubs[ch], new(big.Int).SetUint64(amount), core.StateKeyTokenBalance, token)
	}
}

func (w *wallet) BalanceShouldBe(ch string, expected uint64) {
	assert.Equal(w.ledger.t, "\""+strconv.FormatUint(expected, 10)+"\"", w.Invoke(ch, "balanceOf", w.Address()))
}

func (w *wallet) AllowedBalanceShouldBe(ch string, token string, expected uint64) {
	assert.Equal(w.ledger.t, "\""+strconv.FormatUint(expected, 10)+"\"", w.Invoke(ch, "allowedBalanceOf", w.Address(), token))
}

func (w *wallet) OtfBalanceShouldBe(ch string, token string, expected uint64) {
	assert.Equal(w.ledger.t, "\""+strconv.FormatUint(expected, 10)+"\"", w.Invoke(ch, "getBalance", w.Address(), token))
}

func (w *wallet) IndustrialBalanceShouldBe(ch, group string, expected uint64) {
	var balances map[string]string
	res := w.Invoke(ch, "industrialBalanceOf", w.Address())
	assert.NoError(w.ledger.t, json.Unmarshal([]byte(res), &balances))

	if balance, ok := balances[group]; ok {
		assert.Equal(w.ledger.t, strconv.FormatUint(expected, 10), balance)
	} else if expected == 0 {
		return
	} else {
		assert.Fail(w.ledger.t, "group not found")
	}
}

func (w *wallet) GroupBalanceShouldBe(ch, group string, expected uint64) {
	var balances map[string]string
	res := w.Invoke(ch, "groupBalanceOf", w.Address())
	assert.NoError(w.ledger.t, json.Unmarshal([]byte(res), &balances))

	if balance, ok := balances[group]; ok {
		assert.Equal(w.ledger.t, strconv.FormatUint(expected, 10), balance)
	} else if expected == 0 {
		return
	} else {
		assert.Fail(w.ledger.t, "group not found")
	}
}

func (w *wallet) Invoke(ch string, fn string, args ...string) string {
	return w.ledger.doInvoke(ch, txIDGen(), fn, args...)
}

func (w *wallet) BatchedInvoke(ch string, fn string, args ...string) (string, TxResponse) {
	txID := txIDGen()
	w.ledger.doInvoke(ch, txID, fn, args...)

	id, err := hex.DecodeString(txID)
	assert.NoError(w.ledger.t, err)
	data, err := pb.Marshal(&proto.Batch{TxIDs: [][]byte{id}})
	assert.NoError(w.ledger.t, err)

	cert, err := hex.DecodeString(batchRobotCert)
	assert.NoError(w.ledger.t, err)
	w.ledger.stubs[ch].SetCreator(cert)
	res := w.Invoke(ch, "batchExecute", string(data))
	out := &proto.BatchResponse{}
	assert.NoError(w.ledger.t, pb.Unmarshal([]byte(res), out))

	e := <-w.ledger.stubs[ch].ChaincodeEventsChannel
	if e.EventName == "batchExecute" {
		events := &proto.BatchEvent{}
		assert.NoError(w.ledger.t, pb.Unmarshal(e.Payload, events))
		for _, e := range events.Events {
			if hex.EncodeToString(e.Id) == txID {
				events := make(map[string][]byte)
				for _, e := range e.Events {
					events[e.Name] = e.Value
				}
				err := ""
				if e.Error != nil {
					err = e.Error.Error
				}
				return txID, TxResponse{
					Method: e.Method,
					Error:  err,
					Result: string(e.Result),
					Events: events,
				}
			}
		}
	}
	assert.Fail(w.ledger.t, "shouldn't be here")
	return txID, TxResponse{}
}

func (w *wallet) sign(fn string, ch string, args ...string) ([]string, string) {
	time.Sleep(time.Millisecond * 5)
	nonce := strconv.FormatInt(time.Now().UnixNano()/1000000, 10)
	result := append(append([]string{fn, "", ch, ch}, args...), nonce, base58.Encode(w.pKey))
	message := sha3.Sum256([]byte(strings.Join(result, "")))
	return append(result[1:], base58.Encode(ed25519.Sign(w.sKey, message[:]))), hex.EncodeToString(message[:])
}

func (w *wallet) RawSignedInvoke(ch string, fn string, args ...string) (string, TxResponse, []*proto.Swap) {
	invoke, response, swaps, _ := w.RawSignedMultiSwapInvoke(ch, fn, args...)
	return invoke, response, swaps
}

func (w *wallet) Ledger() *ledger {
	return w.ledger
}

func (w *wallet) RawSignedMultiSwapInvoke(ch string, fn string, args ...string) (string, TxResponse, []*proto.Swap, []*proto.MultiSwap) {
	txID := txIDGen()
	args, _ = w.sign(fn, ch, args...)
	cert, err := base64.StdEncoding.DecodeString(userCert)
	assert.NoError(w.ledger.t, err)
	w.ledger.stubs[ch].SetCreatorCert("atomyzeMSP", cert)
	w.ledger.doInvoke(ch, txID, fn, args...)

	id, err := hex.DecodeString(txID)
	assert.NoError(w.ledger.t, err)
	data, err := pb.Marshal(&proto.Batch{TxIDs: [][]byte{id}})
	assert.NoError(w.ledger.t, err)

	cert, err = hex.DecodeString(batchRobotCert)
	assert.NoError(w.ledger.t, err)
	w.ledger.stubs[ch].SetCreator(cert)
	res := w.Invoke(ch, "batchExecute", string(data))
	out := &proto.BatchResponse{}
	assert.NoError(w.ledger.t, pb.Unmarshal([]byte(res), out))

	e := <-w.ledger.stubs[ch].ChaincodeEventsChannel
	if e.EventName == "batchExecute" {
		events := &proto.BatchEvent{}
		assert.NoError(w.ledger.t, pb.Unmarshal(e.Payload, events))
		for _, e := range events.Events {
			if hex.EncodeToString(e.Id) == txID {
				events := make(map[string][]byte)
				for _, e := range e.Events {
					events[e.Name] = e.Value
				}
				err := ""
				if e.Error != nil {
					err = e.Error.Error
				}
				return txID, TxResponse{
					Method: e.Method,
					Error:  err,
					Result: string(e.Result),
					Events: events,
				}, out.CreatedSwaps, out.CreatedMultiSwap
			}
		}
	}
	assert.Fail(w.ledger.t, "shouldn't be here")
	return txID, TxResponse{}, out.CreatedSwaps, out.CreatedMultiSwap
}

func (w *wallet) RawSignedInvokeWithErrorReturned(ch string, fn string, args ...string) error {
	txID := txIDGen()
	args, _ = w.sign(fn, ch, args...)
	cert, err := base64.StdEncoding.DecodeString(userCert)
	assert.NoError(w.ledger.t, err)
	w.ledger.stubs[ch].SetCreatorCert("atomyzeMSP", cert)
	err = w.ledger.doInvokeWithErrorReturned(ch, txID, fn, args...)
	if err != nil {
		return err
	}

	id, err := hex.DecodeString(txID)
	if err != nil {
		return err
	}
	data, err := pb.Marshal(&proto.Batch{TxIDs: [][]byte{id}})
	if err != nil {
		return err
	}

	cert, err = hex.DecodeString(batchRobotCert)
	if err != nil {
		return err
	}
	w.ledger.stubs[ch].SetCreator(cert)
	res := w.Invoke(ch, "batchExecute", string(data))
	out := &proto.BatchResponse{}
	err = pb.Unmarshal([]byte(res), out)
	if err != nil {
		return err
	}

	e := <-w.ledger.stubs[ch].ChaincodeEventsChannel
	if e.EventName == "batchExecute" {
		events := &proto.BatchEvent{}
		err = pb.Unmarshal(e.Payload, events)
		if err != nil {
			return err
		}
		for _, e := range events.Events {
			if hex.EncodeToString(e.Id) == txID {
				events := make(map[string][]byte)
				for _, e := range e.Events {
					events[e.Name] = e.Value
				}
				if e.Error != nil {
					return errors.New(e.Error.Error)
				}
				return nil
			}
		}
	}
	assert.Fail(w.ledger.t, "shouldn't be here")
	return nil
}

func (w *wallet) SignedInvoke(ch string, fn string, args ...string) string {
	txID, res, swaps := w.RawSignedInvoke(ch, fn, args...)
	assert.Equal(w.ledger.t, "", res.Error)
	for _, swap := range swaps {
		x := proto.Batch{Swaps: []*proto.Swap{{
			Id:      swap.Id,
			Creator: []byte("0000"),
			Owner:   swap.Owner,
			Token:   swap.Token,
			Amount:  swap.Amount,
			From:    swap.From,
			To:      swap.To,
			Hash:    swap.Hash,
			Timeout: swap.Timeout,
		}}}
		data, err := pb.Marshal(&x)
		assert.NoError(w.ledger.t, err)
		cert, err := hex.DecodeString(batchRobotCert)
		assert.NoError(w.ledger.t, err)
		w.ledger.stubs[strings.ToLower(swap.To)].SetCreator(cert)
		w.Invoke(strings.ToLower(swap.To), "batchExecute", string(data))
	}
	return txID
}

func (w *wallet) SignedMultiSwapsInvoke(ch string, fn string, args ...string) string {
	txID, res, _, multiSwaps := w.RawSignedMultiSwapInvoke(ch, fn, args...)
	assert.Equal(w.ledger.t, "", res.Error)
	for _, swap := range multiSwaps {
		x := proto.Batch{
			MultiSwaps: []*proto.MultiSwap{
				{
					Id:      swap.Id,
					Creator: []byte("0000"),
					Owner:   swap.Owner,
					Token:   swap.Token,
					Assets:  swap.Assets,
					From:    swap.From,
					To:      swap.To,
					Hash:    swap.Hash,
					Timeout: swap.Timeout,
				},
			},
		}
		data, err := pb.Marshal(&x)
		assert.NoError(w.ledger.t, err)
		cert, err := hex.DecodeString(batchRobotCert)
		assert.NoError(w.ledger.t, err)
		w.ledger.stubs[swap.To].SetCreator(cert)
		w.Invoke(swap.To, "batchExecute", string(data))
	}
	return txID
}

func (w *wallet) OtfNbInvoke(ch string, fn string, args ...string) (string, string) {
	txID := txIDGen()
	message, hash := w.sign(fn, ch, args...)
	cert, err := base64.StdEncoding.DecodeString(userCert)
	assert.NoError(w.ledger.t, err)
	w.ledger.stubs[ch].SetCreatorCert("atomyzeMSP", cert)
	w.ledger.doInvoke(ch, txID, fn, message...)

	nested, err := pb.Marshal(&proto.Nested{Args: append([]string{fn}, message...)})
	assert.NoError(w.ledger.t, err)

	return base58.Encode(nested), hash
}

func GetCert(t *testing.T, certpath string) *x509.Certificate {
	cert, err := ioutil.ReadFile(certpath)
	assert.NoError(t, err)
	pcert, _ := pem.Decode(cert)
	parsed, err := x509.ParseCertificate(pcert.Bytes)
	assert.NoError(t, err)
	return parsed
}
