package mock

import (
	"crypto/ed25519"
	"encoding/hex"
	"github.com/btcsuite/btcutil/base58"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"gitlab.n-t.io/atmz/foundation/core/types"
	"gitlab.n-t.io/atmz/foundation/proto"
	"golang.org/x/crypto/sha3"
	"strconv"
	"strings"
	"time"

	pb "github.com/golang/protobuf/proto"
)

type multisig struct {
	wallet
	pKeys []ed25519.PublicKey
	sKeys []ed25519.PrivateKey
}

func (w *multisig) Address() string {
	return w.addr
}

/*func (w *multisig) Invoke(ch string, fn string, args ...string) string {
	return w.ledger.doInvoke(ch, txIDGen(), fn, args...)
}

func (w *multisig) Pks() []ed25519.PublicKey {
	return w.pKeys
}

func (w *multisig) SecretKeys() []ed25519.PrivateKey {
	return w.sKeys
}

*/func (w *multisig) AddressType() types.Address {
	value, ver, err := base58.CheckDecode(w.addr)
	if err != nil {
		panic(err)
	}
	return types.Address{Address: append([]byte{ver}, value...)[:32]}
}

// ChangeKeysFor changes private and public keys for multisig member with specific index
func (w *multisig) ChangeKeysFor(index int, sKey ed25519.PrivateKey) error {
	w.sKeys[index] = sKey
	var ok bool
	w.pKeys[index], ok = sKey.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("failed to derive public key from secret")
	}

	return nil
}

func (w *multisig) sign(signCnt int, fn string, ch string, args ...string) ([]string, string) {
	time.Sleep(time.Millisecond * 5)
	nonce := strconv.FormatInt(time.Now().UnixNano() / 1000000, 10)
	result := append(append([]string{fn, "", ch, ch}, args...), nonce)
	for _, pk := range w.pKeys {
		result = append(result, base58.Encode(pk))
	}
	message := sha3.Sum256([]byte(strings.Join(result, "")))
	for _, skey := range w.sKeys {
		if signCnt > 0 {
			result = append(result, base58.Encode(ed25519.Sign(skey, message[:])))
		} else {
			result = append(result, "")
		}
		signCnt--
	}

	return result[1:], hex.EncodeToString(message[:])
}

func (w *multisig) RawSignedInvoke(signCnt int, ch string, fn string, args ...string) (string, TxResponse, []*proto.Swap) {
	txID := txIDGen()
	args, _ = w.sign(signCnt, fn, ch, args...)
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
				}, out.CreatedSwaps
			}
		}
	}
	assert.Fail(w.ledger.t, "shouldn't be here")
	return txID, TxResponse{}, out.CreatedSwaps
}

func (w *multisig) SecretKeys() []ed25519.PrivateKey {
	return w.sKeys
}

func (w *multisig) PubKeys() []ed25519.PublicKey {
	return w.pKeys
}

/*
func (w *multisig) RawSignedInvoke(ch string, fn string, args ...string) (string, TxResponse, []*proto.Swap) {
	txID := txIDGen()
	args, _ = w.sign(fn, args...)
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
				}, out.CreatedSwaps
			}
		}
	}
	assert.Fail(w.ledger.t, "shouldn't be here")
	return txID, TxResponse{}, out.CreatedSwaps
}

func (w *multisig) SignedInvoke(ch string, fn string, args ...string) string {
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
*/
