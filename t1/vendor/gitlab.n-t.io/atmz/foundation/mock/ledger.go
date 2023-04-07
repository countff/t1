package mock

import (
	"bytes"
	"encoding/base64"
	//"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	pb "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-protos-go/msp"
	"sort"

	"gitlab.n-t.io/atmz/foundation/golang-math-big"
	//"gitlab.n-t.io/atmz/newity-infra/chaincode/acl/cc"
	"golang.org/x/crypto/sha3"
	//"sort"
	//"strconv"
	//"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gitlab.n-t.io/atmz/foundation/core"
	"gitlab.n-t.io/atmz/foundation/proto"

	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
)

const defaultCert = `MIICSjCCAfGgAwIBAgIRAKeZTS2c/qkXBN0Vkh+0WYQwCgYIKoZIzj0EAwIwgYcx
CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4g
RnJhbmNpc2NvMSMwIQYDVQQKExphdG9teXplLnVhdC5kbHQuYXRvbXl6ZS5jaDEm
MCQGA1UEAxMdY2EuYXRvbXl6ZS51YXQuZGx0LmF0b215emUuY2gwHhcNMjAxMDEz
MDg1NjAwWhcNMzAxMDExMDg1NjAwWjB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
Q2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEPMA0GA1UECxMGY2xp
ZW50MSowKAYDVQQDDCFVc2VyMTBAYXRvbXl6ZS51YXQuZGx0LmF0b215emUuY2gw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR3V6z/nVq66HBDxFFN3/3rUaJLvHgW
FzoKaA/qZQyV919gdKr82LDy8N2kAYpAcP7dMyxMmmGOPbo53locYWIyo00wSzAO
BgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADArBgNVHSMEJDAigCBSv0ueZaB3
qWu/AwOtbOjaLd68woAqAklfKKhfu10K+DAKBggqhkjOPQQDAgNHADBEAiBFB6RK
O7huI84Dy3fXeA324ezuqpJJkfQOJWkbHjL+pQIgFKIqBJrDl37uXNd3eRGJTL+o
21ZL8pGXH8h0nHjOF9M=`

const adminCert = `MIICSDCCAe6gAwIBAgIQAJwYy5PJAYSC1i0UgVN5bjAKBggqhkjOPQQDAjCBhzEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG
cmFuY2lzY28xIzAhBgNVBAoTGmF0b215emUudWF0LmRsdC5hdG9teXplLmNoMSYw
JAYDVQQDEx1jYS5hdG9teXplLnVhdC5kbHQuYXRvbXl6ZS5jaDAeFw0yMDEwMTMw
ODU2MDBaFw0zMDEwMTEwODU2MDBaMHUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpD
YWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ4wDAYDVQQLEwVhZG1p
bjEpMCcGA1UEAwwgQWRtaW5AYXRvbXl6ZS51YXQuZGx0LmF0b215emUuY2gwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGQX9IhgjCtd3mYZ9DUszmUgvubepVMPD5
FlwjCglB2SiWuE2rT/T5tHJsU/Y9ZXFtOOpy/g9tQ/0wxDWwpkbro00wSzAOBgNV
HQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADArBgNVHSMEJDAigCBSv0ueZaB3qWu/
AwOtbOjaLd68woAqAklfKKhfu10K+DAKBggqhkjOPQQDAgNIADBFAiEAoKRQLe4U
FfAAwQs3RCWpevOPq+J8T4KEsYvswKjzfJYCIAs2kOmN/AsVUF63unXJY0k9ktfD
fAaqNRaboY1Yg1iQ`

type ledger struct {
	t                   *testing.T
	stubs               map[string]*MockStub
	keyEvents           map[string]chan *peer.ChaincodeEvent
	txResponseEvents    map[string]chan TxResponse
	txResponseEventLock *sync.Mutex
}

func (ledger ledger) GetStubByKey(key string) *MockStub {
	return ledger.stubs[key]
}

func (ledger ledger) UpdateStubTxID(stubName string, newTxID string) {
	ledger.stubs[stubName].TxID = newTxID
}

func NewLedger(t *testing.T) *ledger {
	time.Local = time.UTC
	lvl := logrus.ErrorLevel
	var err error
	if level, ok := os.LookupEnv("LOG"); ok {
		lvl, err = logrus.ParseLevel(level)
		assert.NoError(t, err)
	}
	logrus.SetLevel(lvl)
	logrus.SetFormatter(&logrus.JSONFormatter{})

	aclStub := NewMockStub("acl", new(mockACL))
	assert.Equal(t, int32(200), aclStub.MockInit(hex.EncodeToString([]byte("acl")), nil).Status)

	return &ledger{
		t:                   t,
		stubs:               map[string]*MockStub{"acl": aclStub},
		keyEvents:           make(map[string]chan *peer.ChaincodeEvent),
		txResponseEvents:    make(map[string]chan TxResponse),
		txResponseEventLock: &sync.Mutex{},
	}
}

func (ledger *ledger) SetAcl(aclStub *MockStub) {
	ledger.stubs["acl"] = aclStub
}

type TxResponse struct {
	Method     string                    `json:"method"`
	Error      string                    `json:"error,omitempty"`
	Result     string                    `json:"result"`
	Events     map[string][]byte         `json:"events,omitempty"`
	Accounting []*proto.AccountingRecord `json:"accounting"`
}

const batchRobotCertHash = "380499dcb3d3ee374ccfd74cbdcbe03a1cd5ae66b282e5673dcb13cbe290965b"

func (ledger *ledger) NewChainCode(name string, bci core.BaseContractInterface, options *core.ContractOptions, initArgs ...string) {
	_, exists := ledger.stubs[name]
	assert.False(ledger.t, exists)
	cc, err := core.NewChainCode(bci, "atomyzeMSP", options)
	assert.NoError(ledger.t, err)
	ledger.stubs[name] = NewMockStub(name, cc)
	ledger.stubs[name].ChannelID = name
	ledger.stubs[name].MockPeerChaincode("acl/acl", ledger.stubs["acl"])
	args := [][]byte{[]byte(""), []byte(batchRobotCertHash)}
	for _, arg := range initArgs {
		args = append(args, []byte(arg))
	}
	cert, err := base64.StdEncoding.DecodeString(adminCert)
	assert.NoError(ledger.t, err)
	ledger.stubs[name].SetCreatorCert("atomyzeMSP", cert)
	ledger.stubs[name].MockInit(txIDGen(), args)
	ledger.keyEvents[name] = make(chan *peer.ChaincodeEvent, 1)
}

func (ledger *ledger) GetStub(name string) *MockStub {
	return ledger.stubs[name]
}

func (ledger *ledger) WaitMultiSwapAnswer(name string, id string, timeout time.Duration) {
	interval := time.Second / 2
	ticker := time.NewTicker(interval)
	count := timeout.Microseconds() / interval.Microseconds()
	key, err := ledger.stubs[name].CreateCompositeKey(core.MultiSwapCompositeType, []string{id})
	assert.NoError(ledger.t, err)
	for count > 0 {
		count--
		<-ticker.C
		if _, exists := ledger.stubs[name].State[key]; exists {
			return
		}
	}
	for k, v := range ledger.stubs[name].State {
		fmt.Println(k, string(v))
	}
	assert.Fail(ledger.t, "timeout exceeded")
}

func (ledger *ledger) WaitSwapAnswer(name string, id string, timeout time.Duration) {
	interval := time.Second / 2
	ticker := time.NewTicker(interval)
	count := timeout.Microseconds() / interval.Microseconds()
	key, err := ledger.stubs[name].CreateCompositeKey("swaps", []string{id})
	assert.NoError(ledger.t, err)
	for count > 0 {
		count--
		<-ticker.C
		if _, exists := ledger.stubs[name].State[key]; exists {
			return
		}
	}
	for k, v := range ledger.stubs[name].State {
		fmt.Println(k, string(v))
	}
	assert.Fail(ledger.t, "timeout exceeded")
}

func (ledger *ledger) NewWallet() *wallet {
	pKey, sKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(ledger.t, err)
	hash := sha3.Sum256(pKey)
	return &wallet{ledger: ledger, sKey: sKey, pKey: pKey, addr: base58.CheckEncode(hash[1:], hash[0])}
}

func (ledger *ledger) NewMultisigWallet(n int) *multisig {
	wlt := &multisig{wallet: wallet{ledger: ledger}}
	for i := 0; i < n; i++ {
		pKey, sKey, err := ed25519.GenerateKey(rand.Reader)
		assert.NoError(ledger.t, err)
		wlt.pKeys = append(wlt.pKeys, pKey)
		wlt.sKeys = append(wlt.sKeys, sKey)
	}

	binPubKeys := make([][]byte, len(wlt.pKeys))
	for i, k := range wlt.pKeys {
		binPubKeys[i] = k
	}
	sort.Slice(binPubKeys, func(i, j int) bool {
		return bytes.Compare(binPubKeys[i], binPubKeys[j]) < 0
	})

	hashedAddr := sha3.Sum256(bytes.Join(binPubKeys, []byte("")))
	wlt.addr = base58.CheckEncode(hashedAddr[1:], hashedAddr[0])
	return wlt
}

func (ledger *ledger) NewWalletFromKey(key string) *wallet {
	decoded, ver, err := base58.CheckDecode(key)
	assert.NoError(ledger.t, err)
	sKey := ed25519.PrivateKey(append([]byte{ver}, decoded...))
	hash := sha3.Sum256(sKey.Public().(ed25519.PublicKey))
	return &wallet{ledger: ledger, sKey: sKey, pKey: sKey.Public().(ed25519.PublicKey), addr: base58.CheckEncode(hash[1:], hash[0])}
}

func (ledger *ledger) NewWalletFromHexKey(key string) *wallet {
	decoded, err := hex.DecodeString(key)
	assert.NoError(ledger.t, err)
	sKey := ed25519.PrivateKey(decoded)
	hash := sha3.Sum256(sKey.Public().(ed25519.PublicKey))
	return &wallet{ledger: ledger, sKey: sKey, pKey: sKey.Public().(ed25519.PublicKey), addr: base58.CheckEncode(hash[1:], hash[0])}
}

func (ledger *ledger) doInvoke(ch string, txID string, fn string, args ...string) string {
	vArgs := make([][]byte, len(args)+1)
	vArgs[0] = []byte(fn)
	for i, x := range args {
		vArgs[i+1] = []byte(x)
	}

	if len(ledger.stubs[ch].creator) == 0 {
		cert, err := base64.StdEncoding.DecodeString(defaultCert)
		assert.NoError(ledger.t, err)
		ledger.stubs[ch].SetCreatorCert("atomyzeMSP", cert)
	}

	input, err := pb.Marshal(&peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			ChaincodeId: &peer.ChaincodeID{Name: ch},
			Input:       &peer.ChaincodeInput{Args: vArgs},
		},
	})
	assert.NoError(ledger.t, err)
	payload, err := pb.Marshal(&peer.ChaincodeProposalPayload{Input: input})
	assert.NoError(ledger.t, err)
	proposal, err := pb.Marshal(&peer.Proposal{Payload: payload})
	result := ledger.stubs[ch].MockInvokeWithSignedProposal(txID, vArgs, &peer.SignedProposal{
		ProposalBytes: proposal,
	})
	assert.Equal(ledger.t, int32(200), result.Status, result.Message)
	return string(result.Payload)
}

func (ledger *ledger) doInvokeWithErrorReturned(ch string, txID string, fn string, args ...string) error {
	vArgs := make([][]byte, len(args)+1)
	vArgs[0] = []byte(fn)
	for i, x := range args {
		vArgs[i+1] = []byte(x)
	}

	if len(ledger.stubs[ch].creator) == 0 {
		cert, err := base64.StdEncoding.DecodeString(defaultCert)
		assert.NoError(ledger.t, err)
		ledger.stubs[ch].SetCreatorCert("atomyzeMSP", cert)
	}

	input, err := pb.Marshal(&peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			ChaincodeId: &peer.ChaincodeID{Name: ch},
			Input:       &peer.ChaincodeInput{Args: vArgs},
		},
	})
	assert.NoError(ledger.t, err)
	payload, err := pb.Marshal(&peer.ChaincodeProposalPayload{Input: input})
	assert.NoError(ledger.t, err)
	proposal, err := pb.Marshal(&peer.Proposal{Payload: payload})
	result := ledger.stubs[ch].MockInvokeWithSignedProposal(txID, vArgs, &peer.SignedProposal{
		ProposalBytes: proposal,
	})
	if result.Status != 200 {
		return errors.New(result.Message)
	}
	return nil
}

type metadata struct {
	Name            string         `json:"name"`
	Symbol          string         `json:"symbol"`
	Decimals        uint           `json:"decimals"`
	UnderlyingAsset string         `json:"underlyingAsset"`
	Issuer          string         `json:"issuer"`
	Methods         []string       `json:"methods"`
	TotalEmission   *big.Int       `json:"total_emission"`
	Fee             fee            `json:"fee"`
	Rates           []metadataRate `json:"rates"`
}

type industrialMetadata struct {
	Name            string          `json:"name"`
	Symbol          string          `json:"symbol"`
	Decimals        uint            `json:"decimals"`
	UnderlyingAsset string          `json:"underlying_asset"`
	DeliveryForm    string          `json:"deliveryForm"`
	UnitOfMeasure   string          `json:"unitOfMeasure"`
	TokensForUnit   string          `json:"tokensForUnit"`
	PaymentTerms    string          `json:"paymentTerms"`
	Price           string          `json:"price"`
	Issuer          string          `json:"issuer"`
	Methods         []string        `json:"methods"`
	Groups          []MetadataGroup `json:"groups"`
	Fee             fee             `json:"fee"`
	Rates           []metadataRate  `json:"rates"`
}

type fee struct {
	Currency string   `json:"currency"`
	Fee      *big.Int `json:"fee"`
	Floor    *big.Int `json:"floor"`
	Cap      *big.Int `json:"cap"`
}

// MetadataGroup struct
type MetadataGroup struct {
	Name         string    `json:"name"`
	Amount       *big.Int  `json:"amount"`
	MaturityDate time.Time `json:"maturityDate"`
	Note         string    `json:"note"`
}

type metadataRate struct {
	DealType string   `json:"deal_type"`
	Currency string   `json:"currency"`
	Rate     *big.Int `json:"rate"`
	Min      *big.Int `json:"min"`
	Max      *big.Int `json:"max"`
}

func (ledger *ledger) Metadata(ch string) (out metadata) {
	resp := ledger.doInvoke(ch, txIDGen(), "metadata")
	fmt.Println(resp)
	err := json.Unmarshal([]byte(resp), &out)
	assert.NoError(ledger.t, err)
	return
}

// IndustrialMetadata returns metadata for industrial token
func (ledger *ledger) IndustrialMetadata(ch string) (out industrialMetadata) {
	resp := ledger.doInvoke(ch, txIDGen(), "metadata")
	fmt.Println(resp)
	err := json.Unmarshal([]byte(resp), &out)
	assert.NoError(ledger.t, err)

	return
}

func (m metadata) MethodExists(method string) bool {
	for _, mm := range m.Methods {
		if mm == method {
			return true
		}
	}
	return false
}

func txIDGen() string {
	txID := [16]byte(uuid.New())
	return hex.EncodeToString(txID[:])
}

func SetCreator(stub *shimtest.MockStub, creatorMSP string, creatorCert []byte) error {
	pemblock := &pem.Block{Type: "CERTIFICATE", Bytes: creatorCert}
	pemBytes := pem.EncodeToMemory(pemblock)
	if pemBytes == nil {
		return errors.New("encoding of identity failed")
	}

	creator := &msp.SerializedIdentity{Mspid: creatorMSP, IdBytes: pemBytes}
	marshaledIdentity, err := pb.Marshal(creator)
	if err != nil {
		return err
	}
	stub.Creator = marshaledIdentity
	return nil
}
