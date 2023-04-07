package core

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/pkg/errors"
	"gitlab.n-t.io/atmz/foundation/core/helpers"
	"gitlab.n-t.io/atmz/foundation/core/types"
	"gitlab.n-t.io/atmz/foundation/golang-math-big"
	pb "gitlab.n-t.io/atmz/foundation/proto"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
	"strings"
)

func CheckSign(stub shim.ChaincodeStubInterface, fn string, args []string, auth []string) (types.Address, string, error) {
	signers := len(auth) / 2
	if signers == 0 {
		return types.Address{}, "", errors.New("should be signed")
	}
	keys := make([][]byte, 0, signers)
	message := sha3.Sum256([]byte(fn + strings.Join(append(args, auth[:signers]...), "")))
	for i := 0; i < signers; i++ {
		key := base58.Decode(auth[i])
		sign := base58.Decode(auth[i+signers])
		if !ed25519.Verify(key, message[:], sign) {
			return types.Address{}, "", errors.New("incorrect signature")
		}
		keys = append(keys, key)
	}

	acl, err := helpers.CheckACL(stub, auth[:signers])
	if err != nil {
		return types.Address{}, "", err
	}

	if acl.Account != nil && acl.Account.GrayListed {
		return types.Address{}, "", fmt.Errorf("address %s is graylisted", types.Address(*acl.Address.Address).String())
	}

	return types.Address(*acl.Address.Address), hex.EncodeToString(message[:]), nil
}

func checkAuthIfNeeds(stub shim.ChaincodeStubInterface, method *fn, fn string, args []string, check bool) ([]string, error) {
	if !method.needsAuth {
		return args, nil
	}
	total := len(args)
	argLen := len(method.in)
	noncePos := argLen + 3 - 1 // + channel's + chaincode's names,  -1 because first arg is sender
	authPos := noncePos + 1

	//            - sender + channel + chaincode + nonce + pk + sign = 4
	if total < argLen+4 {
		return nil, errors.New("incorrect number of arguments")
	}

	spr, err := stub.GetSignedProposal()
	if err != nil {
		return nil, err
	}
	proposal := &peer.Proposal{}
	if err := proto.Unmarshal(spr.ProposalBytes, proposal); err != nil {
		return nil, err
	}
	payload := &peer.ChaincodeProposalPayload{}
	if err := proto.Unmarshal(proposal.Payload, payload); err != nil {
		return nil, err
	}
	input := &peer.ChaincodeInvocationSpec{}
	if err := proto.Unmarshal(payload.Input, input); err != nil {
		return nil, err
	}

	// args[0] is request id

	if input.ChaincodeSpec == nil || input.ChaincodeSpec.ChaincodeId == nil ||
		args[1] != input.ChaincodeSpec.ChaincodeId.Name {
		return nil, errors.New("incorrect chaincode")
	}

	if args[2] != stub.GetChannelID() {
		return nil, errors.New("incorrect channel")
	}

	if (total-(argLen+3))%2 != 0 {
		return nil, errors.New("incorrect number of keys or signs")
	}

	signers := (total - authPos) / 2
	if signers == 0 {
		return nil, errors.New("should be signed")
	}
	keys := make([][]byte, 0, signers)
	message := sha3.Sum256([]byte(fn + strings.Join(args[:len(args)-signers], "")))

	acl, err := helpers.CheckACL(stub, args[authPos:authPos+signers])
	if err != nil {
		return nil, err
	}
	N := 1 // for single sign
	if signers > 1 {
		if acl.Address != nil && acl.Address.SignaturePolicy != nil {
			N = int(acl.Address.SignaturePolicy.N)
		} else {
			N = signers // если нет в acl такого, подписать должны все
		}
	}

	for i := authPos; i < authPos+signers; i++ {
		if args[i+signers] == "" {
			continue
		}
		key := base58.Decode(args[i])
		sign := base58.Decode(args[i+signers])
		if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message[:], sign) {
			return nil, errors.New("incorrect signature")
		}
		keys = append(keys, key)
		N--
	}

	if N > 0 {
		return nil, errors.New("signature policy isn't satisfied")
	}

	//acl, err := checkACL(stub, args[authPos:authPos+signers])
	//if err != nil {
	//	return nil, err
	//}

	if acl.Account != nil && acl.Account.BlackListed {
		return nil, fmt.Errorf("address %s is blacklisted", types.Address(*acl.Address.Address).String())
	}
	if acl.Account != nil && acl.Account.GrayListed {
		return nil, fmt.Errorf("address %s is graylisted", types.Address(*acl.Address.Address).String())
	}

	if err = helpers.AddAddrIfChanged(stub, acl.Address); err != nil {
		return nil, err
	}

	if err := checkNonce(stub, types.Address(*acl.Address.Address), args[noncePos]); err != nil {
			return nil, err
		}

	addr, err := proto.Marshal(acl.Address.Address)
	if err != nil {
		return nil, err
	}

	addrStr := base64.StdEncoding.EncodeToString(addr)
	return append([]string{addrStr}, args[3:]...), nil
}

func CheckNOutOfM(message []byte, addrMsgFromAcl *pb.SignedAddress, keysAndSignatures []string) error {
	pkeys := keysAndSignatures[:len(keysAndSignatures)/2]
	signatures := keysAndSignatures[len(keysAndSignatures)/2:]

	var signMatches uint32 = 0
	for i, pk := range pkeys {
		// check that this public key really belongs to one of the multisig wallet owners
		if !Contains(addrMsgFromAcl.SignaturePolicy.PubKeys, base58.Decode(pk)) {
			return errors.Errorf("public key %s does not belong to multisig wallet owners", pk)
		}

		// check signatures
		decodedSignature, err := hex.DecodeString(signatures[i])
		if err != nil {
			return err
		}
		if !ed25519.Verify(base58.Decode(pk), message, decodedSignature) {
			return errors.Errorf("the signature %s does not match the public key %s", signatures[i], pk)
		}
		signMatches++
	}

	// check that there are enough signatures
	if signMatches < addrMsgFromAcl.SignaturePolicy.N {
		return errors.Errorf("signature policy violation, multisig wallet requires %d valid signatures, got only %d", addrMsgFromAcl.SignaturePolicy.N, signMatches)
	}

	return nil
}

func checkNonce(stub shim.ChaincodeStubInterface, sender types.Address, nonceStr string) error {
	prefix := hex.EncodeToString([]byte{byte(StateKeyNonce)})
	key, err := stub.CreateCompositeKey(prefix, []string{sender.String()})
	if err != nil {
		return err
	}

	nonce, ok := new(big.Int).SetString(nonceStr, 10)
	if !ok {
		return errors.New("incorrect nonce")
	}
	data, err := stub.GetState(key)
	if err != nil {
		return err
	}
	existed := new(big.Int).SetBytes(data)
	if existed.Cmp(nonce) >= 0 {
		return fmt.Errorf("incorrect nonce, current %s", existed.String())
	}
	return stub.PutState(key, nonce.Bytes())
}

func Contains(arr [][]byte, item []byte) bool {
	for _, elem := range arr {
		if bytes.Equal(elem, item) {
			return true
		}
	}
	return false
}
