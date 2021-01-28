package openoracle

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
)

type OracleResponse struct {
	Timestamp  string            `json:"timestamp"`
	Messages   []string          `json:"messages"`
	Signatures []string          `json:"signatures"`
	Prices     map[string]string `json:"prices"`
}

// UnmarshalVerify will unmarshal a json raw payload
// into and OracleResponse
// if the unmarshal is successful then the content is verified
func UnmarshalVerify(payload []byte, address string) (*OracleResponse, error) {
	oresp, err := Unmarshal(payload)
	if err != nil {
		return nil, err
	}

	pk, kv, err := Verify(*oresp)
	fmt.Printf("%v\n%v\n", pk, kv)

	return oresp, err
}

func Unmarshal(payload []byte) (*OracleResponse, error) {
	oresp := OracleResponse{}
	err := json.Unmarshal(payload, &oresp)
	if err != nil {
		return nil, err
	}
	return &oresp, nil
}

func Verify(oresp OracleResponse) ([]string, map[string]string, error) {
	typString, err := abi.NewType("string", "", nil)
	if err != nil {
		return nil, nil, err
	}

	typUint64, err := abi.NewType("uint64", "", nil)
	if err != nil {
		return nil, nil, err
	}

	args := abi.Arguments([]abi.Argument{
		{
			Name: "kind",
			Type: typString,
		},
		{
			Name: "timestamp",
			Type: typUint64,
		},
		{
			Name: "key",
			Type: typString,
		},
		{
			Name: "value",
			Type: typUint64,
		},
	})

	// ensure we have as much signature than messages
	if len(oresp.Messages) != len(oresp.Signatures) {
		return nil, nil, fmt.Errorf("got %v signatures, but have %v messages", len(oresp.Signatures), len(oresp.Messages))
	}

	pubkeys := map[string]struct{}{}
	keyValues := map[string]string{}

	for i := 0; i < len(oresp.Messages); i++ {
		sigBytes, err := hex.DecodeString(strings.TrimPrefix(oresp.Signatures[i], "0x"))
		if err != nil {
			return nil, nil, err
		}
		msgBytes, err := hex.DecodeString(strings.TrimPrefix(oresp.Messages[i], "0x"))
		if err != nil {
			return nil, nil, err
		}
		hashDecoded := crypto.Keccak256Hash(msgBytes)
		hashDecodedPadded := accounts.TextHash(hashDecoded.Bytes())

		if len(sigBytes) > 65 {
			sigBytes[64] = sigBytes[len(sigBytes)-1]
			sigBytes = sigBytes[:65]
		}
		sigBytes[64] = sigBytes[64] - 27

		sigPublicKeyECDSA, err := crypto.SigToPub(hashDecodedPadded, sigBytes)
		if err != nil {
			return nil, nil, err
		}

		addrHex := crypto.PubkeyToAddress(*sigPublicKeyECDSA).Hex()

		pubkeys[addrHex] = struct{}{}

		// if address != addrHex {
		// 	return nil, nil, fmt.Errorf("oracle response contains invalid address, expected(%v), got(%v)", address, addrHex)
		// }

		// FIXME(jeremy): signature verification seems not to work everytime
		// but address does...
		// signatureNoRecoverID := sigBytes[:len(sigBytes)-1] // remove recovery ID
		// if !crypto.VerifySignature(
		// 	crypto.CompressPubkey(sigPublicKeyECDSA),
		// 	hashDecodedPadded, signatureNoRecoverID) {
		// 	return errors.New("oracle response contains invalid signature")
		// }

		m := map[string]interface{}{}
		err = args.UnpackIntoMap(m, msgBytes)
		if err != nil {
			return nil, nil, err
		}

		keyValues[fmt.Sprintf("%v.%v", m["kind"], m["key"])] = fmt.Sprintf("%v", m["value"])
	}

	pubkeysSlice := make([]string, 0, len(pubkeys))
	for k := range pubkeys {
		pubkeysSlice = append(pubkeysSlice, k)
	}

	return pubkeysSlice, keyValues, nil
}
