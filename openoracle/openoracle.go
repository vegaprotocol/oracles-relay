package openoracle

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
)

// The open oracle payload.
// every messages contain the prices and a timestamps abi encoded.
// A valid payload will contain a valid signature for every message bundles.
// or every entry in the Message array, an corresponding signature must be
// available at the same position in the Signatures array.
// e.g:
// - Message[0] -> Signatures[0]
// - Message[n] -> Signatures[n]
//
// The ABI encode message, contains the following values:
// - "kind", of type string, here always `prices`
// - "timestamp", of type uint64, which is the time at which this specific price was emitted
// - "key", of type string, which here is always a asset name (e.g: BTC, ETH, VEGA)
// - "value", of type uint256, always as price.
//
// Decoding the message can be found in the Verify function below.
type OracleResponse struct {
	// the timestamp at which this payload was emitted
	Timestamp string `json:"timestamp"`
	// a list of ABI encoded message containing the price feeds
	Messages []string `json:"messages"`
	// the matching signatures for the list of messages contains the price feeds
	Signatures []string `json:"signatures"`
	// An option decoded map of asset -> price
	Prices map[string]string `json:"prices"`
}

// An oracle price input
type OraclePrice struct {
	// The asset which is priced
	Asset string
	// The asset value, a string reprenting an unsigned integer.
	Price string
	// The timestamp at which this specific price was valid
	Timestamp uint64
}

// A request to build an open oracle payload
type OracleRequest struct {
	// The Timestamp at which this payload is valid
	Timestamp uint64 `json:"timestamp"`
	// The list of price to bundle
	Prices []OraclePrice `json:"oracle_prices"`
}

func (oreq *OracleRequest) IntoOpenOracle(privKey *ecdsa.PrivateKey) (*OracleResponse, error) {
	oresp := OracleResponse{
		Timestamp:  fmt.Sprintf("%d", oreq.Timestamp),
		Messages:   make([]string, 0, len(oreq.Prices)),
		Signatures: make([]string, 0, len(oreq.Prices)),
	}

	for _, v := range oreq.Prices {
		price, _ := big.NewInt(0).SetString(v.Price, 10)

		msgBytes, err := makeMessage(
			"prices", v.Asset, v.Timestamp, price,
		)
		if err != nil {
			return nil, err
		}

		sigBytes, err := signMessage(msgBytes, privKey)
		if err != nil {
			return nil, err
		}

		oresp.Messages = append(oresp.Messages, "0x"+hex.EncodeToString(msgBytes))
		oresp.Signatures = append(oresp.Signatures, "0x"+hex.EncodeToString(sigBytes))
	}

	return &oresp, nil
}

func signMessage(msgBytes []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	hashBytes := crypto.Keccak256Hash(msgBytes)
	hashBytesPadded := accounts.TextHash(hashBytes.Bytes())

	signature, err := crypto.Sign(hashBytesPadded, privKey)
	if err != nil {
		return nil, err
	}

	signature[64] = signature[64] + 27

	return signature, nil
}

func makeMessage(
	kind string,
	key string,
	timestamp uint64,
	value *big.Int,
) ([]byte, error) {
	typString, err := abi.NewType("string", "", nil)
	if err != nil {
		return nil, err
	}

	typUint64, err := abi.NewType("uint64", "", nil)
	if err != nil {
		return nil, err
	}

	typUint256, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, err
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
			Type: typUint256,
		},
	})

	bytes, err := args.Pack([]interface{}{
		kind, timestamp, key, value,
	}...)
	if err != nil {
		return nil, err
	}

	return bytes, err
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

	typUint256, err := abi.NewType("uint256", "", nil)
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
			Type: typUint256,
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

		m := map[string]interface{}{}
		err = args.UnpackIntoMap(m, msgBytes)
		if err != nil {
			return nil, nil, err
		}

		keyValues[fmt.Sprintf("%v.%v.value", m["kind"], m["key"])] = fmt.Sprintf("%v", m["value"])
		keyValues[fmt.Sprintf("%v.%v.timestamp", m["kind"], m["key"])] = fmt.Sprintf("%v", m["timestamp"])
	}

	pubkeysSlice := make([]string, 0, len(pubkeys))
	for k := range pubkeys {
		pubkeysSlice = append(pubkeysSlice, k)
	}

	return pubkeysSlice, keyValues, nil
}
