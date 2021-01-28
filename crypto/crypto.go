package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	addrRegex = regexp.MustCompile("^0x[0-9a-fA-F]{40}$")
)

// VerifySignature will verify a signature and if the signature is
// valid will return the address which emited the signature and no error
func VerifySignature(msg, sig []byte) (common.Address, error) {
	h := Hash(msg)
	pubkey, err := crypto.SigToPub(h, sig)
	if err != nil {
		return common.Address{}, err
	}
	sigNoID := sig[:len(sig)-1]
	if !crypto.VerifySignature(crypto.CompressPubkey(pubkey), h, sigNoID) {
		return common.Address{}, fmt.Errorf("invalid signature %v for transaction %v",
			hex.EncodeToString(sig), hex.EncodeToString(msg))
	}
	return crypto.PubkeyToAddress(*pubkey), nil
}

func Hash(msg []byte) []byte {
	return crypto.Keccak256(msg)
}

func ValidateAddress(address string) bool {
	return addrRegex.MatchString(address)
}

func MakeNonce() string {
	max := &big.Int{}
	// set it to the max value of the uint64
	max.SetUint64(^uint64(0))
	nonce, _ := rand.Int(rand.Reader, max)
	return nonce.String()
}
