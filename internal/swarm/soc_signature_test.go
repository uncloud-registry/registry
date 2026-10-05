package swarm

import (
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func TestSignSOCIdentifierMatchesBeeVerification(t *testing.T) {
	t.Parallel()
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	ref := make([]byte, 32)
	ref[0] = 1
	sig, err := signSOCIdentifier(id, ref, key)
	if err != nil {
		t.Fatal(err)
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Fatalf("recovery byte = %d, want 27/28", sig[64])
	}
	digest := ethcrypto.Keccak256(id, ref)
	prefixed := ethcrypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), digest)
	rec := append(append([]byte{}, sig[:64]...), sig[64]-27)
	pub, err := ethcrypto.SigToPub(prefixed, rec)
	if err != nil {
		t.Fatal(err)
	}
	if ethcrypto.PubkeyToAddress(*pub) != ethcrypto.PubkeyToAddress(key.PublicKey) {
		t.Fatal("signature does not recover to the owner over the EIP-191 digest")
	}
}
