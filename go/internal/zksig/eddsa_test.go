package zksig

import (
	cryptorand "crypto/rand"
	"math/big"
	"math/rand"
	"testing"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	stdeddsa "github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/test"
)

func TestEdDSA(t *testing.T) {
	// Define the curve to use
	const curve = tedwards.BN254
	// Obtain the corresponding snarkField
	snarkField, err := twistededwards.GetSnarkField(curve)
	if err != nil {
		t.Fatal(err)
	}
	// Define the corresponding hash function (use same name)
	hashFunction := hash.MIMC_BN254
	cryptoRandomness := cryptorand.Reader
	mathRandomness := rand.New(rand.NewSource(time.Now().Unix()))

	// Create a EdDSA key pair to use for signing
	key, err := eddsa.New(curve, cryptoRandomness)
	if err != nil {
		t.Fatal(err)
	}
	usedPublicKey := key.Public()
	// Create a different EdDSA public key
	differentKey, err := eddsa.New(curve, cryptoRandomness)
	if err != nil {
		t.Fatal(err)
	}
	differentPublicKey := differentKey.Public()
	// Add all public keys to the key list
	keyList := []signature.PublicKey{differentPublicKey, usedPublicKey}

	// Original comment stated "note that the message is on 4 bytes" but should be 32?
	var msg big.Int
	msg.Rand(mathRandomness, snarkField)
	msgDataUnpadded := msg.Bytes()
	msgData := make([]byte, len(snarkField.Bytes()))
	copy(msgData[len(msgData)-len(msgDataUnpadded):], msgDataUnpadded)

	// Sign the message
	signature, err := key.Sign(msgData, hashFunction.New())
	if err != nil {
		t.Fatal(err)
	}

	// Verify the signature correctness before generating the proof
	isValid, err := usedPublicKey.Verify(signature, msgData, hashFunction.New())
	if err != nil {
		t.Fatal(err)
	}
	if !isValid {
		t.Fatal("Invalid signature!")
	}

	// Define the circuit
	circuit := EdDSACircuit{
		curveID: curve,
		KeyList: make([]stdeddsa.PublicKey, len(keyList)),
	}

	// Define the witnessAssignment
	witnessAssignment := EdDSACircuit{
		Message: msg,
		KeyList: make([]stdeddsa.PublicKey, len(keyList)),
	}
	witnessAssignment.PublicKey.Assign(curve, usedPublicKey.Bytes())
	witnessAssignment.Signature.Assign(curve, signature)
	// assign the keylist by assigning each key in the list
	for i, pk := range keyList {
		var assignedKey stdeddsa.PublicKey
		assignedKey.Assign(curve, pk.Bytes())
		witnessAssignment.KeyList[i] = assignedKey
	}

	if err := test.IsSolved(&circuit, &witnessAssignment, snarkField); err != nil {
		t.Fatal(err)
	}
}

func TestBadEdDSA(t *testing.T) {
	// Define the curve to use
	const curve = tedwards.BN254
	// Obtain the corresponding snarkField
	snarkField, err := twistededwards.GetSnarkField(curve)
	if err != nil {
		t.Fatal(err)
	}
	// Define the corresponding hash function (use same name)
	hashFunction := hash.MIMC_BN254
	cryptoRandomness := cryptorand.Reader
	mathRandomness := rand.New(rand.NewSource(time.Now().Unix()))

	// Create a EdDSA key pair to use for signing
	key, err := eddsa.New(curve, cryptoRandomness)
	if err != nil {
		t.Fatal(err)
	}
	usedPublicKey := key.Public()
	// Create a different EdDSA public key
	differentKey, err := eddsa.New(curve, cryptoRandomness)
	if err != nil {
		t.Fatal(err)
	}
	differentPublicKey := differentKey.Public()
	// Add just the different public key to the key list
	keyList := []signature.PublicKey{differentPublicKey}

	// Original comment stated "note that the message is on 4 bytes" but should be 32?
	var msg big.Int
	msg.Rand(mathRandomness, snarkField)
	msgDataUnpadded := msg.Bytes()
	msgData := make([]byte, len(snarkField.Bytes()))
	copy(msgData[len(msgData)-len(msgDataUnpadded):], msgDataUnpadded)

	// Sign the message
	signature, err := key.Sign(msgData, hashFunction.New())
	if err != nil {
		t.Fatal(err)
	}

	// Verify the signature correctness before generating the proof
	isValid, err := usedPublicKey.Verify(signature, msgData, hashFunction.New())
	if err != nil {
		t.Fatal(err)
	}
	if !isValid {
		t.Fatal("Invalid signature!")
	}

	// Define the circuit
	circuit := EdDSACircuit{
		curveID: curve,
		KeyList: make([]stdeddsa.PublicKey, len(keyList)),
	}

	// Define the witnessAssignment
	witnessAssignment := EdDSACircuit{
		Message: msg,
		KeyList: make([]stdeddsa.PublicKey, len(keyList)),
	}
	witnessAssignment.PublicKey.Assign(curve, usedPublicKey.Bytes())
	witnessAssignment.Signature.Assign(curve, signature)
	// assign the keylist by assigning each key in the list
	for i, pk := range keyList {
		var assignedKey stdeddsa.PublicKey
		assignedKey.Assign(curve, pk.Bytes())
		witnessAssignment.KeyList[i] = assignedKey
	}

	if err := test.IsSolved(&circuit, &witnessAssignment, snarkField); err == nil {
		t.Fatal("Test failed: proof was successful while it should not be")
	}
}
