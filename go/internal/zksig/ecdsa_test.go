package zksig

import (
	cryptorand "crypto/rand"
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	secp256k1ecda "github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/std/math/emulated"
	stdecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
)

func TestECDSA(t *testing.T) {
	// Define the curve to use
	const curve = ecc.BN254
	// Obtain the corresponding snarkField
	snarkField := curve.ScalarField()

	// Create a ECDSA usedKey pair to use for signing
	cryptoRandomness := cryptorand.Reader
	usedKey, err := secp256k1ecda.GenerateKey(cryptoRandomness)
	if err != nil {
		log.Fatal(err)
	}
	usedPublicKey := AssignKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr](usedKey.PublicKey)
	// Create a different ECDSA public key
	differentKey, err := secp256k1ecda.GenerateKey(cryptoRandomness)
	if err != nil {
		log.Fatal(err)
	}
	differentPublicKey := AssignKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr](differentKey.PublicKey)
	// Add all public keys to the key list
	keyList := []stdecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{differentPublicKey, usedPublicKey}

	// Sign a message
	msgData := []byte("this is a test message")
	signatureBytes, err := usedKey.Sign(msgData, nil) //TODO: use hash function, not nil
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signature correctness before generating the proof
	isValid, err := usedKey.Public().Verify(signatureBytes, msgData, nil) //TODO: use hash function, not nil
	if err != nil {
		log.Fatal(err)
	}
	if !isValid {
		log.Fatal("Invalid signature!")
	}

	// Define the circuit
	circuit := ECDSACircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		curveID: curve,
		KeyList: make([]stdecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], len(keyList)),
	}

	// Define the witnessAssignment
	witnessAssignment := ECDSACircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Signature: AssignSignature[emulated.Secp256k1Fr](signatureBytes),
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](secp256k1ecda.HashToInt(msgData)),
		PublicKey: AssignKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr](usedKey.PublicKey),
		KeyList:   make([]stdecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], len(keyList)),
	}
	// assign the keylist by assigning each key in the list
	for i, pk := range keyList {
		witnessAssignment.KeyList[i] = pk
	}

	if err := test.IsSolved(&circuit, &witnessAssignment, snarkField); err != nil {
		t.Fatal(err)
	}
}

func TestBadECDSA(t *testing.T) {
	// Define the curve to use
	const curve = ecc.BN254
	// Obtain the corresponding snarkField
	snarkField := curve.ScalarField()

	// Create a ECDSA usedKey pair to use for signing
	cryptoRandomness := cryptorand.Reader
	usedKey, err := secp256k1ecda.GenerateKey(cryptoRandomness)
	if err != nil {
		log.Fatal(err)
	}
	// Create a different ECDSA public key
	differentKey, err := secp256k1ecda.GenerateKey(cryptoRandomness)
	if err != nil {
		log.Fatal(err)
	}
	differentPublicKey := AssignKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr](differentKey.PublicKey)
	// Add just the different public keys to the key list
	keyList := []stdecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{differentPublicKey}

	// Sign a message
	msgData := []byte("this is a test message")
	signatureBytes, err := usedKey.Sign(msgData, nil) //TODO: use hash function, not nil
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signature correctness before generating the proof
	isValid, err := usedKey.Public().Verify(signatureBytes, msgData, nil) //TODO: use hash function, not nil
	if err != nil {
		log.Fatal(err)
	}
	if !isValid {
		log.Fatal("Invalid signature!")
	}

	// Define the circuit
	circuit := ECDSACircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		curveID: curve,
		KeyList: make([]stdecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], len(keyList)),
	}

	// Define the witnessAssignment
	witnessAssignment := ECDSACircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Signature: AssignSignature[emulated.Secp256k1Fr](signatureBytes),
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](secp256k1ecda.HashToInt(msgData)),
		PublicKey: AssignKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr](usedKey.PublicKey),
		KeyList:   make([]stdecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], len(keyList)),
	}
	// assign the keylist by assigning each key in the list
	for i, pk := range keyList {
		witnessAssignment.KeyList[i] = pk
	}

	if err := test.IsSolved(&circuit, &witnessAssignment, snarkField); err == nil {
		t.Fatal("Test failed: proof was successful while it should not be")
	}
}
