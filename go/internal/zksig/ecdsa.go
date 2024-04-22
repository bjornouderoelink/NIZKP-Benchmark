package zksig

import (
	cryptorand "crypto/rand"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	secp256k1ecda "github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	stdecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

type ECDSAPublicKey stdecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]

// ECDSACircuit defines the ECDSA circuit
type ECDSACircuit[T, S emulated.FieldParams] struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	curveID   ecc.ID                     `gnark:",secret"`
	PublicKey stdecdsa.PublicKey[T, S]   `gnark:",secret"`
	Signature stdecdsa.Signature[S]      `gnark:",public"`
	Message   emulated.Element[S]        `gnark:",public"`
	KeyList   []stdecdsa.PublicKey[T, S] `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *ECDSACircuit[T, S]) Define(api frontend.API) error {
	// TODO: use hash
	// mimc, err := mimc.NewMiMC(api)
	// if err != nil {
	// 	return err
	// }

	emulatedField, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	// start with isUnknownKey at 1, meaning that the key is unknown
	var isUnknownKey frontend.Variable = 1
	// for each key in the KeyList, we checkfor equality to the PublicKey
	for _, key := range circuit.KeyList {
		// equalX is 1 if the PublicKey.X is equal to the key.X
		equalX := emulatedField.IsZero(emulatedField.Sub(&circuit.PublicKey.X, &key.X))
		api.AssertIsBoolean(equalX)
		// equalY is 1 if the PublicKey.Y is equal to the key.Y
		equalY := emulatedField.IsZero(emulatedField.Sub(&circuit.PublicKey.Y, &key.Y))
		api.AssertIsBoolean(equalY)

		// differentKey is 0 if the key is equal, i.e. both equalX and equalY are 1 (IsZero on And acts as NAND)
		differentKey := api.IsZero(api.And(equalX, equalY))
		api.AssertIsBoolean(differentKey)
		// if the key is different, differentKey is 1 so [0 or 1] * 1 = [0 or 1]
		// if the key is equal, isUnknownKey becomes [0 or 1] * 0 = 0
		isUnknownKey = api.Mul(isUnknownKey, differentKey)
		api.AssertIsBoolean(isUnknownKey)
	}
	// if isUnknownKey is 0 then the used PublicKey is in the KeyList, so this part of the proof must pass.
	// if isUnknownKey is 1 then the used PublicKey is not in the KeyList, so the total proof must fail.
	api.AssertIsEqual(isUnknownKey, 0)

	// verify the signature in the constraint system
	circuit.PublicKey.Verify(api, sw_emulated.GetCurveParams[T](), &circuit.Message, &circuit.Signature)
	return nil //TODO: return error if fails, currently panics
}

func RunECDSA() {
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

	// Compile the circuit into R1CS
	circuit := ECDSACircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		curveID: curve,
		KeyList: make([]stdecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], len(keyList)),
	}
	r1cs, err := frontend.Compile(snarkField, r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatal("Failed to compile circuit! ", err)
	}

	// Setup the groth16 zkSNARK proof
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatal("Failed to perform setup! ", err)
	}

	// Define the witness
	assignment := ECDSACircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Signature: AssignSignature[emulated.Secp256k1Fr](signatureBytes),
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](secp256k1ecda.HashToInt(msgData)),
		PublicKey: AssignKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr](usedKey.PublicKey),
		KeyList:   make([]stdecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], len(keyList)),
	}

	// assign the keylist by assigning each key in the list
	for i, pk := range keyList {
		assignment.KeyList[i] = pk
	}

	witness, err := frontend.NewWitness(&assignment, snarkField)
	if err != nil {
		log.Fatal("Failed to generate witness! ", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatal("Failed to obtain public witness! ", err)
	}

	// Generate the Groth16 proof and verify it
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatal("Failed to generate proof! ", err)
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		log.Fatal("Failed to verify proof! ", err)
	}
}

func AssignSignature[S emulated.FieldParams](signatureBytes []byte) stdecdsa.Signature[S] {
	var signature secp256k1ecda.Signature
	signature.SetBytes(signatureBytes)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature.R[:32])
	s.SetBytes(signature.S[:32])
	return stdecdsa.Signature[S]{
		R: emulated.ValueOf[S](r),
		S: emulated.ValueOf[S](s),
	}
}

func AssignKey[T, S emulated.FieldParams](publicKey secp256k1ecda.PublicKey) stdecdsa.PublicKey[T, S] {
	return stdecdsa.PublicKey[T, S]{
		X: emulated.ValueOf[T](publicKey.A.X),
		Y: emulated.ValueOf[T](publicKey.A.Y),
	}
}
