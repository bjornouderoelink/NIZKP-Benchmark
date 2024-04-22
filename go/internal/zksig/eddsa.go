package zksig

import (
	cryptorand "crypto/rand"
	"log"
	"math/big"
	"math/rand"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	stdeddsa "github.com/consensys/gnark/std/signature/eddsa"
)

// EdDSACircuit defines the EdDSA circuit
type EdDSACircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	curveID   tedwards.ID          `gnark:",secret"`
	PublicKey stdeddsa.PublicKey   `gnark:",secret"`
	Signature stdeddsa.Signature   `gnark:",public"`
	Message   frontend.Variable    `gnark:",public"`
	KeyList   []stdeddsa.PublicKey `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *EdDSACircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// start with isUnknownKey at 1, meaning that the key is unknown
	var isUnknownKey frontend.Variable = 1
	// for each key in the KeyList, we checkfor equality to the PublicKey
	for _, key := range circuit.KeyList {
		// equalX is 1 if the PublicKey.X is equal to the key.X
		equalX := api.IsZero(api.Cmp(circuit.PublicKey.A.X, key.A.X))
		api.AssertIsBoolean(equalX)
		// equalY is 1 if the PublicKey.Y is equal to the key.Y
		equalY := api.IsZero(api.Cmp(circuit.PublicKey.A.Y, key.A.Y))
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
	return stdeddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

func RunEdDSA() {
	// Define the curve to use
	const curve = tedwards.BN254
	// Obtain the corresponding snarkField
	snarkField, err := twistededwards.GetSnarkField(curve)
	if err != nil {
		log.Fatal(err)
	}
	// Define the corresponding hash function (use same name)
	hashFunction := hash.MIMC_BN254
	cryptoRandomness := cryptorand.Reader
	mathRandomness := rand.New(rand.NewSource(time.Now().Unix()))

	// Create a EdDSA key pair to use for signing
	key, err := eddsa.New(curve, cryptoRandomness)
	if err != nil {
		log.Fatal(err)
	}
	usedPublicKey := key.Public()
	// Create a different EdDSA public key
	differentKey, err := eddsa.New(curve, cryptoRandomness)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}

	// Verify the signature correctness before generating the proof
	isValid, err := usedPublicKey.Verify(signature, msgData, hashFunction.New())
	if err != nil {
		log.Fatal(err)
	}
	if !isValid {
		log.Fatal("Invalid signature!")
	}

	// Compile the circuit into R1CS
	circuit := EdDSACircuit{
		curveID: curve,
		KeyList: make([]stdeddsa.PublicKey, len(keyList)),
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
	assignment := EdDSACircuit{
		Message: msg,
		KeyList: make([]stdeddsa.PublicKey, len(keyList)),
	}
	assignment.PublicKey.Assign(curve, usedPublicKey.Bytes())
	assignment.Signature.Assign(curve, signature)
	// assign the keylist by assigning each key in the list
	for i, pk := range keyList {
		var assignedKey stdeddsa.PublicKey
		assignedKey.Assign(curve, pk.Bytes())
		assignment.KeyList[i] = assignedKey
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
