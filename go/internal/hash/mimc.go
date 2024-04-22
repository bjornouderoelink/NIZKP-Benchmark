package hash

import (
	"bytes"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// MiMCCircuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type MiMCCircuit struct {
	Xl        frontend.Variable
	Xr        frontend.Variable
	Constants []frontend.Variable `gnark:",public"`
	Image     frontend.Variable   `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *MiMCCircuit) Define(api frontend.API) error {
	xl := circuit.Xl
	xr := circuit.Xr

	for _, ci := range circuit.Constants {
		xlci := api.Add(xl, ci)
		cube := api.Mul(xlci, xlci, xlci)
		nextXl := api.Add(cube, xr)

		xr = xl
		xl = nextXl
	}

	api.AssertIsEqual(circuit.Image, xl)
	return nil
}

const MIMC_ROUNDS = 100

func Run() {
	// Generate the MiMC round constants
	constants := make([]fr.Element, MIMC_ROUNDS)
	for i := range constants {
		if _, err := constants[i].SetRandom(); err != nil {
			log.Fatal(err)
		}
	}
	constantsAssignment := make([]frontend.Variable, MIMC_ROUNDS)
	for i := range constantsAssignment {
		constantsAssignment[i] = constants[i]
	}

	// Generate a random preimage
	xl := fr.NewElement(0)
	if _, err := xl.SetRandom(); err != nil {
		log.Fatal(err)
	}
	xr := fr.NewElement(0)
	if _, err := xr.SetRandom(); err != nil {
		log.Fatal(err)
	}

	// Compute the MiMC hash image
	image := mimc(xl, xr, constants)

	// compiles our circuit into a R1CS
	circuit := MiMCCircuit{
		Constants: make([]frontend.Variable, MIMC_ROUNDS),
	}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatal(err)
	}

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}

	// witness definition
	assignment := MiMCCircuit{
		Xl:        xl,
		Xr:        xr,
		Constants: constantsAssignment,
		Image:     image,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		log.Fatal(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		log.Fatal(err)
	}

	// Output CRS metrics
	buf := new(bytes.Buffer)
	sizeSerizalizedProvingKeyBytes, err := pk.WriteTo(buf)
	if err != nil {
		log.Fatal(err)
	}
	buf.Reset()
	sizeSerizalizedVerificationKeyBytes, err := vk.WriteTo(buf)
	if err != nil {
		log.Fatal(err)
	}
	buf.Reset()
	sizeSerizalizedRawProvingKeyBytes, err := pk.WriteRawTo(buf)
	if err != nil {
		log.Fatal(err)
	}
	buf.Reset()
	sizeSerizalizedRawVerificationKeyBytes, err := vk.WriteRawTo(buf)
	if err != nil {
		log.Fatal(err)
	}
	buf.Reset()
	log.Printf("CRS metrics:\n\tSize serialized proving key (bytes): %d compressed, %d uncompressed\n\tSize serialized verification key (bytes):  %d compressed, %d uncompressed\n", sizeSerizalizedProvingKeyBytes, sizeSerizalizedRawProvingKeyBytes, sizeSerizalizedVerificationKeyBytes, sizeSerizalizedRawVerificationKeyBytes)

	// Output proof metrics
	sizeSerizalizedProofBytes, err := proof.WriteRawTo(buf)
	if err != nil {
		log.Fatal(err)
	}
	buf.Reset()
	sizeSerizalizedRawProofBytes, err := proof.WriteRawTo(buf)
	if err != nil {
		log.Fatal(err)
	}
	buf.Reset()
	log.Printf("Proof metrics:\n\tSize serialized (bytes): %d compressed, %d uncompressed \n\tSecurity level (bits): %s conjectured, %s proven", sizeSerizalizedProofBytes, sizeSerizalizedRawProofBytes, "?", "?")
}

func mimc(xl, xr fr.Element, constants []fr.Element) fr.Element {
	tempXl := xl
	tempXr := xr

	for _, ci := range constants {
		xlci := fr.NewElement(0)
		xlci.Add(&tempXl, &ci)
		square := fr.NewElement(0)
		square.Mul(&xlci, &xlci)
		cube := fr.NewElement(0)
		cube.Mul(&square, &xlci)
		nextXl := fr.NewElement(0)
		nextXl.Add(&cube, &tempXr)

		tempXr.Set(&tempXl)
		tempXl.Set(&nextXl)
	}

	return tempXl
}
