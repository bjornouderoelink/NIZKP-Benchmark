package hash

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
)

const BENCHMARK_MIMC_ROUNDS = 4095

var BENCHMARK_SCALAR_FIELD = ecc.BLS12_381.ScalarField()

func Benchmark(b *testing.B) {
	// Disable logging to prevent repeated output
	logger.Disable()

	// Generate the MiMC round constants
	constants := make([]fr.Element, BENCHMARK_MIMC_ROUNDS)
	for i := range constants {
		if _, err := constants[i].SetRandom(); err != nil {
			b.Fatal(err)
		}
	}
	constantsAssignment := make([]frontend.Variable, BENCHMARK_MIMC_ROUNDS)
	for i := range constantsAssignment {
		constantsAssignment[i] = constants[i]
	}

	// Generate a random preimage
	xl := fr.NewElement(0)
	if _, err := xl.SetRandom(); err != nil {
		b.Fatal(err)
	}
	xr := fr.NewElement(0)
	if _, err := xr.SetRandom(); err != nil {
		b.Fatal(err)
	}

	// Compute the MiMC hash image
	image := mimc(xl, xr, constants)

	// compiles our circuit into a R1CS
	circuit := MiMCCircuit{
		Constants: make([]frontend.Variable, BENCHMARK_MIMC_ROUNDS),
	}
	ccs, err := frontend.Compile(BENCHMARK_SCALAR_FIELD, r1cs.NewBuilder, &circuit)
	if err != nil {
		b.Fatal(err)
	}

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}

	// witness definition
	assignment := MiMCCircuit{
		Xl:        xl,
		Xr:        xr,
		Constants: constantsAssignment,
		Image:     image,
	}
	witness, err := frontend.NewWitness(&assignment, BENCHMARK_SCALAR_FIELD)
	if err != nil {
		b.Fatal(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		b.Fatal(err)
	}

	// groth16: Prove
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		b.Fatal(err)
	}

	// Collect CRS metrics
	buf := new(bytes.Buffer)
	sizeSerizalizedProvingKeyBytes, err := pk.WriteTo(buf)
	if err != nil {
		b.Fatal(err)
	}
	buf.Reset()
	sizeSerizalizedVerificationKeyBytes, err := vk.WriteTo(buf)
	if err != nil {
		b.Fatal(err)
	}
	buf.Reset()
	sizeSerizalizedRawProvingKeyBytes, err := pk.WriteRawTo(buf)
	if err != nil {
		b.Fatal(err)
	}
	buf.Reset()
	sizeSerizalizedRawVerificationKeyBytes, err := vk.WriteRawTo(buf)
	if err != nil {
		b.Fatal(err)
	}
	buf.Reset()
	fmt.Printf("CRS metrics:\n\tSize serialized proving key (bytes): %d compressed, %d uncompressed\n\tSize serialized verification key (bytes): %d compressed, %d uncompressed\n", sizeSerizalizedProvingKeyBytes, sizeSerizalizedRawProvingKeyBytes, sizeSerizalizedVerificationKeyBytes, sizeSerizalizedRawVerificationKeyBytes)

	// Collect witness metrics
	sizeWitnessBytes, err := witness.WriteTo(buf)
	if err != nil {
		b.Fatal(err)
	}
	buf.Reset()
	sizePublicWitnessBytes, err := publicWitness.WriteTo(buf)
	if err != nil {
		b.Fatal(err)
	}
	buf.Reset()
	fmt.Printf("Witness metrics:\n\tSize total (bytes): %d compressed\n\tSize public only (bytes): %d compressed\n", sizeWitnessBytes, sizePublicWitnessBytes)

	// Collect proof metrics
	sizeSerizalizedProofBytes, err := proof.WriteRawTo(buf)
	if err != nil {
		b.Fatal(err)
	}
	buf.Reset()
	sizeSerizalizedRawProofBytes, err := proof.WriteRawTo(buf)
	if err != nil {
		b.Fatal(err)
	}
	buf.Reset()
	fmt.Printf("Proof metrics:\n\tSize serialized (bytes): %d compressed, %d uncompressed \n\tSecurity level (bits): %s conjectured, %s proven", sizeSerizalizedProofBytes, sizeSerizalizedRawProofBytes, "?", "?")

	b.Run("compile", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccs, err := frontend.Compile(BENCHMARK_SCALAR_FIELD, r1cs.NewBuilder, &circuit)
			if err != nil {
				b.Fatal(err)
			}
			_ = ccs
		}
	})

	b.Run("setup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// groth16 zkSNARK: Setup
			pk, vk, err := groth16.Setup(ccs)
			if err != nil {
				b.Fatal(err)
			}

			_, _ = pk, vk
		}
	})

	b.Run("proof", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// groth16: Prove
			proof, err := groth16.Prove(ccs, pk, witness)
			if err != nil {
				b.Fatal(err)
			}

			_ = proof
		}
	})

	b.Run("verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// groth16: Verify
			if err := groth16.Verify(proof, vk, publicWitness); err != nil {
				b.Fatal(err)
			}
		}
	})
}
