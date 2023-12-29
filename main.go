package main

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark-crypto/hash/mimc"
)

// EdDSA circuit definition
type eddsaCircuit struct {
	PublicKey eddsa.PublicKey   `gnark:",public"`
	Signature eddsa.Signature   `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(cs *frontend.ConstraintSystem) error {
	// your circuit definition here
	return nil
}

func main() {
	// instantiate hash function
	hFunc := mimc.NewMiMC()

	// create an EdDSA key pair
	privateKey, err := eddsa.New(ecc.BN254, rand.Reader)
	if err != nil {
		fmt.Println("Error creating EdDSA key pair:", err)
		return
	}
	publicKey := privateKey.Public()

	// define a message (assuming it's already hashed)
	var msg frontend.Variable

	// create the EdDSA circuit
	var circuit eddsaCircuit
	r1cs, err := frontend.Compile(ecc.BN254, frontend.R1CS, &circuit)
	if err != nil {
		fmt.Println("Error compiling circuit:", err)
		return
	}

	// generate ProvingKey and VerifyingKey linked to the circuit
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Println("Error setting up Groth16:", err)
		return
	}

	// create the witness
	var assignment eddsaCircuit
	assignment.Message.Assign(circuit.Message)
	assignment.PublicKey.Assign(ecc.BN254, publicKey.Bytes()[:32])
	assignment.Signature.Assign(ecc.BN254, privateKey.SignBytes(msg))

	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	if err != nil {
		fmt.Println("Error creating witness:", err)
		return
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("Error extracting public witness:", err)
		return
	}

	// generate the proof
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println("Error generating proof:", err)
		return
	}

	// verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Proof verification failed:", err)
		return
	}

	fmt.Println("Proof verification succeeded!")
}
