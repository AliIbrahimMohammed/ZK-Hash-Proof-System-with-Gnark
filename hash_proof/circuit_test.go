package hash_proof

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
)

func TestHashCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit HashCircuit

	assert.ProverFailed(&circuit, &HashCircuit{
		PreImage: 42,
		Hash:     42,
	})

	testPreImage := 35
	testHash := "2474112249751028531650252582366798049474486386634137916759752348728204118534"

	assert.ProverSucceeded(&circuit, &HashCircuit{
		PreImage: testPreImage,
		Hash:     testHash,
	}, test.WithCurves(ecc.BN254))
}

func TestHashCircuitFullFlow(t *testing.T) {
	var circuit HashCircuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("Failed to setup: %v", err)
	}

	preImage := 35
	hash := "2474112249751028531650252582366798049474486386634137916759752348728204118534"

	assignment := &HashCircuit{
		PreImage: preImage,
		Hash:     hash,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("Failed to create public witness: %v", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatalf("Failed to create proof: %v", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("Failed to verify proof: %v", err)
	}

	t.Log("Full proof flow successful!")
}

func TestHashCircuitProfile(t *testing.T) {
	var circuit HashCircuit

	p := profile.Start()
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}
	p.Stop()

	fmt.Printf("Number of constraints: %d\n", p.NbConstraints())
	fmt.Printf("Profile top:\n%s\n", p.Top())
}

func TestHashCircuitSerialization(t *testing.T) {
	var circuit HashCircuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("Failed to setup: %v", err)
	}

	preImage := 35
	hash := "2474112249751028531650252582366798049474486386634137916759752348728204118534"

	assignment := &HashCircuit{
		PreImage: preImage,
		Hash:     hash,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("Failed to create public witness: %v", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatalf("Failed to create proof: %v", err)
	}

	var buf bytes.Buffer
	_, err = vk.WriteRawTo(&buf)
	if err != nil {
		t.Fatalf("Failed to serialize verifying key: %v", err)
	}
	t.Logf("Verifying key size: %d bytes", buf.Len())

	vkLoaded := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vkLoaded.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("Failed to deserialize verifying key: %v", err)
	}

	var proofBuf bytes.Buffer
	_, err = proof.WriteRawTo(&proofBuf)
	if err != nil {
		t.Fatalf("Failed to serialize proof: %v", err)
	}
	t.Logf("Proof size: %d bytes", proofBuf.Len())

	proofLoaded := groth16.NewProof(ecc.BN254)
	_, err = proofLoaded.ReadFrom(&proofBuf)
	if err != nil {
		t.Fatalf("Failed to deserialize proof: %v", err)
	}

	err = groth16.Verify(proofLoaded, vkLoaded, publicWitness)
	if err != nil {
		t.Fatalf("Failed to verify deserialized proof: %v", err)
	}

	t.Log("Serialization and deserialization successful!")
}

func TestHashCircuitBinarySerialization(t *testing.T) {
	var circuit HashCircuit

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	preImage := 35
	hash := "2474112249751028531650252582366798049474486386634137916759752348728204118534"

	assignment := &HashCircuit{
		PreImage: preImage,
		Hash:     hash,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	data, err := witness.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to binary marshal witness: %v", err)
	}
	t.Logf("Binary witness size: %d bytes", len(data))

	t.Log("Binary serialization successful!")
}

func TestHashCircuitExportSolidity(t *testing.T) {
	var circuit HashCircuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	_, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("Failed to setup: %v", err)
	}

	var solidityBuf bytes.Buffer
	err = vk.ExportSolidity(&solidityBuf)
	if err != nil {
		t.Fatalf("Failed to export Solidity verifier: %v", err)
	}

	solidityCode := solidityBuf.String()
	t.Logf("Solidity verifier generated, size: %d bytes", len(solidityCode))

	if !bytes.Contains([]byte(solidityCode), []byte("contract Verifier")) {
		t.Fatal("Exported Solidity code does not contain Verifier contract")
	}

	err = os.WriteFile("HashProofVerifier.sol", solidityBuf.Bytes(), 0644)
	if err != nil {
		t.Fatalf("Failed to write Solidity verifier to file: %v", err)
	}

	t.Log("Solidity verifier exported to HashProofVerifier.sol")
}

func BenchmarkHashCircuit(b *testing.B) {
	var circuit HashCircuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		b.Fatalf("Failed to compile circuit: %v", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatalf("Failed to setup: %v", err)
	}

	preImage := 35
	hash := "2474112249751028531650252582366798049474486386634137916759752348728204118534"

	assignment := &HashCircuit{
		PreImage: preImage,
		Hash:     hash,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatalf("Failed to create witness: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		b.Fatalf("Failed to create public witness: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof, err := groth16.Prove(ccs, pk, witness)
		if err != nil {
			b.Fatalf("Failed to create proof: %v", err)
		}

		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			b.Fatalf("Failed to verify proof: %v", err)
		}
	}
}

func TestHashCircuitMultipleCurves(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit HashCircuit

	testCases := []struct {
		name     string
		preImage int
		hash     string
		curve    ecc.ID
	}{
		{
			name:     "BN254",
			preImage: 35,
			hash:     "2474112249751028531650252582366798049474486386634137916759752348728204118534",
			curve:    ecc.BN254,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ProverSucceeded(&circuit, &HashCircuit{
				PreImage: tc.preImage,
				Hash:     tc.hash,
			}, test.WithCurves(tc.curve))
		})
	}
}
