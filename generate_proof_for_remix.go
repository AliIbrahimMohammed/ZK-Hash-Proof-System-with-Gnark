package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Circuit struct {
	PreImage frontend.Variable `gnark:",secret"`
	Hash     frontend.Variable `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hFunc.Write(c.PreImage)
	computedHash := hFunc.Sum()
	api.AssertIsEqual(c.Hash, computedHash)
	return nil
}

func main() {
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║  ZK Hash Proof Generator for Remix On-Chain Verification  ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Configuration
	preImage := 35
	hash := "2474112249751028531650252582366798049474486386634137916759752348728204118534"

	fmt.Printf("📋 Configuration:\n")
	fmt.Printf("   Secret PreImage (x): %d\n", preImage)
	fmt.Printf("   Public Hash (y):     %s\n", hash)
	fmt.Println()

	// Step 1: Compile Circuit
	fmt.Println("🔨 Step 1: Compiling circuit...")
	var circuit Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("❌ Error compiling circuit: %v\n", err)
		return
	}
	fmt.Printf("   ✅ Circuit compiled (%d constraints)\n", ccs.GetNbConstraints())
	fmt.Println()

	// Step 2: Setup (CRITICAL: This generates VK for Solidity AND pk for proof)
	fmt.Println("⚙️  Step 2: Setting up Groth16...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Printf("❌ Error in setup: %v\n", err)
		return
	}
	fmt.Println("   ✅ Setup complete")
	fmt.Println()

	// Step 3: Export Solidity Verifier (use SAME vk from step 2)
	fmt.Println("📜 Step 3: Exporting Solidity verifier...")
	var solidityBuf bytes.Buffer
	err = vk.ExportSolidity(&solidityBuf)
	if err != nil {
		fmt.Printf("❌ Error exporting Solidity: %v\n", err)
		return
	}

	err = os.WriteFile("HashProofVerifier.sol", solidityBuf.Bytes(), 0644)
	if err != nil {
		fmt.Printf("❌ Error writing Solidity file: %v\n", err)
		return
	}
	fmt.Printf("   ✅ Solidity verifier written to HashProofVerifier.sol (%d bytes)\n", solidityBuf.Len())
	fmt.Println()

	// Step 4: Create Witness
	fmt.Println("📝 Step 4: Creating witness...")
	assignment := &Circuit{
		PreImage: preImage,
		Hash:     hash,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("❌ Error creating witness: %v\n", err)
		return
	}
	fmt.Println("   ✅ Witness created")
	fmt.Println()

	// Step 5: Generate Proof (use SAME pk from step 2)
	fmt.Println("🔓 Step 5: Generating proof...")
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Printf("❌ Error generating proof: %v\n", err)
		return
	}
	fmt.Println("   ✅ Proof generated")
	fmt.Println()

	// Step 6: Verify Off-chain (sanity check)
	fmt.Println("✅ Step 6: Verifying off-chain...")
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Printf("❌ Error getting public witness: %v\n", err)
		return
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("❌ Off-chain verification failed: %v\n", err)
		return
	}
	fmt.Println("   ✅ Off-chain verification successful")
	fmt.Println()

	// Step 7: Serialize Proof
	fmt.Println("📦 Step 7: Serializing proof...")
	var proofBuf bytes.Buffer
	_, err = proof.WriteRawTo(&proofBuf)
	if err != nil {
		fmt.Printf("❌ Error serializing proof: %v\n", err)
		return
	}
	proofBytes := proofBuf.Bytes()
	fmt.Printf("   ✅ Proof serialized (%d bytes)\n", len(proofBytes))
	fmt.Println()

	// Step 8: Format for Remix
	fmt.Println("🎯 Step 8: Formatting for Remix...")

	type RemixOutput struct {
		Proof    [8]string `json:"proof"`
		Input    string    `json:"input"`
		PreImage int       `json:"preImage"`
		FullHex  string    `json:"fullProofHex"`
	}

	var output RemixOutput
	output.Input = hash
	output.PreImage = preImage

	// Parse proof bytes into 8 uint256 values
	for i := 0; i < 8; i++ {
		start := i * 32
		end := start + 32
		if end > len(proofBytes) {
			end = len(proofBytes)
		}
		val := new(big.Int).SetBytes(proofBytes[start:end])
		output.Proof[i] = val.String()
	}

	output.FullHex = fmt.Sprintf("0x%x", proofBytes)

	jsonData, _ := json.MarshalIndent(output, "", "  ")
	err = os.WriteFile("remix_proof_values.json", jsonData, 0644)
	if err != nil {
		fmt.Printf("❌ Error writing JSON: %v\n", err)
		return
	}
	fmt.Println("   ✅ Remix values saved to remix_proof_values.json")
	fmt.Println()

	// Display Results
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    VERIFICATION COMPLETE                     ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("📁 Files Generated:")
	fmt.Println("   1. HashProofVerifier.sol - Deploy this to Remix")
	fmt.Println("   2. remix_proof_values.json - Copy these values to Remix")
	fmt.Println()
	fmt.Println("🔗 Remix Instructions:")
	fmt.Println("   1. Open https://remix.ethereum.org")
	fmt.Println("   2. Create file 'Verifier.sol' and paste HashProofVerifier.sol")
	fmt.Println("   3. Compile with Solidity 0.8.0+")
	fmt.Println("   4. Deploy with 'Injected Provider - MetaMask'")
	fmt.Println("   5. Call verifyProof with values from remix_proof_values.json")
	fmt.Println()
	fmt.Println("📋 Copy these EXACT values to Remix:")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()

	fmt.Println("Proof (uint256[8]):")
	for i := 0; i < 8; i++ {
		fmt.Printf("  proof[%d]: %s\n", i, output.Proof[i])
	}
	fmt.Println()
	fmt.Printf("Input (uint256[1]):\n")
	fmt.Printf("  input[0]: %s\n", output.Input)
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("✅ Everything is ready! The proof and verifier are now compatible.")
}
