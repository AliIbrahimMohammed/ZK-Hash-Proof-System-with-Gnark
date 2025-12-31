package hash_proof

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type HashCircuit struct {
	PreImage frontend.Variable `gnark:",secret"`
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *HashCircuit) Define(api frontend.API) error {
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	hFunc.Write(circuit.PreImage)
	computedHash := hFunc.Sum()

	api.AssertIsEqual(circuit.Hash, computedHash)

	return nil
}
