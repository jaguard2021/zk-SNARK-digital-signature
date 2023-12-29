package eddsa

import (
	"math/big"

	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/frontend"
)

// CurveParams menyimpan parameter kurva twisted Edwards
type CurveParams struct {
	A, D, Cofactor, Order *big.Int
	Base                  [2]*big.Int // Koordinat titik dasar
}

// PublicKey menyimpan kunci publik pada kurva twisted Edwards
type PublicKey struct {
	A twistededwards.Point
}

// Signature menyimpan tanda tangan EdDSA (R, S)
type Signature struct {
	R twistededwards.Point
	S frontend.Variable
}

// Verify melakukan verifikasi tanda tangan EdDSA di dalam sirkuit zk-SNARK
func Verify(api frontend.API, sig Signature, msg frontend.Variable, pubKey PublicKey) error {
	// Parameter kurva Edwards torsi
	curveParams := &CurveParams{
		// Isi parameter kurva yang sesuai
	}

	// Fungsi hash MiMC
	hash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Hitung H(R, A, M)
	data := []frontend.Variable{
		sig.R.A.X,
		sig.R.A.Y,
		pubKey.A.X,
		pubKey.A.Y,
		msg,
	}
	hramConstant := hash.Hash(api, data...)

	// Inisialisasi sisi kiri (lhs) dan sisi kanan (rhs)
	var lhs, rhs twistededwards.Point

	// Hitung sisi kiri [2^basis*S1]G
	// ...

	// Hitung sisi kanan [2^c*(2^basis*S1 + S2)]G
	// ...

	// Pastikan sisi kiri dan sisi kanan sama di dalam sirkuit zk-SNARK
	api.AssertIsEqual(lhs.X, rhs.X)
	api.AssertIsEqual(lhs.Y, rhs.Y)

	return nil
}
