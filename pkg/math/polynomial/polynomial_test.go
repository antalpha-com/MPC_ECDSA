package polynomial

import (
	big "MPC_ECDSA/pkg/gmp"
	"crypto/rand"
	// "math/big"
	mrand "math/rand"
	"testing"

	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/sample"

	"MPC_ECDSA/pkg/BigInt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolynomial_Constant(t *testing.T) {
	group := curve.Secp256k1{}

	deg := 10
	secret := sample.Scalar(rand.Reader, group)
	poly := NewPolynomial(group, deg, secret)
	require.True(t, poly.Constant().Equal(secret))
}

func TestPolynomial_Evaluate(t *testing.T) {
	group := curve.Secp256k1{}

	polynomial := &Polynomial{group, make([]curve.Scalar, 3)}
	polynomial.coefficients[0] = group.NewScalar().SetNat(new(BigInt.Nat).SetUint64(1))
	polynomial.coefficients[1] = group.NewScalar()
	polynomial.coefficients[2] = group.NewScalar().SetNat(new(BigInt.Nat).SetUint64(1))

	for index := 0; index < 100; index++ {
		x := big.NewInt(int64(mrand.Uint32()))
		result := new(big.Int).Set(x)
		result.Mul(result, result)
		result.Add(result, big.NewInt(1))
		tmp1 := new(BigInt.Nat).SetUint64(0)
		tmp1.Data.Set(x)
		xScalar := group.NewScalar().SetNat(tmp1)
		computedResult := polynomial.Evaluate(xScalar)
		tmp2 := new(BigInt.Nat).SetUint64(0)
		tmp2.Data.Set(result)
		expectedResult := group.NewScalar().SetNat(tmp2)
		assert.True(t, expectedResult.Equal(computedResult))
	}
}
