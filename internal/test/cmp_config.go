package test

import (
	"io"

	"MPC_ECDSA/internal/types"
	paillier "MPC_ECDSA/pkg/gmp_paillier"
	"MPC_ECDSA/pkg/math/curve"
	"MPC_ECDSA/pkg/math/polynomial"
	"MPC_ECDSA/pkg/math/sample"
	"MPC_ECDSA/pkg/party"
	"MPC_ECDSA/pkg/pedersen"
	"MPC_ECDSA/pkg/pool"
	"MPC_ECDSA/protocols/config"
)

// GenerateConfig creates some random configuration for N parties with set threshold T over the group.
func GenerateConfig(group curve.Curve, N, T int, source io.Reader, pl *pool.Pool) (map[party.ID]*config.Config, party.IDSlice) {
	//Generate a list of party IDs using the PartyIDs function.
	partyIDs := PartyIDs(N)
	//Initialize maps to store the configuration and public information for each party.
	configs := make(map[party.ID]*config.Config, N)
	public := make(map[party.ID]*config.Public, N)
	//Create a polynomial object f using the group curve, the threshold, and random scalar values.
	f := polynomial.NewPolynomial(group, T, sample.Scalar(source, group))
	//Generate random RID
	rid, err := types.NewRID(source)
	if err != nil {
		panic(err)
	}
	//Generate chain key values.
	chainKey, err := types.NewRID(source)
	if err != nil {
		panic(err)
	}

	for _, pid := range partyIDs {
		paillierSecret := paillier.NewSecretKey(pl)                                  //Generate a Paillier secret key pair
		s, t, _ := sample.Pedersen(source, paillierSecret.Phi(), paillierSecret.N()) //Pedersen commitment parameters
		pedersenPublic := pedersen.New(paillierSecret.Modulus(), s, t)
		elGamalSecret := sample.Scalar(source, group) //Generate an ElGamal secret key

		ecdsaSecret := f.Evaluate(pid.Scalar(group)) //generate an ECDSA secret key.
		configs[pid] = &config.Config{
			Group:     group,
			ID:        pid,
			Threshold: T,
			ECDSA:     ecdsaSecret,
			ElGamal:   elGamalSecret,
			Paillier:  paillierSecret,
			RID:       rid.Copy(),
			ChainKey:  chainKey.Copy(),
			Public:    public,
		}
		X := ecdsaSecret.ActOnBase()
		public[pid] = &config.Public{
			ECDSA:    X,
			ElGamal:  elGamalSecret.ActOnBase(),
			Paillier: paillierSecret.PublicKey,
			Pedersen: pedersenPublic,
		}
	}
	return configs, partyIDs
}
