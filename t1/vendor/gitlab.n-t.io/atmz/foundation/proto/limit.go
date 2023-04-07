package proto

import "gitlab.n-t.io/atmz/foundation/golang-math-big"

func (m *TokenRate) InLimit(amount *big.Int) bool {
	maxLimit := new(big.Int).SetBytes(m.Max)
	minLimit := new(big.Int).SetBytes(m.Min)

	return amount.Cmp(minLimit) >= 0 && (maxLimit.Cmp(big.NewInt(0)) == 0 || amount.Cmp(maxLimit) <= 0)
}

func (m *TokenRate) CalcPrice(amount *big.Int, rateDecimal uint64) *big.Int {
	return new(big.Int).
		Div(
			new(big.Int).Mul(amount, new(big.Int).SetBytes(m.Rate)),
			new(big.Int).Exp(
				new(big.Int).SetUint64(10),
				new(big.Int).SetUint64(rateDecimal), nil))
}
