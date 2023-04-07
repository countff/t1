package core

type cib int

const (
	NoCheck cib = iota
	CheckInvokerBySKI
	CheckInvokerByMSP
)

type ContractOptions struct {
	DisabledFunctions []string
	CheckInvokerBy    cib
	DisableSwaps      bool
	DisableMultiSwaps bool
}
