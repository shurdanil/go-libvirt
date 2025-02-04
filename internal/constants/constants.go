package constants

const (
	ProcAuthSASLInit  = 67
	ProcAuthSASLStart = 68
	ProcAuthSASLStep  = 69
	ProcAuthPolKit    = 70
)

// RemoteAuthType specifies the type of authentication used by libvirt
type RemoteAuthType uint32

// Currently supported remote authentication types as defined by libvirt
// See:
// https://libvirt.org/git/?p=libvirt.git;a=blob_plain;f=src/remote/remote_protocol.x;hb=HEAD
const (
	// RemoteAuthTypeNone means that no authentication is required
	RemoteAuthTypeNone RemoteAuthType = iota
	// RemoteAuthTypeSASL means that the SASL authentication mechanism is used
	RemoteAuthTypeSASL
	// RemoteAuthTypePolKit means that PolKit is used for authentication
	RemoteAuthTypePolKit
)

const (
	// AuthSASLDataMax is the upper limit on SASL auth negotiation packet
	AuthSASLDataMax = 65536
)
