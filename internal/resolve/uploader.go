package resolve

import "errors"

// ErrUploaderPreSideEffect marks an object-uploader failure that is
// CONCLUSIVELY PRE-SIDE-EFFECT: the object store never received (and never
// could have received) any of the blob's bytes, so registry blob finalization
// may safely RELEASE its durable claim and return the session to active with
// ZERO risk of a duplicate or orphaned external write. It is the ONLY
// classification that authorizes release. Every generic transport/HTTP/parse
// failure — the object store may or may not have stored the bytes and the
// returned reference is lost if the process dies before the receipt is
// persisted — is AMBIGUOUS and must RETAIN the claim fail-closed. Generic
// errors are ambiguous by default: only an implementation that explicitly
// wraps this sentinel claims the no-write guarantee. The data-free text
// carries no operation token, reference, batch id, or raw cause.
//
// This neutral contract lives HERE (the lowest package both the registry
// finalization protocol and the swarm object uploader already depend on, and
// the home of the in-memory streaming object store that implements the same
// Put/PutStream contract) so that both depend DOWNWARD on it and neither
// imports the other.
//
// CONTRACT for uploader implementations: emit this sentinel ONLY for
// failures conclusively known to precede any external write — a rejected
// nil/negative/oversized request argument, a request that could not even be
// constructed, or any failure before the first payload byte reached the
// store. Never emit it for a transport (HTTPClient.Do) failure, a non-success
// status, or a body read/decode/reference failure: any of these may mean the
// store accepted the bytes. A deliberately malicious uploader implementation
// is trusted by the interface — Go cannot cryptographically prevent one from
// mislabeling its errors — so this contract governs well-behaved adapters,
// and the durable claim-release decision assumes the adapter honors it.
var ErrUploaderPreSideEffect = errors.New("object upload failed before any external write")
