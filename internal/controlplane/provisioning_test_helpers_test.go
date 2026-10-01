package controlplane

// newMemPublisher returns a Publisher fully backed by in-memory stores (an
// object store and a feed store that serves as both updater and resolver), so
// a test Service can create registries under the fail-closed provisioning
// contract without any network. Tests dedicated to provisioning may also
// inspect the returned stores; non-provisioning tests just need the Publisher
// present.
func newMemPublisher() *Publisher {
	up := &memoryUploader{refs: map[string][]byte{}}
	fs := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	return &Publisher{Documents: up, Feeds: fs, FeedsReader: fs}
}
