package spec

import (
	"encoding/hex"
	"fmt"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

const (
	authPolicyTopicPrefix  = "v1:policy:auth"
	stampPolicyTopicPrefix = "v1:policy:stamp"
	repoStateTopicPrefix   = "v1:repo:"
)

func AuthPolicyFeedRef(owner string) string {
	return TopicFeedRef(owner, authPolicyTopicPrefix)
}

func StampPolicyFeedRef(owner string) string {
	return TopicFeedRef(owner, stampPolicyTopicPrefix)
}

func RepoStateFeedRef(owner string, repo string) string {
	return TopicFeedRef(owner, repoStateTopicPrefix+repo)
}

func TopicFeedRef(owner string, logicalTopic string) string {
	return fmt.Sprintf("feed://%s/%s", normalizeOwner(owner), topicHex(logicalTopic))
}

func normalizeOwner(owner string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(owner)), "0x")
}

// NormalizeOwner returns the canonical lowercase, 0x-trimmed form of a feed
// owner address. It is the exported form of normalizeOwner so identity
// comparison (e.g. the control-plane feed signer comparing a request owner to a
// stored feed-owner address) uses exactly the same normalization as feed
// construction.
func NormalizeOwner(owner string) string {
	return normalizeOwner(owner)
}

func topicHex(logicalTopic string) string {
	return hex.EncodeToString(ethcrypto.Keccak256([]byte(logicalTopic)))
}
