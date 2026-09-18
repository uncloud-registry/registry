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

func topicHex(logicalTopic string) string {
	return hex.EncodeToString(ethcrypto.Keccak256([]byte(logicalTopic)))
}
