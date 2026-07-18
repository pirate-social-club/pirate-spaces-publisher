package fabric

import (
	"encoding/json"
	"testing"
)

func TestHintsResponseDecodesRelayProtocolField(t *testing.T) {
	var response HintsResponse
	if err := json.Unmarshal([]byte(`{
		"anchor_tip": 958572,
		"hints": [{
			"name": "@xn--tl8h",
			"epoch_tip": 0,
			"seq": 1,
			"delegate_seq": 0
		}]
	}`), &response); err != nil {
		t.Fatalf("decode relay hints: %v", err)
	}

	if len(response.Spaces) != 1 {
		t.Fatalf("decoded %d hints, want 1", len(response.Spaces))
	}
	if response.Spaces[0].Seq != 1 {
		t.Fatalf("decoded sequence %d, want 1", response.Spaces[0].Seq)
	}
}

func TestCompareHintsPrefersRelayWithPublishedSequence(t *testing.T) {
	withRecords := HintsResponse{
		AnchorTip: 958572,
		Spaces:    []SpaceHint{{Space: "@xn--tl8h", Seq: 1}},
	}
	empty := HintsResponse{AnchorTip: 958572}

	if CompareHints(withRecords, empty) <= 0 {
		t.Fatal("relay advertising the published sequence was not preferred")
	}
}
