package fabric

import (
	"context"
	"net/http"
	"testing"
	"time"

	libveritas "github.com/spacesprotocol/libveritas-go"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func digestWithByte(value byte) [32]byte { var digest [32]byte; digest[0] = value; return digest }

func TestReconcileSelectsHighestVerifiedSequence(t *testing.T) {
	zones, err := reconcileZoneCandidates([]zoneCandidate{
		{relay: "fast-stale", zone: libveritas.Zone{Handle: "@alice", Anchor: 4}, sequence: 4, digest: digestWithByte(4), verified: true},
		{relay: "slow-fresh", zone: libveritas.Zone{Handle: "@alice", Anchor: 9}, sequence: 9, digest: digestWithByte(9), verified: true},
		{relay: "invalid-high", zone: libveritas.Zone{Handle: "@alice", Anchor: 99}, sequence: 99, digest: digestWithByte(99), verified: false},
	})
	if err != nil || len(zones) != 1 || zones[0].Anchor != 9 {
		t.Fatalf("unexpected selection: %#v err=%v", zones, err)
	}
}

func TestReconcileTiePolicyAndVerifiedEmpty(t *testing.T) {
	digest := digestWithByte(7)
	if _, err := reconcileZoneCandidates([]zoneCandidate{
		{relay: "one", zone: libveritas.Zone{Handle: "@alice"}, sequence: 7, digest: digest, verified: true},
		{relay: "two", zone: libveritas.Zone{Handle: "@alice"}, sequence: 7, digest: digest, verified: true},
	}); err != nil {
		t.Fatalf("identical tie rejected: %v", err)
	}
	if _, err := reconcileZoneCandidates([]zoneCandidate{
		{relay: "one", zone: libveritas.Zone{Handle: "@alice"}, sequence: 7, digest: digestWithByte(1), verified: true},
		{relay: "two", zone: libveritas.Zone{Handle: "@alice"}, sequence: 7, digest: digestWithByte(2), verified: true},
	}); err == nil {
		t.Fatal("disagreeing tie did not fail closed")
	}
	zones, err := reconcileZoneCandidates([]zoneCandidate{
		{relay: "old", zone: libveritas.Zone{Handle: "@alice", Anchor: 4, Records: []byte{1}}, sequence: 4, digest: digestWithByte(4), verified: true},
		{relay: "cleared", zone: libveritas.Zone{Handle: "@alice", Anchor: 10}, sequence: 10, digest: digestWithByte(10), verified: true},
	})
	if err != nil || len(zones) != 1 || zones[0].Anchor != 10 {
		t.Fatalf("verified empty did not win: %#v err=%v", zones, err)
	}
}

func TestAllRelaysStaleRemainsUndetectable(t *testing.T) {
	digest := digestWithByte(3)
	zones, err := reconcileZoneCandidates([]zoneCandidate{
		{relay: "one", zone: libveritas.Zone{Handle: "@alice"}, sequence: 3, digest: digest, verified: true},
		{relay: "two", zone: libveritas.Zone{Handle: "@alice"}, sequence: 3, digest: digest, verified: true},
	})
	if err != nil || len(zones) != 1 {
		t.Fatalf("consistent stale boundary changed: %#v err=%v", zones, err)
	}
}

func TestRequestedHandlesAndExplicitSeeds(t *testing.T) {
	expected := requestedHandles(QueryRequest{Queries: []Query{{Space: "@alice"}}})
	if _, ok := expected["@alice"]; !ok {
		t.Fatal("requested handle missing")
	}
	if _, ok := expected["@bob"]; ok {
		t.Fatal("cross-handle substitution admitted")
	}
	relays := selectQueryRelays([]string{"https://one/", "https://two"}, []string{"https://random-1", "https://random-2", "https://random-3"}, 4)
	want := []string{"https://one", "https://two", "https://random-1", "https://random-2"}
	for index := range want {
		if relays[index] != want[index] {
			t.Fatalf("relay %d: got %q want %q", index, relays[index], want[index])
		}
	}
}

func TestFetchRelayResponsesHonorsDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	result := <-fetchRelayResponses(ctx, client, []string{"https://slow.test"}, []string{"@alice"}, nil)
	if result.err == nil {
		t.Fatal("slow relay was not cancelled")
	}
}
