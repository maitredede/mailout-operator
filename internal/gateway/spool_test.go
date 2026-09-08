// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
)

// bodyOf builds a message body for a test, on the heap.
func bodyOf(t *testing.T, data []byte) *spool {
	t.Helper()
	s := &spool{threshold: int64(len(data)) + 1}
	if _, err := s.Write(data); err != nil {
		t.Fatalf("write body: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// bytesOf reads a message body back for an assertion.
func bytesOf(t *testing.T, msg *Message) []byte {
	t.Helper()
	data, err := msg.Body.Bytes()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return data
}

// Below the threshold the body stays on the heap; above it, it moves to a file.
// The threshold is the whole point: a small message must not pay for a syscall,
// and a large one must not be sized by the client.
func TestSpoolMovesToDiskPastTheThreshold(t *testing.T) {
	dir := t.TempDir()
	newSpool := newSpoolFactory(Limits{SpoolDir: dir, SpoolThreshold: 1024})

	small := newSpool()
	t.Cleanup(func() { _ = small.Close() })
	if _, err := small.Write(make([]byte, 512)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if small.spooled() {
		t.Error("a 512 byte body went to disk")
	}

	large := newSpool()
	t.Cleanup(func() { _ = large.Close() })
	if _, err := large.Write(make([]byte, 4096)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !large.spooled() {
		t.Error("a 4 KiB body stayed in memory past a 1 KiB threshold")
	}
	if large.Len() != 4096 {
		t.Errorf("Len = %d, want 4096", large.Len())
	}
}

// The file is unlinked as soon as it is created, so an orphan is impossible
// rather than swept up later: the kernel reclaims the inode when the descriptor
// closes, SIGKILL and OOMKill included.
func TestSpoolFileIsNeverVisibleInTheDirectory(t *testing.T) {
	dir := t.TempDir()
	s := newSpoolFactory(Limits{SpoolDir: dir, SpoolThreshold: 16})()

	if _, err := s.Write([]byte(strings.Repeat("x", 4096))); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !s.spooled() {
		t.Fatal("the body did not spool")
	}

	// While the body is in use and readable, nothing names it on disk.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, entry := range entries {
		t.Errorf("%s is visible in the spool directory, so a crash would leave it behind",
			filepath.Join(dir, entry.Name()))
	}

	r, err := s.Reader()
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(data) != 4096 {
		t.Errorf("read back %d bytes, want 4096", len(data))
	}
	if err := s.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// The sweep is insurance for the one case unlinking cannot cover: a container
// restarting inside the same pod, where the emptyDir outlives the process.
func TestSweepSpoolRemovesOnlyOurLeftovers(t *testing.T) {
	dir := t.TempDir()
	ours := filepath.Join(dir, spoolFilePrefix+"leftover")
	theirs := filepath.Join(dir, "someone-elses-file")
	for _, name := range []string{ours, theirs} {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	SweepSpool(dir, testLogger())

	if _, err := os.Stat(ours); !os.IsNotExist(err) {
		t.Error("our leftover survived the sweep")
	}
	if _, err := os.Stat(theirs); err != nil {
		t.Error("the sweep removed a file that is not ours")
	}
}

// A directory that cannot be written must stop the gateway at startup, not
// produce a 451 on the first large message: the container's root filesystem is
// read-only, so a missing volume is a real failure mode.
func TestProbeSpoolRefusesAnUnwritableDirectory(t *testing.T) {
	if err := probeSpool(t.TempDir()); err != nil {
		t.Fatalf("a writable directory should probe clean: %v", err)
	}
	if err := probeSpool(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("a missing spool directory was accepted")
	}
}

// The regression that matters: a large message must relay intact, and must not
// cost the heap its own size. Before the body was spooled, each stage of the
// pipeline kept a full copy — a 20 MiB message drove the heap to 120 MiB, so
// eight parallel submissions were enough to have the pod OOMKilled and take the
// relay down for every tenant.
func TestLargeMessageRelaysWithoutSizingTheHeap(t *testing.T) {
	const bodySize = 20 << 20

	gw := newTestGateway(t, func(cfg *Config) {
		cfg.Limits.SpoolDir = t.TempDir()
		cfg.Limits.SpoolThreshold = 1 << 20
	})
	// The upstream discards rather than buffering: otherwise this side of the
	// connection holds 20 MiB in the same process and the measurement below
	// says nothing about the gateway.
	gw.upstream.mu.Lock()
	gw.upstream.discardBody = true
	gw.upstream.mu.Unlock()

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	// Generated as a stream rather than built as a string: a 20 MiB string in
	// this process would be counted by the measurement below and hide whatever
	// the gateway itself is doing.
	source := io.MultiReader(
		strings.NewReader("Subject: big\r\n\r\n"),
		io.LimitReader(&lineReader{}, bodySize),
	)
	if err := c.SendMail("app@example.test", []string{"dest@example.test"}, source); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	runtime.ReadMemStats(&after)
	// Generous on purpose: the claim is not a precise figure but that the body
	// is not on the heap at all. Half the message size still fails hard on any
	// stage that keeps a full copy.
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > bodySize/2 {
		t.Errorf("the heap grew by %d bytes for a %d byte message, so a stage is still buffering it",
			grew, bodySize)
	}

	received := gw.upstream.received()
	if len(received) != 1 {
		t.Fatalf("upstream received %d messages, want 1", len(received))
	}
	gw.upstream.mu.Lock()
	seen := gw.upstream.bytesSeen
	gw.upstream.mu.Unlock()
	// Received header included, so at least the body: this is what proves the
	// streaming path did not truncate anything.
	if seen < bodySize {
		t.Errorf("upstream saw %d bytes, want at least %d", seen, bodySize)
	}

	if got := counter(t, gw, "mailout_messages_spooled_total",
		map[string]string{"account": testAccount}); got != 1 {
		t.Errorf("spooled messages = %v, want 1", got)
	}
}

// lineReader yields wrapped lines forever without allocating them: go-smtp
// refuses a line longer than 2000 bytes, so a single enormous line would be
// rejected rather than relayed.
type lineReader struct{ offset int }

func (r *lineReader) Read(p []byte) (int, error) {
	const line = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n"
	for i := range p {
		p[i] = line[r.offset%len(line)]
		r.offset++
	}
	return len(p), nil
}

// go-smtp has no connection limit of its own, so without one the pod's memory
// and CPU are sized by whoever connects: 400 idle connections were accepted
// before this, and eight parallel large submissions were enough to OOM the pod.
func TestConnectionsBeyondTheLimitAreNotServed(t *testing.T) {
	gw := newTestGateway(t, func(cfg *Config) { cfg.Limits.MaxConnections = 1 })

	// The first connection takes the only slot and holds it.
	first, err := net.Dial("tcp", gw.submissionAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer first.Close()
	if _, err := readGreeting(first); err != nil {
		t.Fatalf("the first connection got no greeting: %v", err)
	}

	// The second is accepted by the kernel but never served, so no banner comes.
	second, err := net.Dial("tcp", gw.submissionAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer second.Close()
	if line, err := readGreeting(second); err == nil {
		t.Errorf("a connection past the limit was served: %q", line)
	}

	// Releasing the slot lets it through, so the limit queues rather than
	// refuses — which is what a mail client handles best.
	_ = first.Close()
	if _, err := readGreeting(second); err != nil {
		t.Errorf("the queued connection was never served after a slot freed: %v", err)
	}
}

// readGreeting waits briefly for an SMTP banner.
func readGreeting(c net.Conn) (string, error) {
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	return line, err
}

// go-smtp's default line limit of 2000 applies during DATA too, so any long
// body line made a message undeliverable — unwrapped HTML or a long References
// header is enough. Found by accident while writing the spool test above.
func TestLongBodyLineIsRelayed(t *testing.T) {
	gw := newTestGateway(t)
	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	// Longer than go-smtp's default, shorter than ours.
	body := "Subject: long\r\n\r\n" + strings.Repeat("x", 4000) + "\r\n"
	if err := c.SendMail("app@example.test", []string{"dest@example.test"}, strings.NewReader(body)); err != nil {
		t.Fatalf("a 4000 byte body line was refused: %v", err)
	}
	if received := gw.upstream.received(); len(received) != 1 {
		t.Fatalf("upstream received %d messages, want 1", len(received))
	}
}
