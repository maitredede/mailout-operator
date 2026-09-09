// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// spoolFilePrefix names the transaction files, so that a sweep can tell ours
// from anything else sharing the directory.
const spoolFilePrefix = "mailout-body-"

// spool holds one message being processed. Small messages stay on the heap;
// past a threshold the body moves to a file, because the relay must not size
// its memory on what a client chooses to send.
//
// This is not a mail spool. There is no store-and-forward and no retry queue:
// the file exists for the length of one SMTP transaction, is never named in the
// directory (see newSpool), and cannot outlive the process. Delivery stays
// synchronous and the pod stays stateless.
type spool struct {
	dir       string
	threshold int64

	buf  bytes.Buffer
	file *os.File
	n    int64
}

func newSpoolFactory(limits Limits) func() *spool {
	dir, threshold := limits.SpoolDir, limits.SpoolThreshold
	return func() *spool { return &spool{dir: dir, threshold: threshold} }
}

// Write appends to the body, moving it to a file once the threshold is passed.
func (s *spool) Write(p []byte) (int, error) {
	if s.file == nil && s.n+int64(len(p)) > s.threshold {
		if err := s.overflow(); err != nil {
			return 0, err
		}
	}
	var (
		written int
		err     error
	)
	if s.file != nil {
		written, err = s.file.Write(p)
	} else {
		written, err = s.buf.Write(p)
	}
	s.n += int64(written)
	return written, err
}

// overflow moves what is already buffered to a file and switches to it.
//
// The file is unlinked as soon as it exists, while the descriptor stays open:
// the inode lives exactly as long as this spool does, and the kernel reclaims
// it when the process closes it — or dies, SIGKILL and OOMKill included. That
// is what makes an orphaned body impossible rather than merely swept up later.
func (s *spool) overflow() error {
	f, err := os.CreateTemp(s.dir, spoolFilePrefix+"*")
	if err != nil {
		return fmt.Errorf("spool to %s: %w", s.spoolDir(), err)
	}
	if err := os.Remove(f.Name()); err != nil {
		// Keeping a named file we cannot unlink would leak it on every message.
		_ = f.Close()
		return fmt.Errorf("unlink spool file: %w", err)
	}
	if _, err := f.Write(s.buf.Bytes()); err != nil {
		_ = f.Close()
		return fmt.Errorf("move body to spool: %w", err)
	}
	s.buf.Reset()
	s.file = f
	return nil
}

func (s *spool) spoolDir() string {
	if s.dir == "" {
		return os.TempDir()
	}
	return s.dir
}

// sibling is an empty spool with the same storage decisions, for a stage that
// writes a new body while reading the old one.
func (s *spool) sibling() *spool { return &spool{dir: s.dir, threshold: s.threshold} }

// spooled reports whether this body is on disk rather than on the heap.
func (s *spool) spooled() bool { return s.file != nil }

// Len is the size of the body so far.
func (s *spool) Len() int64 { return s.n }

// Reader reads the body from the start. The returned reader is valid until the
// next write or until Close.
func (s *spool) Reader() (io.Reader, error) {
	if s.file == nil {
		return bytes.NewReader(s.buf.Bytes()), nil
	}
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind spool: %w", err)
	}
	return s.file, nil
}

// ReaderAt reads from an offset, which is how the body is streamed past a
// header block that has already been parsed.
func (s *spool) ReaderAt(offset int64) (io.Reader, error) {
	if offset > s.n {
		offset = s.n
	}
	if s.file == nil {
		return bytes.NewReader(s.buf.Bytes()[offset:]), nil
	}
	if _, err := s.file.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek spool: %w", err)
	}
	return s.file, nil
}

// Bytes materializes the whole body on the heap.
//
// Every caller of this is a caller that has not been taught to stream, and on a
// spooled body it undoes what the spool is for. The milter stage is the one
// that still needs it; nothing else should grow a use.
//
// On a body still in memory the slice aliases the buffer, so it is only valid
// until the next write — copy it if it has to outlive that.
func (s *spool) Bytes() ([]byte, error) {
	if s.file == nil {
		return s.buf.Bytes(), nil
	}
	r, err := s.Reader()
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// maxHeaderBytes bounds how much of a body is read to find the end of the
// header block. A header block larger than this is not a message anyone sends;
// reading further would mean loading a spooled body onto the heap to answer a
// question about its first few kilobytes.
const maxHeaderBytes = 1024 * 1024

// headerBlock returns the header block, terminated by its blank line, without
// materializing the body.
//
// The second return value reports whether the block was actually terminated
// within maxHeaderBytes. A caller that makes a security decision on the headers
// must not treat an unterminated block as "no headers found" — that is how a
// sender policy gets skipped by a message with no blank line in its first
// megabyte.
func (s *spool) headerBlock() ([]byte, bool, error) {
	r, err := s.Reader()
	if err != nil {
		return nil, false, err
	}
	block, err := io.ReadAll(io.LimitReader(r, maxHeaderBytes))
	if err != nil {
		return nil, false, err
	}
	for _, sep := range [][]byte{[]byte("\r\n\r\n"), []byte("\n\n")} {
		if i := bytes.Index(block, sep); i >= 0 {
			return block[:i+len(sep)], true, nil
		}
	}
	return block, false, nil
}

// Reset replaces the body, keeping the same storage decision.
func (s *spool) Reset(data []byte) error {
	if s.file != nil {
		if err := s.file.Truncate(0); err != nil {
			return fmt.Errorf("truncate spool: %w", err)
		}
		if _, err := s.file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind spool: %w", err)
		}
		s.n = 0
		_, err := s.Write(data)
		return err
	}
	s.buf.Reset()
	s.n = 0
	_, err := s.Write(data)
	return err
}

// Close releases the body. It is safe to call more than once.
func (s *spool) Close() error {
	s.buf.Reset()
	if s.file == nil {
		return nil
	}
	f := s.file
	s.file = nil
	return f.Close()
}

// sweepSpool removes bodies left behind by a previous run of this process.
//
// Unlinking at creation makes this unnecessary in every ordinary case, which is
// the point of doing it that way. What is left is the crash between creating
// the file and unlinking it, and a container that restarts inside the same pod
// — an emptyDir outlives the process, not the pod. Cheap insurance, and it runs
// once at startup rather than on the path of a message.
func SweepSpool(dir string, log *slog.Logger) {
	if dir == "" {
		// Same resolution as a spool with no directory configured, so the sweep
		// looks where the bodies would actually have been written.
		dir = os.TempDir()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn("cannot sweep the spool directory", "dir", dir, "err", err)
		}
		return
	}
	var swept int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), spoolFilePrefix) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			log.Warn("cannot remove a leftover spool file", "file", entry.Name(), "err", err)
			continue
		}
		swept++
	}
	if swept > 0 {
		log.Info("removed spool files left by a previous run", "dir", dir, "count", swept)
	}
}

// probeSpool checks at startup that a body can actually be written, so that a
// directory that is missing or read-only is a refusal to start rather than a
// 451 on the first large message. The gateway's root filesystem is read-only,
// so this is a real failure mode and not a theoretical one.
func probeSpool(dir string) error {
	f, err := os.CreateTemp(dir, spoolFilePrefix+"probe-*")
	if err != nil {
		target := dir
		if target == "" {
			target = os.TempDir()
		}
		return fmt.Errorf("spool directory %s is not writable: %w", target, err)
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}
