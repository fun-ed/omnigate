package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type notifyingReader struct {
	reader  io.Reader
	started chan struct{}
	once    sync.Once
}

func (r *notifyingReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.reader.Read(p)
}

func TestGooglePromptCancellation(t *testing.T) {
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	reader := &notifyingReader{reader: input, started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := askGoogle(ctx, reader, io.Discard, "project?"); done <- err }()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("prompt did not block on stdin")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Ctrl-C cancellation left prompt blocked on stdin")
	}
}
func TestGooglePromptAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := askGoogle(ctx, nil, io.Discard, "project?")
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled setup should not try to read stdin")
	}
}
