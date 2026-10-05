package api

import (
	"bytes"
	"os/exec"
)

func runCgWithProgressCapture(cmd *exec.Cmd, sendProgress func(string)) (output []byte, logs []byte, err error) {
	var stdout bytes.Buffer
	stderr := progressCapture{sendProgress: sendProgress}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Let os/exec drain both streams while waiting, so WaitDelay also closes
	// pipes inherited by descendants after the scanner exits or is cancelled.
	err = cmd.Run()
	stderr.flush()
	return stdout.Bytes(), stderr.logs.Bytes(), err
}

type progressCapture struct {
	logs         bytes.Buffer
	pending      []byte
	sendProgress func(string)
}

func (p *progressCapture) Write(data []byte) (int, error) {
	n, err := p.logs.Write(data)
	if p.sendProgress == nil {
		return n, err
	}
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			p.pending = append(p.pending, data...)
			break
		}
		p.pending = append(p.pending, data[:i]...)
		p.emit()
		data = data[i+1:]
	}
	return n, err
}

func (p *progressCapture) emit() {
	line := p.pending
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	p.sendProgress(string(line))
	p.pending = p.pending[:0]
}

func (p *progressCapture) flush() {
	if len(p.pending) > 0 {
		p.emit()
	}
}
