/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"time"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// diagnosisStepCount is how many steps a test of a tunnel has, for showing progress.
const diagnosisStepCount = 5

// A tunnelDiagnosis is the latest test of a tunnel, while it runs and after.
type tunnelDiagnosis struct {
	running  bool
	steps    []manager.DiagnosisStep
	err      string
	finished time.Time
}

// diagnose tests a started tunnel in the manager. The test takes seconds, so it runs in a goroutine, and each
// step that finishes is shown as it comes.
func (model *appModel) diagnose(name string) {
	entry := model.entry(name)
	if entry == nil || entry.state != manager.TunnelStarted {
		return
	}
	if model.diagnoses == nil {
		model.diagnoses = make(map[string]*tunnelDiagnosis)
	}
	if current := model.diagnoses[name]; current != nil && current.running {
		return
	}
	diagnosis := &tunnelDiagnosis{running: true}
	model.diagnoses[name] = diagnosis
	model.notifyChanged()
	tunnel := entry.tunnel
	go func() {
		steps, err := tunnel.DiagnoseWithProgress(func(steps []manager.DiagnosisStep) {
			model.synchronize(func() {
				diagnosis.steps = steps
				model.notifyChanged()
			})
		})
		model.synchronize(func() {
			diagnosis.running, diagnosis.finished = false, time.Now()
			if err != nil {
				diagnosis.err = err.Error()
			} else {
				diagnosis.steps = steps
			}
			model.notifyChanged()
		})
	}()
}

// diagnosisLabel is what a step of a test checks, in plain words. Steps that this version does not know are
// labelled by their identifier.
func diagnosisLabel(id string) string {
	switch id {
	case manager.DiagnosisEndpointResolves:
		return l18n.Sprintf("The endpoint name resolves")
	case manager.DiagnosisHandshake:
		return l18n.Sprintf("The peer answers a handshake")
	case manager.DiagnosisPing:
		return l18n.Sprintf("Pings through the tunnel are answered")
	case manager.DiagnosisDNS:
		return l18n.Sprintf("DNS answers through the tunnel")
	case manager.DiagnosisEndpointRoute:
		return l18n.Sprintf("The endpoint is reached outside the tunnel")
	}
	return id
}

// diagnosisAdvice is the likely cause of a failed step and what to check, in one line, or nothing for a step this
// version does not know.
func diagnosisAdvice(id string) string {
	switch id {
	case manager.DiagnosisEndpointResolves:
		return l18n.Sprintf("Your network or its DNS is not working, or the name in the configuration is misspelled.")
	case manager.DiagnosisHandshake:
		return l18n.Sprintf("Check the endpoint and port, that the server runs, that both sides have each other's public key, and that no firewall blocks UDP.")
	case manager.DiagnosisPing:
		return l18n.Sprintf("The peer answers but traffic does not get through: check the allowed IPs on both sides, or choose an address that answers pings.")
	case manager.DiagnosisDNS:
		return l18n.Sprintf("Check the DNS servers of the tunnel, and that the server's allowed IPs for this device include them.")
	case manager.DiagnosisEndpointRoute:
		return l18n.Sprintf("The endpoint is only reachable through the tunnel itself. Check your network connection, or remove the endpoint's address from the allowed IPs.")
	}
	return ""
}

// outcomeMark draws a mark for how a step ended, in a 16x16 box: a check, a cross, or a dash for a skipped step.
func (s *scene) outcomeMark(outcome manager.DiagnosisOutcome, x, y float64) {
	switch outcome {
	case manager.DiagnosisPassed:
		s.fill(x, y, 16, 16, 8, theme.green)
		s.line(1.8, theme.greenInk, x+4.5, y+8.5, x+7, y+11, x+11.5, y+5.5)
	case manager.DiagnosisFailed:
		s.fill(x, y, 16, 16, 8, theme.red)
		s.line(1.8, theme.redInk, x+5, y+5, x+11, y+11)
		s.line(1.8, theme.redInk, x+11, y+5, x+5, y+11)
	default:
		s.stroke(x, y, 16, 16, 8, 1.5, theme.muted)
		s.line(1.8, theme.muted, x+5, y+8, x+11, y+8)
	}
}

// troubleshootingCard draws the test of a tunnel with its result, and the action that saves a diagnostics file,
// and returns its height.
func (mtw *ManageTunnelsWindow) troubleshootingCard(s *scene, x, y, w float64, entry *tunnelEntry, now time.Time) float64 {
	const pad, buttonHeight, markWidth = 16, 36, 26
	model, name := mtw.model, entry.tunnel.Name
	started := entry.state == manager.TunnelStarted
	diagnosis := model.diagnoses[name]
	textWidth := w - 2*pad
	stepWidth := textWidth - markWidth

	intro := l18n.Sprintf("Checks in order that the endpoint name resolves, the peer answers, pings and DNS get through the tunnel, and the endpoint is not routed into the tunnel. Only this tunnel's own addresses are contacted.")
	if !started {
		intro = l18n.Sprintf("Testing needs the tunnel to be active. A diagnostics file can be saved at any time.")
	}
	introHeight := s.wrappedHeight(intro, fontSmall, textWidth)

	// The heights of the step rows are measured first, as the panel is drawn before them.
	type stepLayout struct {
		label, detail, advice                   string
		labelHeight, detailHeight, adviceHeight float64
	}
	var steps []stepLayout
	status, statusColor := "", theme.textDim
	if diagnosis != nil {
		for _, step := range diagnosis.steps {
			layout := stepLayout{label: diagnosisLabel(step.ID), detail: step.Detail}
			if step.Outcome == manager.DiagnosisFailed {
				layout.advice = diagnosisAdvice(step.ID)
			}
			layout.labelHeight = max(s.wrappedHeight(layout.label, fontBodyBold, stepWidth), 20)
			if len(layout.detail) > 0 {
				layout.detailHeight = s.wrappedHeight(layout.detail, fontSmall, stepWidth)
			}
			if len(layout.advice) > 0 {
				layout.adviceHeight = s.wrappedHeight(layout.advice, fontSmall, stepWidth)
			}
			steps = append(steps, layout)
		}
		switch {
		case diagnosis.running:
			status = l18n.Sprintf("Testing… step %d of %d", min(len(diagnosis.steps)+1, diagnosisStepCount), diagnosisStepCount)
		case len(diagnosis.err) > 0:
			status, statusColor = diagnosis.err, theme.redSoft
		default:
			failed := 0
			for _, step := range diagnosis.steps {
				if step.Outcome == manager.DiagnosisFailed {
					failed++
				}
			}
			status = l18n.Sprintf("Tested %s · all checks passed", formatAgo(now.Sub(diagnosis.finished)))
			if failed > 0 {
				status, statusColor = l18n.Sprintf("Tested %s · %d of %d checks failed", formatAgo(now.Sub(diagnosis.finished)), failed, len(diagnosis.steps)), theme.amberSoft
			}
		}
	}
	statusHeight, statusIndent := 0.0, 0.0
	if diagnosis != nil && diagnosis.running {
		statusIndent = 18
	}
	if len(status) > 0 {
		statusHeight = s.wrappedHeight(status, fontBody, textWidth-statusIndent) + 10
	}
	height := pad + 16 + 10 + introHeight + 12 + buttonHeight + pad
	if statusHeight > 0 {
		height += 12 + statusHeight
	}
	for _, step := range steps {
		height += 10 + step.labelHeight
		if step.detailHeight > 0 {
			height += 2 + step.detailHeight
		}
		if step.adviceHeight > 0 {
			height += 4 + step.adviceHeight
		}
	}

	s.fill(x, y, w, height, 8, theme.panel)
	s.label(l18n.Sprintf("TROUBLESHOOTING"), fontCaps, theme.textDim, x+pad, y+pad, w-2*pad, 16, textLeft)
	rowY := y + pad + 16 + 10
	s.text(intro, fontSmall, theme.textDim, x+pad, rowY, textWidth, introHeight, textWrap)
	rowY += introHeight + 12

	buttonWidth := (textWidth - 8) / 2
	testStyle := buttonOutline
	if !started || diagnosis != nil && diagnosis.running {
		testStyle = buttonDisabled
	}
	s.button("diagnose", x+pad, rowY, buttonWidth, buttonHeight, l18n.Sprintf("Test this tunnel"), testStyle, func() { model.diagnose(name) })
	s.button("diagnostics-save", x+pad+buttonWidth+8, rowY, buttonWidth, buttonHeight, l18n.Sprintf("Save diagnostics…"), buttonOutline, func() { model.saveDiagnostics(mtw, name) })
	rowY += buttonHeight

	if statusHeight > 0 {
		rowY += 12
		statusX := x + pad + statusIndent
		if statusIndent > 0 {
			// A dot that breathes while the test runs, as the ring of the status screen does while switching.
			s.fill(x+pad+2, rowY+5, 10, 10, 5, mix(theme.textDim, theme.panel, 0.7*s.pulse(busyPulsePeriod)))
		}
		s.text(status, fontBody, statusColor, statusX, rowY, x+w-pad-statusX, statusHeight-10, textWrap)
		rowY += statusHeight - 10
	}
	for i, step := range steps {
		rowY += 10
		s.outcomeMark(diagnosis.steps[i].Outcome, x+pad, rowY+2)
		textX := x + pad + markWidth
		s.text(step.label, fontBodyBold, theme.text, textX, rowY, stepWidth, step.labelHeight, textWrap)
		rowY += step.labelHeight
		if step.detailHeight > 0 {
			rowY += 2
			s.text(step.detail, fontSmall, theme.textDim, textX, rowY, stepWidth, step.detailHeight, textWrap)
			rowY += step.detailHeight
		}
		if step.adviceHeight > 0 {
			rowY += 4
			s.text(step.advice, fontSmall, theme.amberSoft, textX, rowY, stepWidth, step.adviceHeight, textWrap)
			rowY += step.adviceHeight
		}
	}
	return height
}
