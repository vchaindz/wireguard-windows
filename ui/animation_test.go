/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"image"
	"math"
	"testing"
	"time"

	"github.com/lxn/win"

	"golang.zx2c4.com/wireguard/windows/manager"
)

func TestAnimateWithoutAnimator(t *testing.T) {
	s := &scene{}
	if v := s.animate("a", 0.25); v != 0.25 {
		t.Errorf("animate without an animator: %v, want the target", v)
	}
	if v := s.animateFrom("b", 0, 1); v != 1 {
		t.Errorf("animateFrom without an animator: %v, want the target", v)
	}
	if v := s.pulse(time.Second); v != 0 {
		t.Errorf("pulse without an animator: %v, want 0", v)
	}
}

func TestAnimatorEasesTowardsTarget(t *testing.T) {
	a := newAnimator()
	s := &scene{anim: a}
	t0 := time.Now()

	a.beginFrame(t0, true)
	if v := s.animate("x", 0); v != 0 || a.moving {
		t.Fatalf("first sight: %v, moving %v; want the target and nothing moving", v, a.moving)
	}
	a.endFrame()

	a.beginFrame(t0.Add(time.Millisecond), true)
	if v := s.animate("x", 1); v <= 0 || v > 0.5 || !a.moving {
		t.Errorf("start of a change: %v, moving %v", v, a.moving)
	}
	a.endFrame()

	a.beginFrame(t0.Add(time.Millisecond+animationDuration/2), true)
	if v := s.animate("x", 1); v < 0.8 || v >= 1 || !a.moving {
		t.Errorf("halfway, eased out: %v, moving %v; want well past the middle", v, a.moving)
	}
	a.endFrame()

	a.beginFrame(t0.Add(time.Millisecond+animationDuration), true)
	if v := s.animate("x", 1); v != 1 || a.moving {
		t.Errorf("at the end: %v, moving %v", v, a.moving)
	}
	a.endFrame()

	// Changing direction halfway starts from where the value is.
	a.beginFrame(t0.Add(time.Second), true)
	s.animate("x", 0)
	a.endFrame()
	a.beginFrame(t0.Add(time.Second+animationDuration/2), true)
	middle := s.animate("x", 0)
	a.endFrame()
	a.beginFrame(t0.Add(time.Second+animationDuration/2+time.Millisecond), true)
	// It moves on by about one frame of an eased-out start, not back to an end.
	if v := s.animate("x", 1); v < middle || v-middle > 0.35 {
		t.Errorf("turning around: jumped from %v to %v", middle, v)
	}
	a.endFrame()

	// A value that a frame does not use is forgotten and starts at its target when it comes back.
	a.beginFrame(t0.Add(2*time.Second), true)
	a.endFrame()
	if a.known("x") {
		t.Error("an unused value is kept")
	}
}

func TestAnimatorRespectsSetting(t *testing.T) {
	a := newAnimator()
	s := &scene{anim: a}
	t0 := time.Now()
	a.beginFrame(t0, false)
	s.animate("x", 0)
	a.endFrame()
	a.beginFrame(t0.Add(time.Millisecond), false)
	if v := s.animate("x", 1); v != 1 || a.moving {
		t.Errorf("animations off: %v, moving %v; want a jump", v, a.moving)
	}
	if v := s.animateFrom("y", 0, 1); v != 1 {
		t.Errorf("animations off, growing: %v, want a jump", v)
	}
	if v := s.pulse(time.Second); v != 0 || a.moving {
		t.Errorf("animations off, pulse: %v, moving %v", v, a.moving)
	}
}

func TestPulseRepeats(t *testing.T) {
	a := newAnimator()
	s := &scene{anim: a}
	const period = time.Second
	for _, c := range []struct {
		at   time.Duration
		want float64
	}{{0, 0}, {period / 4, 0.5}, {period / 2, 1}, {period, 0}, {period * 5 / 2, 1}} {
		a.beginFrame(a.epoch.Add(c.at), true)
		if v := s.pulse(period); math.Abs(v-c.want) > 1e-9 || !a.moving {
			t.Errorf("at %v: %v, moving %v; want %v", c.at, v, a.moving, c.want)
		}
	}
}

func TestMix(t *testing.T) {
	for _, c := range []struct {
		a, b rgb
		t    float64
		want rgb
	}{
		{0x000000, 0xFFFFFF, 0, 0x000000},
		{0x000000, 0xFFFFFF, 1, 0xFFFFFF},
		{0x000000, 0xFFFFFF, 0.5, 0x808080},
		{0x102030, 0x302010, 0.5, 0x202020},
		{0x3DDC97, 0x7C8792, -1, 0x3DDC97},
		{0x3DDC97, 0x7C8792, 2, 0x7C8792},
	} {
		if got := mix(c.a, c.b, c.t); got != c.want {
			t.Errorf("mix(%06X, %06X, %v) = %06X, want %06X", c.a, c.b, c.t, got, c.want)
		}
	}
}

// buildFrame builds a scene as a view does when it paints, with an animator and real text measurement.
func buildFrame(width, height float64, anim *animator, now time.Time, build func(s *scene, width, height float64)) *scene {
	measureHDC := win.CreateCompatibleDC(0)
	defer win.DeleteDC(measureHDC)
	anim.beginFrame(now, true)
	s := &scene{anim: anim}
	s.measure = func(text string, font themeFont, width float64) float64 {
		return measureWrapped(measureHDC, 96, text, font, width)
	}
	s.lineWidth = func(text string, font themeFont) float64 {
		return measureLine(measureHDC, 96, text, font)
	}
	build(s, width, height)
	anim.endFrame()
	return s
}

// A frame in which only a switch moves must redraw only the switch, not the screen around it.
func TestAnimatingToggleRedrawsOnlyToggle(t *testing.T) {
	wasAdmin := IsAdmin
	IsAdmin = true
	defer func() { IsAdmin = wasAdmin }()

	office := tunnelEntry{tunnel: manager.Tunnel{Name: "office"}, state: manager.TunnelStopped, settingsLoaded: true, probingAllowed: true}
	office.config = sampleConfig("office", "10.8.0.2/24", 0, 0, 0)
	mtw := &ManageTunnelsWindow{model: &appModel{entries: []tunnelEntry{office}, globalState: manager.TunnelStopped}, screen: screenDetails, detailsName: "office"}
	const width, height = 524, 820
	anim := newAnimator()
	cv := &canvasView{}
	t0 := time.Now()

	first := buildFrame(width, height, anim, t0, mtw.buildDetails)
	if dirty := cv.updateFrame(first, width, height, 1); dirty != image.Rect(0, 0, width, height) {
		t.Fatalf("first frame drew %v, want everything", dirty)
	}
	if dirty := cv.updateFrame(buildFrame(width, height, anim, t0.Add(16*time.Millisecond), mtw.buildDetails), width, height, 1); !dirty.Empty() {
		t.Errorf("a frame without change drew %v", dirty)
	}

	mtw.model.entries[0].settings.Probe = true
	moving := buildFrame(width, height, anim, t0.Add(32*time.Millisecond), mtw.buildDetails)
	if !anim.moving {
		t.Fatal("switching the toggle does not animate")
	}
	hit := moving.hitByID("probe")
	if hit == nil {
		t.Fatal("no toggle on the details screen")
	}
	dirty := cv.updateFrame(moving, width, height, 1)
	around := image.Rect(int(hit.rect.x), int(hit.rect.y), int(math.Ceil(hit.rect.x+hit.rect.w)), int(math.Ceil(hit.rect.y+hit.rect.h)))
	if dirty.Empty() || !dirty.In(around) {
		t.Errorf("animating toggle drew %v, want a part of %v", dirty, around)
	}

	mid := buildFrame(width, height, anim, t0.Add(32*time.Millisecond+animationDuration/2), mtw.buildDetails)
	if dirty := cv.updateFrame(mid, width, height, 1); dirty.Empty() || !dirty.In(around) {
		t.Errorf("halfway, the toggle drew %v, want a part of %v", dirty, around)
	}
	settled := buildFrame(width, height, anim, t0.Add(time.Second), mtw.buildDetails)
	if anim.moving {
		t.Error("the toggle is still moving after its animation")
	}
	cv.updateFrame(settled, width, height, 1)
	if dirty := cv.updateFrame(buildFrame(width, height, anim, t0.Add(2*time.Second), mtw.buildDetails), width, height, 1); !dirty.Empty() {
		t.Errorf("a settled frame drew %v", dirty)
	}
}

// Hovering a button fades it in without changing the number of shapes, so that only the button is redrawn.
func TestHoverFadeRedrawsOnlyButton(t *testing.T) {
	anim := newAnimator()
	cv := &canvasView{}
	hot := ""
	build := func(s *scene, width, height float64) {
		s.hot = hot
		s.fill(0, 0, width, 40, 0, theme.panel)
		s.button("a", 20, 60, 120, 44, "First", buttonOutline, func() {})
		s.button("b", 160, 60, 120, 44, "Second", buttonGreen, func() {})
	}
	t0 := time.Now()
	cv.updateFrame(buildFrame(300, 200, anim, t0, build), 300, 200, 1)
	hot = "a"
	s := buildFrame(300, 200, anim, t0.Add(40*time.Millisecond), build)
	if !anim.moving {
		t.Fatal("hovering does not fade")
	}
	if dirty := cv.updateFrame(s, 300, 200, 1); dirty.Empty() || !dirty.In(image.Rect(18, 58, 142, 106)) {
		t.Errorf("hover fade drew %v", dirty)
	}
}
