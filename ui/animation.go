/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"math"
	"time"
	"unsafe"

	"github.com/lxn/win"
)

// Animation in the drawing layer. A scene asks for a value by id and gets it on its way to a target; the view
// that builds the scene keeps the values between frames and repaints while any of them moves. A scene without
// an animator, as in tests, gets every value at its target, so that what it draws is always the same.

const (
	// animationDuration is how long a value takes to reach a new target.
	animationDuration = 150 * time.Millisecond
	// animationFrame is how often a view repaints while something moves, about sixty times a second.
	animationFrame = 16 * time.Millisecond
)

type animatedValue struct {
	from, to float64
	start    time.Time
}

// An animator holds the animated values of one view between frames.
type animator struct {
	// now is the time of the frame being built.
	now time.Time
	// enabled is false when Windows is told not to animate, and values then jump to their targets.
	enabled bool
	// moving is set while building a frame if some value has not arrived yet, or something repeats.
	moving bool
	values map[string]*animatedValue
	// seen holds the ids used by the frame being built. Values that a frame no longer uses are forgotten, so
	// that a region that comes back, as on another screen, starts at its target again.
	seen map[string]bool
	// epoch is when the animator was made; repeating values count from it.
	epoch time.Time
}

func newAnimator() *animator {
	return &animator{values: make(map[string]*animatedValue), seen: make(map[string]bool), epoch: time.Now(), enabled: true}
}

// beginFrame starts a frame at a time.
func (a *animator) beginFrame(now time.Time, enabled bool) {
	a.now, a.enabled, a.moving = now, enabled, false
	clear(a.seen)
}

// endFrame forgets the values that the frame did not use.
func (a *animator) endFrame() {
	for id := range a.values {
		if !a.seen[id] {
			delete(a.values, id)
		}
	}
}

// known reports whether a value was used by an earlier frame and is still kept.
func (a *animator) known(id string) bool {
	_, ok := a.values[id]
	return ok
}

// current is where a value is at the time of the frame, eased out: fast at first, slowing down as it arrives.
func (a *animator) current(v *animatedValue) float64 {
	t := float64(a.now.Sub(v.start)) / float64(animationDuration)
	if t >= 1 || !a.enabled || v.from == v.to {
		return v.to
	}
	if t < 0 {
		t = 0
	}
	a.moving = true
	ease := 1 - math.Pow(1-t, 3)
	return v.from + (v.to-v.from)*ease
}

// value moves the value of an id towards a target. A value seen for the first time starts at from.
//
// A movement is taken to have begun one frame before the frame that asks for it, so that the frame which
// follows a click already shows the start of the change instead of the state before it.
func (a *animator) value(id string, from, target float64) float64 {
	a.seen[id] = true
	v := a.values[id]
	start := a.now.Add(-animationFrame)
	if v == nil {
		v = &animatedValue{from: from, to: target, start: start}
		if !a.enabled {
			v.from = target
		}
		a.values[id] = v
		return a.current(v)
	}
	if v.to != target {
		v.from, v.to, v.start = a.current(v), target, start
	}
	return a.current(v)
}

// animate returns the value of an id on its way to a target. The first time an id is seen it is at its target
// at once, so that the first frame of a screen does not move.
func (s *scene) animate(id string, target float64) float64 {
	if s.anim == nil {
		return target
	}
	return s.anim.value(id, target, target)
}

// animateFrom is like animate, but an id seen for the first time starts at from, for things that should grow
// into view when they appear.
func (s *scene) animateFrom(id string, from, target float64) float64 {
	if s.anim == nil {
		return target
	}
	return s.anim.value(id, from, target)
}

// animationKnown reports whether an id was animated in an earlier frame of the view.
func (s *scene) animationKnown(id string) bool {
	return s.anim != nil && s.anim.known(id)
}

// pulse is a value that swings between 0 and 1 and back once a period, smoothly, for as long as the scene asks
// for it. It is 0 without an animator or when animations are off.
func (s *scene) pulse(period time.Duration) float64 {
	if s.anim == nil || !s.anim.enabled || period <= 0 {
		return 0
	}
	s.anim.moving = true
	phase := float64(s.anim.now.Sub(s.anim.epoch)%period) / float64(period)
	return (1 - math.Cos(2*math.Pi*phase)) / 2
}

// hoverAmount is how far the hover look of a region has faded in: 1 while the mouse is over it, 0 when not.
func (s *scene) hoverAmount(id string, hot bool) float64 {
	target := 0.0
	if hot {
		target = 1
	}
	return s.animate("hover:"+id, target)
}

// mix blends two colors: 0 gives a, 1 gives b.
func mix(a, b rgb, t float64) rgb {
	t = clamp01(t)
	channel := func(shift uint) rgb {
		ca, cb := float64(byte(a>>shift)), float64(byte(b>>shift))
		return rgb(math.Round(ca+(cb-ca)*t)) << shift
	}
	return channel(16) | channel(8) | channel(0)
}

// lerp is the number between a and b at t.
func lerp(a, b, t float64) float64 {
	return a + (b-a)*t
}

const spiGetClientAreaAnimation = 0x1042

// animationsEnabled reports whether Windows is set to show animations in windows. It is read for every frame
// that animates, which is cheap, so that a change of the setting takes effect at once.
func animationsEnabled() bool {
	var enabled int32 = 1
	if !win.SystemParametersInfo(spiGetClientAreaAnimation, 0, unsafe.Pointer(&enabled), 0) {
		return true
	}
	return enabled != 0
}
