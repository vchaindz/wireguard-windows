/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/draw"
	"image/png"
	"math"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// The tray icon tells the state of the tunnels at a glance: the logo in grey when none is active, and the logo
// with a mark in its corner otherwise. It is drawn for the exact size the taskbar asks for, as one bitmap scaled
// to another size turns blurry at the sizes of tray icons.

// A trayState is what the tray icon shows. The states are ordered by how much they need attention, so that the
// icon can show the worst of several tunnels.
type trayState int

const (
	trayOff       trayState = iota // no tunnel is active
	trayConnected                  // tunnels are active and their peers answer
	trayBusy                       // a tunnel is being activated or deactivated
	trayProblem                    // a tunnel is active but its connection is missing, unstable or poor
	trayCutOff                     // a tunnel takes over all traffic, but its peer does not answer
	trayStateCount
)

// trayStateOf is what the tray shows for one tunnel.
func trayStateOf(entry *tunnelEntry, samples tunnelSamples) trayState {
	switch entry.state {
	case manager.TunnelStarting, manager.TunnelStopping:
		return trayBusy
	case manager.TunnelStarted:
	default:
		return trayOff
	}
	switch {
	case entry.health == manager.TunnelHealthNoConnectionNetworkBlocked:
		return trayCutOff
	case entry.health.IsNoConnection(), entry.conflictSuspected, entry.unstable:
		return trayProblem
	case entry.health == manager.TunnelHealthConnected && summarizeQuality(samples.seconds).poor():
		return trayProblem
	}
	return trayConnected
}

// trayState is the worst state among the tunnels, with the tunnel that has it, the first by name among equals.
// It returns trayOff and nil when no tunnel is active.
func (model *appModel) trayState() (trayState, *tunnelEntry) {
	worst, which := trayOff, (*tunnelEntry)(nil)
	for i := range model.entries {
		entry := &model.entries[i]
		if state := trayStateOf(entry, model.samples[entry.tunnel.Name]); state > worst {
			worst, which = state, entry
		}
	}
	return worst, which
}

// trayToolTipLimit is how many UTF-16 units a tooltip of a tray icon holds, without its terminating zero.
const trayToolTipLimit = 127

// trayToolTip says what the tray icon shows, in up to three lines: the state, the tunnel with how long it has
// been connected, and its current rates when they are known.
func (model *appModel) trayToolTip(now time.Time) string {
	state, entry := model.trayState()
	if entry == nil {
		return l18n.Sprintf("WireGuard: %s", l18n.Sprintf("Not connected"))
	}
	look := lookFor(entry)
	title := look.title
	if state == trayProblem && entry.health == manager.TunnelHealthConnected {
		// The state of the tunnel says connected; the problem is told on the second line.
		if warning, _ := connectionWarning(entry); len(warning) > 0 {
			title = warning
		} else if entry.unstable {
			title = l18n.Sprintf("Unstable connection")
		} else {
			title = l18n.Sprintf("Poor connection quality")
		}
	}
	lines := []string{l18n.Sprintf("WireGuard: %s", title)}

	name := entry.tunnel.Name
	if others := model.activeCount() - 1; others > 0 {
		name = l18n.Sprintf("%s (+%d)", name, others)
	}
	if entry.state == manager.TunnelStarted && !entry.metrics.ConnectedSince.IsZero() {
		lines = append(lines, l18n.Sprintf("%s · connected for %s", name, formatDuration(now.Sub(entry.metrics.ConnectedSince))))
	} else {
		lines = append(lines, name)
	}

	if entry.state == manager.TunnelStarted {
		if samples := model.samples[entry.tunnel.Name].seconds; len(samples) > 0 && now.Sub(samples[len(samples)-1].Time) < 15*time.Second {
			rate := currentRate(samples)
			lines = append(lines, l18n.Sprintf("In %s · Out %s", formatRate(rate.rx), formatRate(rate.tx)))
		}
	}
	return limitUTF16(strings.Join(lines, "\n"), trayToolTipLimit)
}

// activeCount is how many tunnels are active or being switched.
func (model *appModel) activeCount() int {
	count := 0
	for i := range model.entries {
		if model.entries[i].active() {
			count++
		}
	}
	return count
}

// limitUTF16 cuts a text to a number of UTF-16 units, ending it with an ellipsis if it had to be cut.
func limitUTF16(text string, limit int) string {
	if len(utf16.Encode([]rune(text))) <= limit {
		return text
	}
	units := 0
	for i, r := range text {
		units += utf16.RuneLen(r)
		if units > limit-1 {
			return text[:i] + "…"
		}
	}
	return text
}

// Drawing

// trayMark draws the mark of a state into a scene in pixels, in the corner of an icon of a size. It reports where
// the mark is, as a circle, so that the logo can be cut away around it.
func trayMark(s *scene, state trayState, size float64) (cx, cy, radius float64) {
	diameter := size * 0.5625
	stateMark(s, state, size-diameter, size-diameter, diameter)
	return size - diameter/2, size - diameter/2, diameter / 2
}

// stateMark draws the mark of a state as a disc of a diameter. Besides their colors, the marks differ in what is
// drawn on them, so that they can be told apart without seeing colors.
func stateMark(s *scene, state trayState, x, y, diameter float64) {
	cx, cy, radius := x+diameter/2, y+diameter/2, diameter/2
	line := math.Max(diameter*0.16, 1.2)
	switch state {
	case trayConnected:
		s.fill(x, y, diameter, diameter, radius, darkPalette.green)
		s.line(line, darkPalette.greenInk, x+diameter*0.27, y+diameter*0.52, x+diameter*0.44, y+diameter*0.68, x+diameter*0.74, y+diameter*0.35)
	case trayBusy:
		// A ring with a hollow middle, the shape of something under way.
		s.fill(x, y, diameter, diameter, radius, darkPalette.textDim)
		inner := diameter * 0.42
		s.fill(cx-inner/2, cy-inner/2, inner, inner, inner/2, darkPalette.panel)
	case trayProblem:
		s.fill(x, y, diameter, diameter, radius, darkPalette.amber)
		s.line(line, darkPalette.amberInk, cx, y+diameter*0.24, cx, y+diameter*0.56)
		dot := line * 1.15
		s.fill(cx-dot/2, y+diameter*0.68, dot, dot, dot/2, darkPalette.amberInk)
	case trayCutOff:
		// A bar across, as on a no-entry sign.
		s.fill(x, y, diameter, diameter, radius, darkPalette.red)
		s.line(line*1.1, darkPalette.redInk, x+diameter*0.27, cy, x+diameter*0.73, cy)
	}
}

// overlayImage is the mark of a state alone, filling an icon of a size in pixels, with a dark edge that keeps it
// apart from the icon of the taskbar button it is put on.
func overlayImage(state trayState, size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := &scene{}
	edge := math.Max(float64(size)/16, 1)
	s.fill(0, 0, float64(size), float64(size), float64(size)/2, darkPalette.backdrop)
	stateMark(s, state, edge, edge, float64(size)-2*edge)
	composeShapes(img, s.shapes)
	return img
}

// trayIconImage draws the icon of a state at a size in pixels on top of the logo at that size.
func trayIconImage(state trayState, logo *image.NRGBA) *image.NRGBA {
	size := logo.Bounds().Dx()
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	draw.Draw(img, img.Rect, logo, logo.Bounds().Min, draw.Src)
	if state == trayOff {
		desaturate(img)
		return img
	}
	s := &scene{}
	cx, cy, radius := trayMark(s, state, float64(size))
	// A gap around the mark keeps it apart from the logo at the smallest sizes.
	gap := math.Max(float64(size)/16, 1)
	cutout := sceneShape{kind: shapeFill, rect: sceneRect{cx - radius - gap, cy - radius - gap, 2 * (radius + gap), 2 * (radius + gap)}, radius: radius + gap}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if cover := cutout.coverage(float64(x)+0.5, float64(y)+0.5, 1); cover > 0 {
				pixel := img.Pix[img.PixOffset(x, y)+3:]
				pixel[0] = byte(float64(pixel[0])*(1-cover) + 0.5)
			}
		}
	}
	composeShapes(img, s.shapes)
	return img
}

// desaturate turns an image grey, a little lighter than its brightness, so that the logo of the "off" state
// stays visible on a dark taskbar.
func desaturate(img *image.NRGBA) {
	for i := 0; i+3 < len(img.Pix); i += 4 {
		r, g, b := float64(img.Pix[i]), float64(img.Pix[i+1]), float64(img.Pix[i+2])
		grey := byte(math.Min(255, 48+0.85*(0.299*r+0.587*g+0.114*b)+0.5))
		img.Pix[i], img.Pix[i+1], img.Pix[i+2] = grey, grey, grey
	}
}

// composeShapes draws shapes, given in pixels, over an image with transparency.
func composeShapes(img *image.NRGBA, shapes []sceneShape) {
	size := img.Bounds().Size()
	for i := range shapes {
		shape := &shapes[i]
		bounds := shape.bounds(1, size.X, size.Y)
		r, g, b := float64(byte(shape.color>>16)), float64(byte(shape.color>>8)), float64(byte(shape.color))
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				cover := shape.coverage(float64(x)+0.5, float64(y)+0.5, 1) * (1 - shape.fade)
				if cover <= 0 {
					continue
				}
				pixel := img.Pix[img.PixOffset(x, y):]
				below := float64(pixel[3]) / 255
				alpha := cover + below*(1-cover)
				blend := func(over, under byte) byte {
					return byte((float64(over)*cover+float64(under)*below*(1-cover))/alpha + 0.5)
				}
				pixel[0], pixel[1], pixel[2] = blend(byte(r), pixel[0]), blend(byte(g), pixel[1]), blend(byte(b), pixel[2])
				pixel[3] = byte(alpha*255 + 0.5)
			}
		}
	}
}

// The logo

// An iconFrame is one of the images of an icon: its size, and its data as stored in an .ico file or an icon
// resource, a PNG or a bitmap without its file header.
type iconFrame struct {
	size int
	data []byte
}

// pickIconFrame chooses the frame to draw an icon of a size from: one of that size, else the smallest larger one,
// else the largest.
func pickIconFrame(frames []iconFrame, size int) (iconFrame, bool) {
	best := -1
	for i, frame := range frames {
		if frame.size == size {
			return frame, true
		}
		if best < 0 {
			best = i
			continue
		}
		switch chosen := frames[best].size; {
		case chosen < size && frame.size > chosen:
			// While the chosen frame is too small, any larger one is better.
			best = i
		case chosen > size && frame.size > size && frame.size < chosen:
			// A larger frame closer to the size loses less when it is reduced.
			best = i
		}
	}
	if best < 0 {
		return iconFrame{}, false
	}
	return frames[best], true
}

// icoFileFrames lists the frames of an .ico file.
func icoFileFrames(data []byte) ([]iconFrame, error) {
	if len(data) < 6 || binary.LittleEndian.Uint16(data[2:]) != 1 {
		return nil, errors.New("not an icon file")
	}
	count := int(binary.LittleEndian.Uint16(data[4:]))
	frames := make([]iconFrame, 0, count)
	for i := 0; i < count; i++ {
		entry := data[min(6+16*i, len(data)):]
		if len(entry) < 16 {
			return nil, errors.New("icon directory is truncated")
		}
		length, offset := int(binary.LittleEndian.Uint32(entry[8:])), int(binary.LittleEndian.Uint32(entry[12:]))
		if offset < 0 || length < 0 || offset+length > len(data) {
			return nil, errors.New("icon frame lies outside of the file")
		}
		frames = append(frames, iconFrame{iconDirectorySize(entry[0]), data[offset : offset+length]})
	}
	return frames, nil
}

// iconDirectorySize is the size of a frame as an icon directory writes it, where 0 means 256.
func iconDirectorySize(b byte) int {
	if b == 0 {
		return 256
	}
	return int(b)
}

// decodeIconFrame decodes the image of a frame, which is either a PNG or a 32-bit bitmap with alpha.
func decodeIconFrame(data []byte) (*image.NRGBA, error) {
	if bytes.HasPrefix(data, []byte("\x89PNG")) {
		decoded, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		img := image.NewNRGBA(image.Rect(0, 0, decoded.Bounds().Dx(), decoded.Bounds().Dy()))
		draw.Draw(img, img.Rect, decoded, decoded.Bounds().Min, draw.Src)
		return img, nil
	}
	if len(data) < 40 {
		return nil, errors.New("icon bitmap is truncated")
	}
	headerSize := int(binary.LittleEndian.Uint32(data))
	width := int(int32(binary.LittleEndian.Uint32(data[4:])))
	height := int(int32(binary.LittleEndian.Uint32(data[8:]))) / 2 // The height counts the mask too.
	if binary.LittleEndian.Uint16(data[14:]) != 32 || width <= 0 || height <= 0 || width > 1024 || height > 1024 {
		return nil, errors.New("only 32-bit icon bitmaps are supported")
	}
	pixels := data[min(headerSize, len(data)):]
	if len(pixels) < width*height*4 {
		return nil, errors.New("icon bitmap is truncated")
	}
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		row := pixels[(height-1-y)*width*4:] // Bitmaps are stored bottom up.
		for x := 0; x < width; x++ {
			pixel := img.Pix[img.PixOffset(x, y):]
			pixel[0], pixel[1], pixel[2], pixel[3] = row[x*4+2], row[x*4+1], row[x*4], row[x*4+3]
		}
	}
	return img, nil
}

// resizeImage scales an image with transparency to a square size by averaging the pixels that each new pixel
// covers, weighted by their alpha, which is what a reduction by a fraction needs to stay sharp.
func resizeImage(src *image.NRGBA, size int) *image.NRGBA {
	from := src.Bounds().Dx()
	if from == size {
		return src
	}
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
	ratio := float64(from) / float64(size)
	for y := 0; y < size; y++ {
		y0, y1 := float64(y)*ratio, float64(y+1)*ratio
		for x := 0; x < size; x++ {
			x0, x1 := float64(x)*ratio, float64(x+1)*ratio
			var sum [4]float64
			var area float64
			for sy := int(y0); sy < int(math.Ceil(y1)) && sy < from; sy++ {
				hy := math.Min(y1, float64(sy+1)) - math.Max(y0, float64(sy))
				for sx := int(x0); sx < int(math.Ceil(x1)) && sx < from; sx++ {
					weight := hy * (math.Min(x1, float64(sx+1)) - math.Max(x0, float64(sx)))
					pixel := src.Pix[src.PixOffset(sx, sy):]
					alpha := float64(pixel[3]) * weight
					sum[0] += float64(pixel[0]) * alpha
					sum[1] += float64(pixel[1]) * alpha
					sum[2] += float64(pixel[2]) * alpha
					sum[3] += alpha
					area += weight
				}
			}
			if sum[3] <= 0 || area <= 0 {
				continue
			}
			pixel := dst.Pix[dst.PixOffset(x, y):]
			pixel[0], pixel[1], pixel[2] = byte(sum[0]/sum[3]+0.5), byte(sum[1]/sum[3]+0.5), byte(sum[2]/sum[3]+0.5)
			pixel[3] = byte(sum[3]/area + 0.5)
		}
	}
	return dst
}

// logoFromFrames is the logo at a size in pixels, from its own frame if the icon has one of that size.
func logoFromFrames(frames []iconFrame, size int) (*image.NRGBA, error) {
	frame, ok := pickIconFrame(frames, size)
	if !ok {
		return nil, errors.New("icon has no frames")
	}
	img, err := decodeIconFrame(frame.data)
	if err != nil {
		return nil, err
	}
	return resizeImage(img, size), nil
}

// logoResourceID is the icon resource of the WireGuard logo, from resources.rc.
const logoResourceID = 7

// logoResourceFrames lists the frames of the logo icon in the resources of the program. An icon resource is a
// directory like that of an .ico file, but it names each frame by a resource id instead of an offset.
func logoResourceFrames() ([]iconFrame, error) {
	module := windows.Handle(win.GetModuleHandle(nil))
	group, err := windows.FindResource(module, windows.ResourceID(logoResourceID), windows.RT_GROUP_ICON)
	if err != nil {
		return nil, err
	}
	directory, err := windows.LoadResourceData(module, group)
	if err != nil {
		return nil, err
	}
	if len(directory) < 6 {
		return nil, errors.New("icon resource is truncated")
	}
	count := int(binary.LittleEndian.Uint16(directory[4:]))
	var frames []iconFrame
	for i := 0; i < count; i++ {
		entry := directory[min(6+14*i, len(directory)):]
		if len(entry) < 14 {
			return nil, errors.New("icon resource is truncated")
		}
		id := binary.LittleEndian.Uint16(entry[12:])
		resource, err := windows.FindResource(module, windows.ResourceID(id), windows.RT_ICON)
		if err != nil {
			return nil, err
		}
		data, err := windows.LoadResourceData(module, resource)
		if err != nil {
			return nil, err
		}
		frames = append(frames, iconFrame{iconDirectorySize(entry[0]), data})
	}
	return frames, nil
}

var (
	cachedLogoFrames []iconFrame
	cachedLogoImages = make(map[int]*image.NRGBA)
)

// logoImage is the logo at a size in pixels.
func logoImage(size int) (*image.NRGBA, error) {
	if img := cachedLogoImages[size]; img != nil {
		return img, nil
	}
	if cachedLogoFrames == nil {
		frames, err := logoResourceFrames()
		if err != nil {
			return nil, err
		}
		cachedLogoFrames = frames
	}
	img, err := logoFromFrames(cachedLogoFrames, size)
	if err != nil {
		return nil, err
	}
	cachedLogoImages[size] = img
	return img, nil
}

// iconFromImage makes a Windows icon of an image. The colors of an icon bitmap are not premultiplied by their
// alpha, which is how an NRGBA image keeps them, so they are copied as they are.
func iconFromImage(img *image.NRGBA) (win.HICON, error) {
	size := img.Bounds().Size()
	info := win.BITMAPINFOHEADER{
		BiWidth:       int32(size.X),
		BiHeight:      -int32(size.Y), // Top-down
		BiPlanes:      1,
		BiBitCount:    32,
		BiCompression: win.BI_RGB,
	}
	info.BiSize = uint32(unsafe.Sizeof(info))
	hdc := win.GetDC(0)
	var bits unsafe.Pointer
	color := win.CreateDIBSection(hdc, &info, win.DIB_RGB_COLORS, &bits, 0, 0)
	win.ReleaseDC(0, hdc)
	if color == 0 {
		return 0, errors.New("CreateDIBSection failed")
	}
	defer win.DeleteObject(win.HGDIOBJ(color))
	pixels := unsafe.Slice((*byte)(bits), size.X*size.Y*4)
	for i := 0; i < len(pixels); i += 4 {
		pixels[i], pixels[i+1], pixels[i+2], pixels[i+3] = img.Pix[i+2], img.Pix[i+1], img.Pix[i], img.Pix[i+3]
	}
	mask := win.CreateBitmap(int32(size.X), int32(size.Y), 1, 1, nil)
	if mask == 0 {
		return 0, errors.New("CreateBitmap failed")
	}
	defer win.DeleteObject(win.HGDIOBJ(mask))
	icon := win.CreateIconIndirect(&win.ICONINFO{FIcon: win.TRUE, HbmMask: mask, HbmColor: color})
	if icon == 0 {
		return 0, errors.New("CreateIconIndirect failed")
	}
	return icon, nil
}

type stateIconKey struct {
	state       trayState
	pixels, dpi int
}

var cachedStateIcons = make(map[stateIconKey]*walk.Icon)

var cachedOverlayIcons = make(map[stateIconKey]*walk.Icon)

// overlayIcon is the mark of a state as the overlay of a taskbar button, which is 16x16 at 96 DPI.
func overlayIcon(state trayState, dpi int) (*walk.Icon, error) {
	if dpi <= 0 {
		dpi = 96
	}
	key := stateIconKey{state, (16*dpi + 48) / 96, dpi}
	if icon := cachedOverlayIcons[key]; icon != nil {
		return icon, nil
	}
	handle, err := iconFromImage(overlayImage(state, key.pixels))
	if err != nil {
		return nil, err
	}
	icon, err := walk.NewIconFromHICONForDPI(handle, dpi)
	if err != nil {
		win.DestroyIcon(handle)
		return nil, err
	}
	cachedOverlayIcons[key] = icon
	return icon, nil
}

// stateIcon is the icon of a state for a size in 1/96" units on a screen of a DPI, drawn at its exact size in
// pixels there.
func stateIcon(state trayState, size, dpi int) (*walk.Icon, error) {
	if dpi <= 0 {
		dpi = 96
	}
	key := stateIconKey{state, (size*dpi + 48) / 96, dpi}
	if icon := cachedStateIcons[key]; icon != nil {
		return icon, nil
	}
	logo, err := logoImage(key.pixels)
	if err != nil {
		return nil, err
	}
	handle, err := iconFromImage(trayIconImage(state, logo))
	if err != nil {
		return nil, err
	}
	icon, err := walk.NewIconFromHICONForDPI(handle, dpi)
	if err != nil {
		win.DestroyIcon(handle)
		return nil, err
	}
	cachedStateIcons[key] = icon
	return icon, nil
}
