/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"strconv"
	"strings"

	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// A statusLook is how the state of a tunnel is presented: colors, icon and wording.
type statusLook struct {
	accent, background rgb
	icon               iconKind
	dashed             bool
	glyph              glyphKind
	primary            buttonStyle
	title              string
	// short is the one-line status shown next to a tunnel name, in the color shortColor.
	short      string
	shortColor rgb
	// message explains a problem, if there is one.
	message     string
	messageKind noticeKind
}

func lookFor(entry *tunnelEntry) statusLook {
	look := statusLook{accent: themeMuted, background: themePanel, icon: iconShield, glyph: glyphOff, primary: buttonGreen, shortColor: themeTextDim}
	if entry == nil {
		look.title = l18n.Sprintf("Not connected")
		look.short = l18n.Sprintf("No tunnel is active")
		return look
	}
	switch entry.state {
	case manager.TunnelStarting:
		look.accent, look.glyph = themeTextDim, glyphBusy
		look.title = l18n.Sprintf("Activating…")
		look.short = look.title
	case manager.TunnelStopping:
		look.accent, look.glyph = themeTextDim, glyphBusy
		look.title = l18n.Sprintf("Deactivating…")
		look.short = look.title
	case manager.TunnelStarted:
		look.accent, look.background, look.glyph = themeGreen, themeGreenBg, glyphOn
		switch entry.health {
		case manager.TunnelHealthConnected:
			look.icon = iconShieldCheck
			look.title = l18n.Sprintf("Connected")
			look.short, look.shortColor = look.title, themeGreen
		case manager.TunnelHealthWaitingForPeer:
			look.accent, look.background, look.glyph, look.primary = themeAmber, themeAmberBg, glyphWarning, buttonAmber
			look.icon, look.dashed = iconClock, true
			look.title = l18n.Sprintf("Waiting for peer")
			look.short, look.shortColor = l18n.Sprintf("Peer does not answer · network unaffected"), themeAmberSoft
			look.message = l18n.Sprintf("Routes have not been applied, so the rest of your network is unaffected. Check the endpoint, the keys and your network.")
		case manager.TunnelHealthNoConnection:
			look.accent, look.background, look.glyph, look.primary = themeAmber, themeAmberBg, glyphWarning, buttonAmber
			look.icon = iconShieldCross
			look.title = l18n.Sprintf("No connection")
			look.short, look.shortColor = l18n.Sprintf("Peer does not answer"), themeAmberSoft
			look.message = l18n.Sprintf("The peer does not answer. Check the endpoint, the keys and your network.")
		case manager.TunnelHealthNoConnectionNetworkBlocked:
			look.accent, look.background, look.glyph, look.primary = themeRed, themeRedBg, glyphAlert, buttonRed
			look.icon = iconShieldCross
			look.title = l18n.Sprintf("Network cut off")
			look.short, look.shortColor = look.title, themeRedSoft
			look.message, look.messageKind = l18n.Sprintf("This tunnel takes over all network traffic, but its peer does not answer. Nothing gets through until it answers or you deactivate the tunnel."), noticeRed
		default:
			look.title = l18n.Sprintf("Active")
			look.short = l18n.Sprintf("Active · connection not verified yet")
		}
	case manager.TunnelStopped:
		look.title = l18n.Sprintf("Inactive")
		look.short = look.title
	default:
		look.title = l18n.Sprintf("Unknown state")
		look.short = look.title
	}
	return look
}

// connectionWarning is the text about the stability of a connection, if there is something to say.
func connectionWarning(entry *tunnelEntry) (title, text string) {
	if entry.state != manager.TunnelStarted {
		return "", ""
	}
	if entry.conflictSuspected {
		return l18n.Sprintf("Key used elsewhere"), l18n.Sprintf("Another device appears to be using this tunnel's key, which breaks connections on both. Give each device its own key pair.")
	}
	if entry.unstable {
		return "", l18n.Sprintf("The connection is unstable: it was lost and re-established recently.")
	}
	return "", ""
}

func joinAddresses[T interface{ String() string }](addresses []T) string {
	parts := make([]string, len(addresses))
	for i := range addresses {
		parts[i] = addresses[i].String()
	}
	return strings.Join(parts, l18n.EnumerationSeparator())
}

// latestHandshake returns the most recent handshake of any peer, and the traffic of all peers.
func trafficOf(config *conf.Config) (handshake conf.HandshakeTime, rx, tx conf.Bytes) {
	for i := range config.Peers {
		peer := &config.Peers[i]
		if peer.LastHandshakeTime > handshake {
			handshake = peer.LastHandshakeTime
		}
		rx += peer.RxBytes
		tx += peer.TxBytes
	}
	return
}

const (
	screenPadding = 28
	footerHeight  = 80
	headerHeight  = 52
)

// buildStatus draws the main screen: the state of the active tunnel on top, the other tunnels below.
func (mtw *ManageTunnelsWindow) buildStatus(s *scene, width, height float64) {
	model := mtw.model
	left, inner := float64(screenPadding), width-2*screenPadding
	y := 24.0

	if model.updateAvailable {
		if s.hit("update", left, 14, inner, 36, func() { mtw.showScreen(screenUpdate) }) {
			s.fill(left, 14, inner, 36, 8, themeAmberBg)
		}
		s.stroke(left, 14, inner, 36, 8, 1, themeAmberBorder)
		s.label(l18n.Sprintf("An Update is Available!"), fontBodyBold, themeAmberSoft, left+12, 14, inner-24, 36, textCenter)
		y += 40
	}

	hero := model.hero()
	look := lookFor(hero)
	subtitle := look.short
	var suggestion *tunnelEntry
	if hero != nil {
		subtitle = hero.tunnel.Name
		if hero.state == manager.TunnelStarted && look.short != look.title {
			subtitle = l18n.Sprintf("%s · %s", hero.tunnel.Name, look.short)
		}
	} else if suggestion = model.suggested(); suggestion == nil {
		look.title = l18n.Sprintf("No tunnels yet")
		subtitle = l18n.Sprintf("Import a configuration file to get started.")
	}

	// The ring with the state icon
	ringX := width/2 - 56
	s.fill(ringX, y, 112, 112, 56, look.background)
	if look.dashed {
		s.dashedRing(ringX, y, 112, 3, 9, look.accent)
	} else {
		s.stroke(ringX, y, 112, 112, 56, 3, look.accent)
	}
	s.icon(look.icon, ringX+34, y+34, 44, look.accent)
	y += 112 + 12
	s.label(look.title, fontTitle, themeText, left, y, inner, 38, textCenter)
	y += 38
	if hero != nil && hero.state == manager.TunnelStarted && hero.health == manager.TunnelHealthConnected && hero.config != nil {
		if handshake, _, _ := trafficOf(hero.config); !handshake.IsEmpty() {
			subtitle = l18n.Sprintf("%s · latest handshake %s", hero.tunnel.Name, handshake.String())
		}
	}
	s.label(subtitle, fontBody, themeTextDim, left, y, inner, 22, textCenter)
	y += 22 + 14

	// Address and traffic of the active tunnel
	if hero != nil && hero.state == manager.TunnelStarted && hero.config != nil {
		_, rx, tx := trafficOf(hero.config)
		tiles := [3][2]string{
			{l18n.Sprintf("Address"), joinAddresses(hero.config.Interface.Addresses)},
			{l18n.Sprintf("Received"), rx.String()},
			{l18n.Sprintf("Sent"), tx.String()},
		}
		tileWidth := (inner - 16) / 3
		for i, tile := range tiles {
			x := left + float64(i)*(tileWidth+8)
			s.fill(x, y, tileWidth, 54, 8, themePanel)
			s.label(tile[0], fontSmall, themeTextDim, x+12, y+8, tileWidth-24, 18, textLeft)
			s.label(tile[1], fontBodyBold, themeText, x+12, y+26, tileWidth-24, 20, textLeft)
		}
		y += 54 + 14
	}

	// The main action
	switch {
	case hero != nil:
		name := hero.tunnel.Name
		style := look.primary
		if !model.canToggle() {
			style = buttonDisabled
		}
		s.button("hero-toggle", left, y, inner-104, 44, l18n.Sprintf("Deactivate"), style, func() { model.toggle(mtw, name) })
		s.button("hero-details", left+inner-96, y, 96, 44, l18n.Sprintf("Details"), buttonOutline, func() { mtw.showDetails(name) })
		y += 44
	case suggestion != nil:
		name := suggestion.tunnel.Name
		style := buttonGreen
		if !model.canToggle() {
			style = buttonDisabled
		}
		s.button("hero-toggle", left, y, inner, 44, l18n.Sprintf("Activate %s", name), style, func() { model.toggle(mtw, name) })
		y += 44
	case IsAdmin:
		s.button("hero-import", left, y, inner, 44, l18n.Sprintf("Import tunnel(s) from file"), buttonGreen, func() { model.importTunnels(mtw) })
		y += 44
	}

	if hero != nil {
		if len(look.message) > 0 {
			y += 14
			y += s.notice(left, y, inner, look.messageKind, "", look.message)
		}
		if title, text := connectionWarning(hero); len(text) > 0 {
			y += 14
			y += s.notice(left, y, inner, noticeAmber, title, text)
		}
	}

	// The other tunnels, in a part of the screen that scrolls
	var others []*tunnelEntry
	for i := range model.entries {
		if hero == nil || model.entries[i].tunnel != hero.tunnel {
			others = append(others, &model.entries[i])
		}
	}
	footerY := height - footerHeight
	if len(others) > 0 {
		y += 20
		caption := l18n.Sprintf("OTHER TUNNELS")
		if hero == nil {
			caption = l18n.Sprintf("TUNNELS")
		}
		s.label(caption, fontCaps, themeTextDim, left, y, inner, 16, textLeft)
		y += 24

		const rowHeight, rowGap = 56, 6
		viewport := footerY - y
		if viewport < rowHeight {
			viewport = rowHeight
		}
		s.maxScroll = float64(len(others))*(rowHeight+rowGap) - rowGap - viewport
		s.setClip(0, y, width, viewport)
		rowY := y - s.scroll
		for _, entry := range others {
			name := entry.tunnel.Name
			rowLook := lookFor(entry)
			background := themePanel
			if s.hit("row:"+name, left, rowY, inner, rowHeight, func() { mtw.showDetails(name) }) {
				background = themePanelHot
			}
			s.fill(left, rowY, inner, rowHeight, 8, background)
			s.glyph(rowLook.glyph, left+14, rowY+22)
			s.label(name, fontBodyBold, themeText, left+38, rowY+9, inner-38-76, 20, textLeft)
			s.label(rowLook.short, fontSmall, rowLook.shortColor, left+38, rowY+29, inner-38-76, 18, textLeft)
			s.toggle("toggle:"+name, left+inner-14-toggleWidth, rowY+16, entry.active(), model.canToggle(), func() { model.toggle(mtw, name) })
			rowY += rowHeight + rowGap
		}
		s.clearClip()
	}

	// The footer
	s.fill(0, footerY, width, footerHeight, 0, themeBackdrop)
	type footerButton struct {
		id, label string
		action    func()
	}
	buttons := []footerButton{{"log", l18n.Sprintf("Log"), func() { mtw.showScreen(screenLog) }}}
	if IsAdmin {
		buttons = []footerButton{
			{"add", l18n.Sprintf("Add tunnel"), func() { model.addTunnel(mtw) }},
			{"import", l18n.Sprintf("Import"), func() { model.importTunnels(mtw) }},
			{"export", l18n.Sprintf("Export"), func() { model.exportTunnels(mtw) }},
			buttons[0],
		}
	}
	buttonWidth := (inner - float64(len(buttons)-1)*8) / float64(len(buttons))
	for i, button := range buttons {
		s.button(button.id, left+float64(i)*(buttonWidth+8), footerY+16, buttonWidth, 44, button.label, buttonOutline, button.action)
	}
}

type detailRow struct {
	label, value string
	font         themeFont
	color        rgb
	copyable     bool
}

func interfaceRows(c *conf.Interface) []detailRow {
	rows := []detailRow{{label: l18n.Sprintf("Public key"), value: c.PrivateKey.Public().String(), font: fontMono, copyable: IsAdmin}}
	if c.ListenPort > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Listen port"), value: strconv.Itoa(int(c.ListenPort))})
	}
	if c.MTU > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("MTU"), value: strconv.Itoa(int(c.MTU))})
	}
	if len(c.Addresses) > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Addresses"), value: joinAddresses(c.Addresses)})
	}
	if len(c.DNS)+len(c.DNSSearch) > 0 {
		servers := make([]string, 0, len(c.DNS)+len(c.DNSSearch))
		for _, address := range c.DNS {
			servers = append(servers, address.String())
		}
		servers = append(servers, c.DNSSearch...)
		rows = append(rows, detailRow{label: l18n.Sprintf("DNS servers"), value: strings.Join(servers, l18n.EnumerationSeparator())})
	}
	var scriptsInUse []string
	if len(c.PreUp) > 0 {
		scriptsInUse = append(scriptsInUse, l18n.Sprintf("pre-up"))
	}
	if len(c.PostUp) > 0 {
		scriptsInUse = append(scriptsInUse, l18n.Sprintf("post-up"))
	}
	if len(c.PreDown) > 0 {
		scriptsInUse = append(scriptsInUse, l18n.Sprintf("pre-down"))
	}
	if len(c.PostDown) > 0 {
		scriptsInUse = append(scriptsInUse, l18n.Sprintf("post-down"))
	}
	if len(scriptsInUse) > 0 {
		value := l18n.Sprintf("disabled, per policy")
		if conf.AdminBool("DangerousScriptExecution") {
			value = strings.Join(scriptsInUse, l18n.EnumerationSeparator())
		}
		rows = append(rows, detailRow{label: l18n.Sprintf("Scripts"), value: value})
	}
	if c.TableOff {
		rows = append(rows, detailRow{label: l18n.Sprintf("Table"), value: l18n.Sprintf("off")})
	}
	return rows
}

func peerRows(c *conf.Peer, connected bool) []detailRow {
	rows := []detailRow{{label: l18n.Sprintf("Public key"), value: c.PublicKey.String(), font: fontMono}}
	if !c.PresharedKey.IsZero() && IsAdmin {
		rows = append(rows, detailRow{label: l18n.Sprintf("Preshared key"), value: l18n.Sprintf("enabled")})
	}
	if len(c.AllowedIPs) > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Allowed IPs"), value: joinAddresses(c.AllowedIPs)})
	}
	if !c.Endpoint.IsEmpty() {
		rows = append(rows, detailRow{label: l18n.Sprintf("Endpoint"), value: c.Endpoint.String()})
	}
	if c.PersistentKeepalive > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Persistent keepalive"), value: strconv.Itoa(int(c.PersistentKeepalive))})
	}
	if !c.LastHandshakeTime.IsEmpty() {
		row := detailRow{label: l18n.Sprintf("Latest handshake"), value: c.LastHandshakeTime.String()}
		if connected {
			row.color = themeGreen
		}
		rows = append(rows, row)
	}
	if c.RxBytes > 0 || c.TxBytes > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Transfer"), value: l18n.Sprintf("%s received, %s sent", c.RxBytes.String(), c.TxBytes.String())})
	}
	return rows
}

// card draws a titled panel of labelled values and returns its height.
func (s *scene) card(x, y, w float64, title string, rows []detailRow) float64 {
	const labelWidth, pad, rowGap = 128, 16, 8
	valueWidth := w - 2*pad - labelWidth
	heights := make([]float64, len(rows))
	height := float64(pad + 16 + 10)
	for i := range rows {
		heights[i] = s.wrappedHeight(rows[i].value, rows[i].font, valueWidth)
		if heights[i] < 20 {
			heights[i] = 20
		}
		height += heights[i] + rowGap
	}
	height += pad - rowGap

	s.fill(x, y, w, height, 8, themePanel)
	s.label(title, fontCaps, themeTextDim, x+pad, y+pad, w-2*pad, 16, textLeft)
	rowY := y + pad + 16 + 10
	for i, row := range rows {
		color := row.color
		if color == 0 {
			color = themeText
		}
		if row.copyable {
			value := row.value
			s.button("copy:"+title+row.label, x+w-pad-132, y+pad-5, 132, 26, l18n.Sprintf("Copy public key"), buttonOutline, func() { walk.Clipboard().SetText(value) })
		}
		s.label(row.label, fontBody, themeTextDim, x+pad, rowY, labelWidth-8, 20, textLeft)
		s.text(row.value, row.font, color, x+pad+labelWidth, rowY+1, valueWidth, heights[i], textWrap)
		rowY += heights[i] + rowGap
	}
	return height
}

// buildHeader draws the bar on top of every screen but the main one.
func (s *scene) header(width float64, title string, back func()) {
	s.backButton(back)
	s.label(title, fontHeading, themeText, 54, 0, width-54-16, headerHeight, textLeft)
	s.fill(0, headerHeight, width, 1, 0, themeLine)
}

// buildDetails draws the screen about one tunnel.
func (mtw *ManageTunnelsWindow) buildDetails(s *scene, width, height float64) {
	model := mtw.model
	name := mtw.detailsName
	back := func() { mtw.showScreen(screenStatus) }
	entry := model.entry(name)
	if entry == nil {
		s.header(width, name, back)
		return
	}
	look := lookFor(entry)
	left, inner := 24.0, width-48

	// The content, which scrolls between the header and the footer
	top, footerY := float64(headerHeight+1), height-footerHeight
	s.setClip(0, top, width, footerY-top)
	y := top + 18 - s.scroll
	if len(look.message) > 0 {
		y += s.notice(left, y, inner, look.messageKind, "", look.message) + 14
	}
	if title, text := connectionWarning(entry); len(text) > 0 {
		y += s.notice(left, y, inner, noticeAmber, title, text) + 14
	}
	if entry.config != nil {
		y += s.card(left, y, inner, l18n.Sprintf("INTERFACE"), interfaceRows(&entry.config.Interface)) + 14
		for i := range entry.config.Peers {
			connected := entry.state == manager.TunnelStarted && entry.health == manager.TunnelHealthConnected
			y += s.card(left, y, inner, l18n.Sprintf("PEER"), peerRows(&entry.config.Peers[i], connected)) + 14
		}
	}
	s.maxScroll = y + s.scroll + 4 - footerY
	s.clearClip()

	// The header
	s.fill(0, 0, width, headerHeight, 0, themeBackdrop)
	s.header(width, name, back)
	s.label(look.short, fontBodyBold, look.shortColor, width/2, 0, width/2-20, headerHeight, textRight)

	// The footer
	s.fill(0, footerY, width, footerHeight, 0, themeBackdrop)
	s.fill(0, footerY, width, 1, 0, themeLine)
	style, label := look.primary, l18n.Sprintf("Deactivate")
	if !entry.active() {
		style, label = buttonGreen, l18n.Sprintf("Activate")
	}
	if !model.canToggle() {
		style = buttonDisabled
	}
	mainWidth := inner
	if IsAdmin {
		mainWidth = inner - 88 - 104
		s.button("edit", left+mainWidth+8, footerY+18, 80, 44, l18n.Sprintf("Edit"), buttonOutline, func() { model.editTunnel(mtw, name) })
		s.button("remove", left+mainWidth+96, footerY+18, 96, 44, l18n.Sprintf("Remove"), buttonDanger, func() {
			if model.deleteTunnel(mtw, name) {
				mtw.showScreen(screenStatus)
			}
		})
	}
	s.button("toggle", left, footerY+18, mainWidth, 44, label, style, func() { model.toggle(mtw, name) })
}
