/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"strings"

	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/l18n"
)

// runProbeTargetDialog asks for the address that connection quality is measured with; empty means that the
// manager chooses one. apply is called with what was entered when OK is pressed, and the dialog stays open
// with its error shown if it fails, so that a mistyped address can be corrected. It reports whether apply
// succeeded.
func runProbeTargetDialog(owner walk.Form, current string, apply func(target string) error) bool {
	var disposables walk.Disposables
	defer disposables.Treat()

	dlg, err := walk.NewDialog(owner)
	if showError(err, owner) {
		return false
	}
	disposables.Add(dlg)
	dlg.SetTitle(l18n.Sprintf("Address to measure"))
	if owner != nil {
		dlg.SetIcon(owner.Icon())
	}
	layout := walk.NewGridLayout()
	layout.SetSpacing(8)
	layout.SetMargins(walk.Margins{14, 14, 14, 14})
	dlg.SetLayout(layout)
	dlg.SetMinMaxSize(walk.Size{420, 0}, walk.Size{0, 0})

	explanation, err := walk.NewTextLabel(dlg)
	if showError(err, owner) {
		return false
	}
	layout.SetRange(explanation, walk.Rectangle{0, 0, 2, 1})
	explanation.SetText(l18n.Sprintf("Connection quality is measured by pinging an address through the tunnel once a second. Leave the field empty to let WireGuard choose a peer address or DNS server of the tunnel."))

	addressLabel, err := walk.NewTextLabel(dlg)
	if showError(err, owner) {
		return false
	}
	layout.SetRange(addressLabel, walk.Rectangle{0, 1, 1, 1})
	addressLabel.SetTextAlignment(walk.AlignHFarVCenter)
	addressLabel.SetText(l18n.Sprintf("&Address:"))

	addressEdit, err := walk.NewLineEdit(dlg)
	if showError(err, owner) {
		return false
	}
	layout.SetRange(addressEdit, walk.Rectangle{1, 1, 1, 1})
	addressEdit.SetText(current)
	addressEdit.SetCueBanner(l18n.Sprintf("automatic"))

	buttons, err := walk.NewComposite(dlg)
	if showError(err, owner) {
		return false
	}
	layout.SetRange(buttons, walk.Rectangle{0, 2, 2, 1})
	buttons.SetLayout(walk.NewHBoxLayout())
	buttons.Layout().SetMargins(walk.Margins{})
	walk.NewHSpacer(buttons)
	okButton, err := walk.NewPushButton(buttons)
	if showError(err, owner) {
		return false
	}
	okButton.SetText(l18n.Sprintf("OK"))
	cancelButton, err := walk.NewPushButton(buttons)
	if showError(err, owner) {
		return false
	}
	cancelButton.SetText(l18n.Sprintf("Cancel"))

	applied := false
	okButton.Clicked().Attach(func() {
		if err := apply(strings.TrimSpace(addressEdit.Text())); err != nil {
			showErrorCustom(dlg, l18n.Sprintf("Invalid address"), err.Error())
			addressEdit.SetFocus()
			return
		}
		applied = true
		dlg.Accept()
	})
	cancelButton.Clicked().Attach(dlg.Cancel)
	dlg.SetDefaultButton(okButton)
	dlg.SetCancelButton(cancelButton)

	restyle := func() {
		styleDialog(dlg)
		buttons.SetBackground(themeBrush(theme.backdrop))
		styleLabels(theme.text, explanation)
		styleLabels(theme.textDim, addressLabel)
		styleEdits(addressEdit)
		styleButtons(okButton, cancelButton)
	}
	restyle()
	defer watchTheme(restyle)()

	dlg.Starting().Attach(func() {
		addressEdit.SetFocus()
		addressEdit.SetTextSelection(0, -1)
	})
	disposables.Spare()
	defer dlg.Dispose()
	dlg.Run()
	return applied
}
