/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
)

const (
	maxLogLinesDisplayed = 10000
)

type LogPage struct {
	*walk.Composite
	logView *walk.TableView
	model   *logModel
}

func NewLogPage(parent walk.Container) (*LogPage, error) {
	lp := &LogPage{}

	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	if lp.Composite, err = walk.NewComposite(parent); err != nil {
		return nil, err
	}
	disposables.Add(lp)

	lp.Disposing().Attach(func() {
		close(lp.model.quit)
	})

	layout := walk.NewVBoxLayout()
	layout.SetMargins(walk.Margins{HNear: 16, HFar: 16})
	lp.SetLayout(layout)

	if lp.logView, err = walk.NewTableView(lp); err != nil {
		return nil, err
	}
	lp.logView.SetLastColumnStretched(true)
	lp.logView.SetHeaderHidden(true)
	lp.logView.SetCellStyler(lp)
	lp.logView.SetBackground(themeBrush(themeBackdrop))
	for child := win.GetWindow(lp.logView.Handle(), win.GW_CHILD); child != 0; child = win.GetWindow(child, win.GW_HWNDNEXT) {
		useDarkControlTheme(child)
		win.SendMessage(child, win.LVM_SETBKCOLOR, 0, uintptr(themeBackdrop.walk()))
	}

	contextMenu, err := walk.NewMenu()
	if err != nil {
		return nil, err
	}
	lp.logView.AddDisposable(contextMenu)
	copyAction := walk.NewAction()
	copyAction.SetText(l18n.Sprintf("&Copy"))
	copyAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyC})
	copyAction.Triggered().Attach(lp.onCopy)
	contextMenu.Actions().Add(copyAction)
	lp.ShortcutActions().Add(copyAction)
	selectAllAction := walk.NewAction()
	selectAllAction.SetText(l18n.Sprintf("Select &all"))
	selectAllAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyA})
	selectAllAction.Triggered().Attach(lp.onSelectAll)
	contextMenu.Actions().Add(selectAllAction)
	lp.ShortcutActions().Add(selectAllAction)
	saveAction := walk.NewAction()
	saveAction.SetText(l18n.Sprintf("&Save to file…"))
	saveAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyS})
	saveAction.Triggered().Attach(lp.onSave)
	contextMenu.Actions().Add(saveAction)
	lp.ShortcutActions().Add(saveAction)
	lp.logView.SetContextMenu(contextMenu)
	setSelectionStatus := func() {
		copyAction.SetEnabled(len(lp.logView.SelectedIndexes()) > 0)
		selectAllAction.SetEnabled(len(lp.logView.SelectedIndexes()) < len(lp.model.items))
	}
	lp.logView.SelectedIndexesChanged().Attach(setSelectionStatus)

	stampCol := walk.NewTableViewColumn()
	stampCol.SetName("Stamp")
	stampCol.SetTitle(l18n.Sprintf("Time"))
	stampCol.SetFormat("2006-01-02 15:04:05.000")
	stampCol.SetWidth(140)
	lp.logView.Columns().Add(stampCol)

	msgCol := walk.NewTableViewColumn()
	msgCol.SetName("Line")
	msgCol.SetTitle(l18n.Sprintf("Log message"))
	lp.logView.Columns().Add(msgCol)

	lp.model = newLogModel(lp)
	lp.model.RowsReset().Attach(setSelectionStatus)
	lp.logView.SetModel(lp.model)
	setSelectionStatus()

	disposables.Spare()

	return lp, nil
}

// StyleCell colors the log for the dark window and marks warnings and errors.
func (lp *LogPage) StyleCell(style *walk.CellStyle) {
	style.BackgroundColor = themeBackdrop.walk()
	style.TextColor = themeText.walk()
	row := style.Row()
	if style.Col() == 0 || row < 0 || row >= len(lp.model.items) {
		style.TextColor = themeTextDim.walk()
		return
	}
	switch ringlogger.ParseLine(lp.model.items[row].Line).Level {
	case ringlogger.LevelWarning:
		style.TextColor = themeAmberSoft.walk()
	case ringlogger.LevelError:
		style.TextColor = themeRedSoft.walk()
	}
}

// setFilter restricts the log to the lines of one tunnel, if a name is given, and to warnings and errors.
func (lp *LogPage) setFilter(tunnel string, warningsOnly bool) {
	mdl := lp.model
	if mdl.filterTunnel == tunnel && mdl.warningsOnly == warningsOnly {
		return
	}
	mdl.filterTunnel, mdl.warningsOnly = tunnel, warningsOnly
	mdl.applyFilter()
	mdl.PublishRowsReset()
	lp.scrollToBottom()
}

func (lp *LogPage) filter() (tunnel string, warningsOnly bool) {
	return lp.model.filterTunnel, lp.model.warningsOnly
}

// copySelectionOrAll copies the selected lines, or the whole log when none is selected.
func (lp *LogPage) copySelectionOrAll() {
	if len(lp.logView.SelectedIndexes()) == 0 {
		lp.onSelectAll()
	}
	lp.onCopy()
}

func (lp *LogPage) isAtBottom() bool {
	return len(lp.model.items) == 0 || lp.logView.ItemVisible(len(lp.model.items)-1)
}

func (lp *LogPage) scrollToBottom() {
	lp.logView.EnsureItemVisible(len(lp.model.items) - 1)
}

func (lp *LogPage) onCopy() {
	var logLines strings.Builder
	selectedItemIndexes := lp.logView.SelectedIndexes()
	if len(selectedItemIndexes) == 0 {
		return
	}
	for i := range selectedItemIndexes {
		logItem := lp.model.items[selectedItemIndexes[i]]
		logLines.WriteString(fmt.Sprintf("%s: %s\r\n", logItem.Stamp.Format("2006-01-02 15:04:05.000"), logItem.Line))
	}
	walk.Clipboard().SetText(logLines.String())
}

func (lp *LogPage) onSelectAll() {
	lp.logView.SetSelectedIndexes([]int{-1})
}

func (lp *LogPage) onSave() {
	fd := walk.FileDialog{
		Filter:   l18n.Sprintf("Text Files (*.txt)|*.txt|All Files (*.*)|*.*"),
		FilePath: fmt.Sprintf("wireguard-log-%s.txt", time.Now().Format("2006-01-02T150405")),
		Title:    l18n.Sprintf("Export log to file"),
	}

	form := lp.Form()

	if ok, _ := fd.ShowSave(form); !ok {
		return
	}

	if fd.FilterIndex == 1 && !strings.HasSuffix(fd.FilePath, ".txt") {
		fd.FilePath = fd.FilePath + ".txt"
	}

	writeFileWithOverwriteHandling(form, fd.FilePath, func(file *os.File) error {
		if _, err := ringlogger.Global.WriteTo(file); err != nil {
			return fmt.Errorf("exportLog: Ringlogger.WriteTo failed: %w", err)
		}

		return nil
	})
}

type logModel struct {
	walk.ReflectTableModelBase
	lp   *LogPage
	quit chan struct{}
	// all holds every line; items holds the ones that pass the filter and is what the table shows.
	all   []ringlogger.FollowLine
	items []ringlogger.FollowLine

	filterTunnel string
	warningsOnly bool
}

func (mdl *logModel) applyFilter() {
	if len(mdl.filterTunnel) == 0 && !mdl.warningsOnly {
		mdl.items = mdl.all
		return
	}
	mdl.items = nil
	for i := range mdl.all {
		parsed := ringlogger.ParseLine(mdl.all[i].Line)
		if len(mdl.filterTunnel) > 0 && parsed.Tunnel != mdl.filterTunnel {
			continue
		}
		if mdl.warningsOnly && parsed.Level == ringlogger.LevelInfo {
			continue
		}
		mdl.items = append(mdl.items, mdl.all[i])
	}
}

func newLogModel(lp *LogPage) *logModel {
	mdl := &logModel{lp: lp, quit: make(chan struct{})}
	go func() {
		ticker := time.NewTicker(time.Second)
		cursor := ringlogger.CursorAll

		for {
			select {
			case <-ticker.C:
				var items []ringlogger.FollowLine
				items, cursor = ringlogger.Global.FollowFromCursor(cursor)
				if len(items) == 0 {
					continue
				}
				mdl.lp.Synchronize(func() {
					isAtBottom := mdl.lp.isAtBottom() && len(lp.logView.SelectedIndexes()) <= 1

					mdl.all = append(mdl.all, items...)
					if len(mdl.all) > maxLogLinesDisplayed {
						mdl.all = mdl.all[len(mdl.all)-maxLogLinesDisplayed:]
					}
					mdl.applyFilter()
					mdl.PublishRowsReset()

					if isAtBottom {
						mdl.lp.scrollToBottom()
					}
				})

			case <-mdl.quit:
				ticker.Stop()
				return
			}
		}
	}()

	return mdl
}

func (mdl *logModel) Items() any {
	return mdl.items
}
