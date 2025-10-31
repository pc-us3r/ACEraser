//go:build windows

package main

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("Activity Eraser")
	w.Resize(fyne.NewSize(600, 420))

	// Показать обязательный Disclaimer
	showDisclaimer(w, func(accepted bool) {
		if !accepted {
			w.Close()
			return
		}
		buildMainUI(w)
	})

	w.ShowAndRun()
}

func buildMainUI(w fyne.Window) {
	if ok, _ := isAdmin(); !ok {
		dialog.ShowInformation("Требуются права администратора",
			"Для очистки BAM/HKLM и журналов событий запустите приложение от имени администратора.",
			w)
	}

	btnSafe := widget.NewButton("Safe", func() { showProfileConfirm(w, ProfileSafe) })
	btnExtended := widget.NewButton("Extended", func() { showProfileConfirm(w, ProfileExtended) })
	btnMaximum := widget.NewButton("Maximum", func() { showProfileConfirm(w, ProfileMaximum) })
	btnReadme := widget.NewButton("Read Me", func() { showReadme(w) })

	w.SetContent(container.NewVBox(
		widget.NewLabel("Выберите режим очистки:"),
		btnSafe,
		btnExtended,
		btnMaximum,
		widget.NewSeparator(),
		btnReadme,
	))
}

// Дисклеймер с ссылками на лицензию и политику
func showDisclaimer(w fyne.Window, onResult func(accepted bool)) {
	text := "ВНИМАНИЕ\n\n" +
		"Этот инструмент предназначен для приватности и обслуживания (личные ПК, тестовые стенды, подготовка к продаже).\n" +
		"Запрещено использовать для сокрытия противоправной активности, обхода аудита или препятствования расследованиям.\n" +
		"В расширенных режимах удаляются диагностические данные (Prefetch/ReadyBoot, Minidump, журналы событий Windows).\n" +
		"Перед очисткой логов рекомендуется выполнить экспорт журналов.\n\n" +
		"Нажимая «Согласен», вы подтверждаете ответственное использование и соблюдение применимых законов/политик.\n"

	lbl := widget.NewLabel(text)

	uLicense, _ := url.Parse("https://github.com/pc-us3r/ACEraser/blob/master/LICENSE%20(MIT)")
	uPolicy, _ := url.Parse("https://github.com/pc-us3r/ACEraser/blob/master/POLICY.md")
	linkLicense := widget.NewHyperlink("LICENSE (MIT)", uLicense)
	linkPolicy := widget.NewHyperlink("POLICY.md (Acceptable Use)", uPolicy)

	var dlg dialog.Dialog

	btnAgree := widget.NewButton("Согласен", func() {
		dlg.Hide()
		onResult(true)
	})
	btnCancel := widget.NewButton("Отмена", func() {
		dlg.Hide()
		onResult(false)
	})

	content := container.NewVBox(
		lbl,
		container.NewHBox(linkLicense, linkPolicy),
		widget.NewSeparator(),
		container.NewHBox(btnAgree, btnCancel),
	)

	dlg = dialog.NewCustomWithoutButtons("Дисклеймер и правила использования", content, w)
	dlg.Show()
}

func showProfileConfirm(w fyne.Window, p Profile) {
	title, msg := profileDescription(p)
	content := widget.NewLabel(msg)

	if p != ProfileMaximum {
		dialog.ShowCustomConfirm(
			title,
			"Подтвердить",
			"Отмена",
			content,
			func(ok bool) {
				if !ok {
					return
				}
				runCleanupWithOptions(w, Options{
					Profile:           p,
					BackupEventLogsTo: "",
					DryRun:            false,
					Verbose:           true,
				})
			},
			w,
		)
		return
	}

	// Maximum: Confirm/Cancel + внутренняя кнопка «Экспорт логов»
	exportBtn := widget.NewButton("Экспорт логов", func() {
		dir := appDir()
		logDir := filepath.Join(dir, "logs")
		_ = os.MkdirAll(logDir, 0o755)

		pb := widget.NewProgressBar()
		pb.Min = 0
		pb.Max = 1
		pb.SetValue(0)
		lbl := widget.NewLabel("Подготовка экспорта...")
		progBox := container.NewVBox(lbl, pb)
		expDlg := dialog.NewCustom("Экспорт журналов", "Скрыть", progBox, w)
		expDlg.Show()

		OpenConsoleForLogs()

		go func() {
			opts := Options{
				Profile:           ProfileMaximum,
				BackupEventLogsTo: logDir,
				DryRun:            true, // только экспорт
				Verbose:           true, // отображать команды в консоли
			}
			logNames := listEventLogs(true)
			total := len(logNames)
			if total == 0 {
				lbl.SetText("Нет доступных журналов для экспорта.")
				pb.SetValue(1)
				time.Sleep(1 * time.Second)
				expDlg.Hide()
				dialog.ShowInformation("Экспорт завершён", "Журналы отсутствуют или недоступны.", w)
				return
			}
			lbl.SetText("Экспорт журналов...")
			pb.Min = 0
			pb.Max = float64(total)
			pb.SetValue(0)

			ExportAllEventLogsWithProgress(opts, true, func(cur, tot int, name string) {
				pb.SetValue(float64(cur))
				lbl.SetText(fmt.Sprintf("Экспорт: %d%%  (%d/%d)  %s", percent(cur, tot), cur, tot, name))
			})

			_ = exec.Command("explorer.exe", logDir).Start()
			expDlg.Hide()
			dialog.ShowInformation("Экспорт завершён", "Журналы сохранены в: "+logDir, w)
		}()
	})

	box := container.NewVBox(
		content,
		widget.NewSeparator(),
		exportBtn,
	)

	dialog.ShowCustomConfirm(
		title,
		"Подтвердить",
		"Отмена",
		box,
		func(ok bool) {
			if !ok {
				return
			}
			runCleanupWithOptions(w, Options{
				Profile:           ProfileMaximum,
				BackupEventLogsTo: "",
				DryRun:            false,
				Verbose:           true,
			})
		},
		w,
	)
}

func runCleanupWithOptions(w fyne.Window, opts Options) {
	if adm, _ := isAdmin(); !adm {
		dialog.ShowInformation("Нет прав", "Запустите приложение от имени администратора.", w)
		return
	}
	go func() {
		err := ExecuteCleanup(opts)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		doneMsg := "Очистка завершена."
		if opts.BackupEventLogsTo != "" && opts.Profile == ProfileMaximum && opts.DryRun {
			doneMsg = "Экспорт завершён. Журналы сохранены в: " + opts.BackupEventLogsTo
		}
		if !opts.DryRun {
			doneMsg += "\nРекомендуется перезагрузка."
		}
		dialog.ShowInformation("Готово", doneMsg, w)
	}()
}

func profileDescription(p Profile) (string, string) {
	switch p {
	case ProfileSafe:
		return "Safe", "Что делает:\n- Удаляет ShellBags, RunMRU, ComDlg32, Jump Lists/Recent, Search RecentApps, MountPoints2, BAM значения текущего SID.\n- Не трогает Prefetch, Minidump, Event Logs.\nРиски:\n- Сброс видов папок и истории диалогов/быстрых списков.\nПодходит для мягкой очистки без потери диагностики."
	case ProfileExtended:
		return "Extended", "Что делает:\n- Всё из Safe.\n- Дополнительно чистит Prefetch/ReadyBoot/SuperFetch и Minidump.\n- Сбрасывает AppCompat Layers (режимы совместимости/админ‑запуск).\nРиски:\n- Следующая загрузка и первые запуски медленнее.\n- Потеря дампов сбоев и снятых настроек совместимости."
	case ProfileMaximum:
		return "Maximum", "Что делает:\n- Всё из Extended.\n- Очищает все журналы событий Windows.\nРиски:\n- Полная потеря аудита и истории событий (для расследований и отладки).\nРекомендуется предварительный экспорт логов, если они могут понадобиться."
	default:
		return "Неизвестный режим", "Режим не распознан."
	}
}

func showReadme(w fyne.Window) {
	msg := "Инструкция:\n" +
		"1) Запустите приложение от имени администратора.\n" +
		"2) Выберите режим (Safe / Extended / Maximum) и подтвердите действие.\n" +
		"3) После завершения перезагрузите ПК для перестроения Prefetch.\n\n" +
		"Осторожно:\n" +
		"- Extended/Maximum: чистка Prefetch/ReadyBoot замедлит первую загрузку и старт приложений.\n" +
		"- Extended: удаление Minidump лишит дампов сбоев.\n" +
		"- Maximum: очистка Event Logs удалит журналы аудита/диагностики.\n" +
		"- Очистка AppCompat Layers снимет назначенные режимы совместимости/админ‑запуска."
	dialog.ShowInformation("Read Me", msg, w)
}
