//go:build windows

package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type Profile int

const (
	ProfileSafe Profile = iota + 1
	ProfileExtended
	ProfileMaximum
)

type Options struct {
	Profile           Profile
	BackupEventLogsTo string
	DryRun            bool
	Verbose           bool
}

func mustAdminOrErr() error {
	ok, err := isAdmin()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("нужны права администратора")
	}
	return nil
}

func isAdmin() (bool, error) {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	); err != nil {
		return false, err
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false, err
	}
	return member, nil
}

func currentUserSID() (string, error) {
	token := windows.Token(0)
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

func runCmd(name string, args []string, verbose bool) error {
	if verbose {
		log.Printf("exec: %s %s\n", name, strings.Join(args, " "))
	}
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if verbose {
			log.Printf("WARN command failed: %s %v: %s", name, err, stderr.String())
		}
		return err
	}
	return nil
}

func regDeleteKey(path string, recurse bool, dry, verbose bool) {
	if verbose {
		log.Printf("REG DELETE %s (recurse=%v)", path, recurse)
	}
	if dry {
		return
	}
	if recurse {
		_ = runCmd("reg", []string{"delete", path, "/f"}, verbose)
	} else {
		_ = runCmd("reg", []string{"delete", path, "/va", "/f"}, verbose)
	}
}

func regEnsureKey(path string, dry, verbose bool) {
	if verbose {
		log.Printf("REG ADD %s", path)
	}
	if dry {
		return
	}
	_ = runCmd("reg", []string{"add", path, "/f"}, verbose)
}

func regKeyExists(path string) bool {
	root, sub, err := splitRoot(path)
	if err != nil {
		return false
	}
	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func splitRoot(path string) (registry.Key, string, error) {
	up := strings.ToUpper(path)
	switch {
	case strings.HasPrefix(up, "HKLM\\"):
		return registry.LOCAL_MACHINE, path[5:], nil
	case strings.HasPrefix(up, "HKCU\\"):
		return registry.CURRENT_USER, path[5:], nil
	case strings.HasPrefix(up, "HKCR\\"):
		return registry.CLASSES_ROOT, path[5:], nil
	case strings.HasPrefix(up, "HKU\\"):
		return registry.USERS, path[4:], nil
	case strings.HasPrefix(up, "HKCC\\"):
		return registry.CURRENT_CONFIG, path[5:], nil
	default:
		return 0, "", errors.New("unsupported root")
	}
}

func ExecuteCleanup(opts Options) error {
	if err := mustAdminOrErr(); err != nil {
		return err
	}

	// Safe
	clearShellbags(opts)
	clearExplorerRunMRU(opts)
	clearComDlg32(opts)
	clearJumpListsAndRecent(opts)
	clearRADARDiagnosedApplications(opts)
	clearAppCompatCache(opts)
	clearAppCompatFlagsStore(opts)

	if sid, err := currentUserSID(); err == nil {
		clearSearchRecentApps(opts, sid)
		clearMountPoints2(opts, sid)
		clearBAM(opts, sid)
	}

	// Extended/Maximum
	if opts.Profile != ProfileSafe {
		clearUserAssist(opts)
		clearPrefetchAndReadyBoot(opts)
		clearMinidump(opts)
		clearAppCompatLayers(opts)
	}

	// Maximum
	if opts.Profile == ProfileMaximum {
		if opts.DryRun && opts.BackupEventLogsTo != "" {
			exportAllEventLogs(opts)
		} else {
			clearAllEventLogs(opts)
		}
	}

	return nil
}

func clearShellbags(opts Options) {
	regDeleteKey(`HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`, false, opts.DryRun, opts.Verbose)
	regDeleteKey(`HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`, true, opts.DryRun, opts.Verbose)
	regDeleteKey(`HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags`, true, opts.DryRun, opts.Verbose)
	regDeleteKey(`HKCU\Software\Microsoft\Windows\Shell\BagMRU`, true, opts.DryRun, opts.Verbose)
	regDeleteKey(`HKCU\Software\Microsoft\Windows\Shell\Bags`, true, opts.DryRun, opts.Verbose)
}

func clearExplorerRunMRU(opts Options) {
	regDeleteKey(`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, false, opts.DryRun, opts.Verbose)
}

func clearComDlg32(opts Options) {
	regDeleteKey(`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\FirstFolder`, false, opts.DryRun, opts.Verbose)
	regDeleteKey(`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`, false, opts.DryRun, opts.Verbose)
	regDeleteKey(`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy`, false, opts.DryRun, opts.Verbose)
	regDeleteKey(`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`, true, opts.DryRun, opts.Verbose)
	regEnsureKey(`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`, opts.DryRun, opts.Verbose)
}

func clearUserAssist(opts Options) {
	regDeleteKey(`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`, true, opts.DryRun, opts.Verbose)
	regEnsureKey(`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`, opts.DryRun, opts.Verbose)
}

func clearAppCompatCache(opts Options) {
	regDeleteKey(`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, false, opts.DryRun, opts.Verbose)
	regDeleteKey(`HKLM\SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache`, false, opts.DryRun, opts.Verbose)
}

func clearRADARDiagnosedApplications(opts Options) {
	regDeleteKey(`HKLM\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications`, true, opts.DryRun, opts.Verbose)
	regEnsureKey(`HKLM\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications`, opts.DryRun, opts.Verbose)
}

func clearSearchRecentApps(opts Options, sid string) {
	key := `HKU\` + sid + `\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`
	regDeleteKey(key, true, opts.DryRun, opts.Verbose)
	regEnsureKey(key, opts.DryRun, opts.Verbose)
}

func clearMountPoints2(opts Options, sid string) {
	key := `HKU\` + sid + `\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`
	regDeleteKey(key, true, opts.DryRun, opts.Verbose)
	regEnsureKey(key, opts.DryRun, opts.Verbose)
}

func clearAppCompatFlagsStore(opts Options) {
	// noop — при необходимости можно расширить
}

func clearAppCompatLayers(opts Options) {
	if sid, err := currentUserSID(); err == nil {
		regDeleteKey(`HKU\`+sid+`\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`, false, opts.DryRun, opts.Verbose)
	}
}

func clearBAM(opts Options, sid string) {
	paths := []string{
		`HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\` + sid,
		`HKLM\SYSTEM\ControlSet001\Services\bam\State\UserSettings\` + sid,
	}
	for _, p := range paths {
		regDeleteKey(p, false, opts.DryRun, opts.Verbose)
	}
}

func removeFiles(globs []string, opts Options) {
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, f := range matches {
			if opts.Verbose {
				log.Printf("DEL %s\n", f)
			}
			if opts.DryRun {
				continue
			}
			_ = os.Remove(f)
		}
	}
}

func clearJumpListsAndRecent(opts Options) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return
	}
	removeFiles([]string{
		filepath.Join(appdata, `Microsoft\Windows\Recent\*.*`),
		filepath.Join(appdata, `Microsoft\Windows\Recent\CustomDestinations\*.*`),
		filepath.Join(appdata, `Microsoft\Windows\Recent\AutomaticDestinations\*.*`),
	}, opts)
}

func clearPanther(opts Options) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	removeFiles([]string{
		filepath.Join(root, `Panther\*.*`),
	}, opts)
}

func clearAppCompatProgramsReports(opts Options) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	removeFiles([]string{
		filepath.Join(root, `appcompat\Programs\*.txt`),
		filepath.Join(root, `appcompat\Programs\*.xml`),
		filepath.Join(root, `appcompat\Programs\Install\*.txt`),
		filepath.Join(root, `appcompat\Programs\Install\*.xml`),
	}, opts)
}

func clearPrefetchAndReadyBoot(opts Options) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	removeFiles([]string{
		filepath.Join(root, `Prefetch\*.pf`),
		filepath.Join(root, `Prefetch\*.ini`),
		filepath.Join(root, `Prefetch\*.7db`),
		filepath.Join(root, `Prefetch\*.ebd`),
		filepath.Join(root, `Prefetch\*.bin`),
		filepath.Join(root, `Prefetch\*.db`),
		filepath.Join(root, `Prefetch\ReadyBoot\*.fx`),
	}, opts)
}

func clearMinidump(opts Options) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	removeFiles([]string{
		filepath.Join(root, `Minidump\*.*`),
	}, opts)
}

func listEventLogs(verbose bool) []string {
	cmd := exec.Command("wevtutil", "el")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		if verbose {
			log.Printf("wevtutil el failed: %v", err)
		}
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	var logs []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			logs = append(logs, l)
		}
	}
	return logs
}

func exportAllEventLogs(opts Options) {
	if opts.BackupEventLogsTo == "" {
		return
	}
	_ = os.MkdirAll(opts.BackupEventLogsTo, 0o755)
	logs := listEventLogs(opts.Verbose)
	for _, lg := range logs {
		dst := filepath.Join(opts.BackupEventLogsTo, safeFileName(lg)+".evtx")
		_ = runCmd("wevtutil", []string{"epl", lg, dst, "/ow:true"}, opts.Verbose)
	}
}

func ExportAllEventLogsWithProgress(opts Options, needOverwrite bool, onProgress func(done, total int, name string)) {
	if opts.BackupEventLogsTo == "" {
		return
	}
	_ = os.MkdirAll(opts.BackupEventLogsTo, 0o755)
	logs := listEventLogs(opts.Verbose)
	total := len(logs)
	for i, lg := range logs {
		dst := filepath.Join(opts.BackupEventLogsTo, safeFileName(lg)+".evtx")
		args := []string{"epl", lg, dst}
		if needOverwrite {
			args = append(args, "/ow:true")
		}
		_ = runCmd("wevtutil", args, opts.Verbose)
		if onProgress != nil {
			onProgress(i+1, total, lg)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func clearAllEventLogs(opts Options) {
	logs := listEventLogs(opts.Verbose)
	for _, lg := range logs {
		if opts.BackupEventLogsTo != "" {
			dst := filepath.Join(opts.BackupEventLogsTo, safeFileName(lg)+".evtx")
			_ = runCmd("wevtutil", []string{"epl", lg, dst, "/ow:true"}, opts.Verbose)
		}
		_ = runCmd("wevtutil", []string{"cl", lg}, opts.Verbose)
	}
}

func safeFileName(s string) string {
	r := strings.NewReplacer("\\", "_", "/", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	return r.Replace(s)
}

func appDir() string {
	exe, err := os.Executable()
	if err != nil {
		dir, _ := os.Getwd()
		return dir
	}
	return filepath.Dir(exe)
}

// Открыть отдельную консоль для визуального лога экспорта.
func OpenConsoleForLogs() {
	_ = exec.Command("cmd.exe", "/k", "title Экспорт журналов (лог) && echo Экспорт запущен...").Start()
}

// Проценты для UI
func percent(done, total int) int {
	if total <= 0 {
		return 100
	}
	return int(float64(done) / float64(total) * 100.0)
}
