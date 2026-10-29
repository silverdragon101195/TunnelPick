package main

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// driverService is the service WinDivert registers the first time a handle is opened. The driver stays
// loaded after the last handle closes, so the engine stops and deletes it on exit; nothing outlives it.
const driverService = "WinDivert"

// removeDriverService stops and deletes the WinDivert driver service. When another program still holds
// a handle the driver cannot stop; the service is then only marked for deletion and goes away with it.
func removeDriverService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(driverService)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer s.Close()

	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		s.Control(svc.Stop)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	// WinDivert marks its own service for deletion as soon as the driver loads, so "already marked" is success.
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return err
	}
	return nil
}
