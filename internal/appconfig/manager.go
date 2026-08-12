package appconfig

import "sync"

type Manager struct {
	mu      sync.RWMutex
	path    string
	current Config
}

func OpenManager(path string) (*Manager, error) {
	config, err := Load(path)
	if err != nil {
		return nil, err
	}

	return &Manager{
		path:    path,
		current: config,
	}, nil
}

func (manager *Manager) Current() Config {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	return manager.current
}

func (manager *Manager) Replace(config Config) error {
	return manager.replaceWithSave(
		config,
		save,
	)
}

func (manager *Manager) replaceWithSave(
	config Config,
	persist func(string, Config) (bool, error),
) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	committed, err := persist(
		manager.path,
		config,
	)

	if committed {
		manager.current = config
	}

	return err
}
