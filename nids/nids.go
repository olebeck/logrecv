package nids

import (
	"os"

	"gopkg.in/yaml.v3"
)

type NidModule struct {
	Name      string
	Libraries map[uint32]NidLibrary
}

type NidLibrary struct {
	Name      string
	Functions map[uint32]string
}

type Nids struct {
	Modules map[uint32]NidModule
}

func (n *Nids) Lookup(module, nid uint32) (name string) {
	mod, ok := n.Modules[module]
	if !ok {
		return ""
	}
	for _, lib := range mod.Libraries {
		name, ok = lib.Functions[nid]
		if !ok {
			continue
		}
		return name
	}
	return ""
}

type libraryYml struct {
	Nid       uint32            `yaml:"nid"`
	Functions map[string]uint32 `yaml:"functions"`
}

type moduleYml struct {
	Nid       uint32                `yaml:"nid"`
	Libraries map[string]libraryYml `yaml:"libraries"`
}

type nidsYml struct {
	Modules map[string]moduleYml `yaml:"modules"`
}

func LoadNids(filename string) (*Nids, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var dbYml nidsYml
	err = yaml.Unmarshal(data, &dbYml)
	if err != nil {
		return nil, err
	}

	n := Nids{
		Modules: make(map[uint32]NidModule),
	}

	for modName, mod := range dbYml.Modules {
		libs := make(map[uint32]NidLibrary)
		for libName, lib := range mod.Libraries {
			funcs := make(map[uint32]string)
			for funcName, nid := range lib.Functions {
				funcs[nid] = funcName
			}
			libs[lib.Nid] = NidLibrary{
				Name:      libName,
				Functions: funcs,
			}
		}
		n.Modules[mod.Nid] = NidModule{
			Name:      modName,
			Libraries: libs,
		}
	}

	return &n, nil
}
