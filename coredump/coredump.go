package coredump

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"

	"github.com/ghostiam/binstruct"
	"github.com/sirupsen/logrus"
)

type Coredump struct {
	CorefileInfo     *CorefileInfo
	HwInfo           *HwInfo
	BuildVerInfo     *BuildVerInfo
	SystemInfo       *SystemInfo
	TtyInfo          *TtyInfo
	TtyInfo2         *TtyInfo
	ScreenshotInfo   *ScreenshotInfo
	SysDeviceInfo    *SysDeviceInfo
	AppInfo          *AppInfo
	ProcessInfo      *ProcessInfo
	DeviceInfo       *DeviceInfo
	ExtnlProcessInfo *ExtnlProcessInfo
	FileInfo         *FileInfo
	AppListInfo      *AppListInfo
	StackInfo        *StackInfo
	ModuleInfo       *ModuleInfo
	MemblockInfo     *MemblockInfo
	BudgetInfo       *BudgetInfo
	LibraryInfo      *LibraryInfo
	EventLogInfo     *EventLogInfo
	SemaphoreInfo    *SemaphoreInfo
	EventflagInfo    *EventFlagInfo
	MutexInfo        *MutexInfo
	LwmutexInfo      *LwMutexInfo
	MsgpipeInfo      *MsgpipeInfo
	CallbackInfo     *CallbackInfo
	TimerInfo        *TimerInfo
	RwlockInfo       *RwlockInfo
	CondvarInfo      *CondVarInfo
	LwcondvarInfo    *LwcondvarInfo
	SimpleeventInfo  *SmplEventInfo
	UltInfo          *UltInfo
	UltSemaphoreInfo *UltSemaInfo
	UltCondvarInfo   *UltCondvarInfo
	UltMutexInfo     *UltMutexInfo
	UltRwlockInfo    *UltRWLockInfo
	UltWqpoolInfo    *UltWQPoolInfo
	UltQpoolInfo     *UltQueuePoolInfo
	UltQueueInfo     *UltQueueInfo
	FiberInfo        *FiberInfo
	ThreadInfo       *ThreadInfo
	ThreadRegInfo    *ThreadRegInfo
	GpuInfo          *GPUInfo

	Segments []*elf.Prog
}

func ParseCoredump(data []byte) (*Coredump, error) {
	br := bytes.NewReader(data)
	gz, err := gzip.NewReader(br)
	if err == nil {
		data, err := io.ReadAll(gz)
		if err != nil {
			return nil, err
		}
		br = bytes.NewReader(data)
	}

	elfFile, err := elf.NewFile(br)
	if err != nil {
		return nil, err
	}

	cd := Coredump{}
	var notes []elfNote
	for _, prog := range elfFile.Progs {
		if prog.Type == elf.PT_NOTE {
			notes2, err := readNotesFromSegment(prog)
			if err != nil {
				return nil, err
			}
			notes = append(notes, notes2...)
		}
		if prog.Type == elf.PT_LOAD {
			cd.Segments = append(cd.Segments, prog)
		}
	}
	if notes == nil {
		return nil, fmt.Errorf("no notes")
	}

	for _, note := range notes {
		field := noteIdToField(&cd, note.Type)
		if field == nil {
			fmt.Printf("unhandled note %s\n", note.Name)
			continue
		}
		fieldValue := reflect.ValueOf(field)
		innerPtr := reflect.New(fieldValue.Type().Elem().Elem())
		fieldValue.Elem().Set(innerPtr)

		reader := binstruct.NewReaderFromBytes(note.Data, binary.LittleEndian, false)
		if err = reader.Unmarshal(innerPtr.Interface()); err != nil {
			return nil, err
		}
	}

	return &cd, nil
}

func (cd *Coredump) GetCrashThreadID() (uint32, error) {
	for _, thread := range cd.ThreadInfo.Records {
		if thread.StopReason != 0 {
			return thread.ThreadID, nil
		}
	}
	return 0, fmt.Errorf("no crashed threads")
}
func (cd *Coredump) ReadVaddr(addr uint32, size int) []byte {
	for _, prog := range cd.Segments {
		if addr >= uint32(prog.Vaddr) && addr < uint32(prog.Vaddr+prog.Memsz) {
			offsetInSegment := addr - uint32(prog.Vaddr)
			var buf = make([]byte, size)
			n, err := prog.ReadAt(buf, int64(offsetInSegment))
			if err == io.EOF && n > 0 {
				buf = buf[:n]
				err = nil
			}
			if err != nil {
				logrus.Fatal(err)
			}
			return buf
		}
	}
	return nil
}

// GetModuleInfo returns the module which contains the vaddr
func (cd *Coredump) GetModuleInfo(vaddr uint32) (*ModuleInfoInfo, *ModuleInfoSegmentinfo) {
	for _, module := range cd.ModuleInfo.Modules {
		for _, segment := range module.Segments {
			if segment.BaseAddr < vaddr && segment.BaseAddr+segment.MemorySize > vaddr {
				return &module, &segment
			}
		}
	}
	return nil, nil
}

func (cd *Coredump) IsInMainExecutable(vaddr uint32) bool {
	mainFingerprint := cd.ProcessInfo.Fingerprint
	for _, module := range cd.ModuleInfo.Modules {
		if module.Fingerprint == mainFingerprint {
			return module.Start < vaddr && module.End > vaddr
		}
	}
	return false
}

func (cd *Coredump) GetThread(threadID uint32) *ThreadInfoThread {
	for _, thread := range cd.ThreadInfo.Records {
		if thread.ThreadID == threadID {
			return &thread
		}
	}
	return nil
}

func (cd *Coredump) GetThreadRegisters(threadID uint32) *ThreadRegInfoInfo {
	for _, threadReg := range cd.ThreadRegInfo.Records {
		if threadReg.ThreadID == threadID {
			return &threadReg
		}
	}
	return nil
}
