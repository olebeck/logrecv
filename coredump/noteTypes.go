package coredump

const (
	COREFILE_INFO = 0x00001000
	SYSTEM_INFO   = 0x00001001

	PROCESS_INFO    = 0x00001002
	THREAD_INFO     = 0x00001003
	THREAD_REG_INFO = 0x00001004
	MODULE_INFO     = 0x00001005
	LIBRARY_INFO    = 0x00001006
	MEM_BLK_INFO    = 0x00001007

	FILE_INFO      = 0x00001009
	SEMAPHORE_INFO = 0x0000100a
	EVENTFLAG_INFO = 0x0000100b
	MUTEX_INFO     = 0x0000100c
	LWMUTEX_INFO   = 0x0000100d

	MESG_PIPE_INFO = 0x00001010
	CALLBACK_INFO  = 0x00001011
	TIMER_INFO     = 0x00001013
	RWLOCK_INFO    = 0x00001014

	CONDVAR_INFO    = 0x00001015
	LWCONDVAR_INFO  = 0x00001016
	FIBER_INFO      = 0x00001017
	ULT_INFO        = 0x00001018
	META_DATA_INFO  = 0x00001019
	HW_INFO         = 0x0000101a
	STACK_INFO      = 0x0000101b
	APP_INFO        = 0x0000101c
	BUILD_VER_INFO  = 0x0000101d
	EXTNL_PROC_INFO = 0x0000101e
	BUDGET_INFO     = 0x0000101f
	APP_LIST_INFO   = 0x00001020
	DEVICE_INFO     = 0x00001021

	USER_INFO = 0x00001022 // raw data from user coredump handler

	ULT_SEMA_INFO   = 0x00001023
	ULT_MUTEX_INFO  = 0x00001024
	ULT_Q_POOL_INFO = 0x00001025
	ULT_WQPOOL_INFO = 0x00001026
	ULT_QUEUE_INFO  = 0x00001027
	ULT_RWLOCK_INFO = 0x00001028
	ULT_COND_INFO   = 0x00001029

	TTY_INFO        = 0x0000102a
	SCREENSHOT_INFO = 0x0000102b // fulldump only

	EVENT_LOG_INFO  = 0x0000102c
	SYSTEM_INFO2    = 0x0000102d // was MINI_SS_INFO = on 2.60; minidump only
	SUMMARY_INFO    = 0x0000102e
	SYS_DEVICE_INFO = 0x0000102f

	SMPL_EVENT_INFO = 0x00001030

	TTY_INFO2    = 0x00001031
	GPU_INFO     = 0x00002000 // gpu crash only
	GPU_ACT_INFO = 0x00002001 // seems to be present; but filled with 0x810 sized data on devkit in devmode only on specific gpu bug?
	KERNEL_INFO  = 0x00003000 // seems to be written by SceCoredumpForDriver_13EF8516 with NPXS19999 as app
)

func noteIdToField(c *Coredump, noteId uint32) any {
	switch noteId {
	case COREFILE_INFO:
		return &c.CorefileInfo
	case SYSTEM_INFO:
		return &c.SystemInfo
	case PROCESS_INFO:
		return &c.ProcessInfo
	case THREAD_INFO:
		return &c.ThreadInfo
	case THREAD_REG_INFO:
		return &c.ThreadRegInfo
	case MODULE_INFO:
		return &c.ModuleInfo
	case LIBRARY_INFO:
		return &c.LibraryInfo
	case MEM_BLK_INFO:
		return &c.MemblockInfo
	case FILE_INFO:
		return &c.FileInfo
	case SEMAPHORE_INFO:
		return &c.SemaphoreInfo
	case EVENTFLAG_INFO:
		return &c.EventflagInfo
	case MUTEX_INFO:
		return &c.MutexInfo
	case LWMUTEX_INFO:
		return &c.LwmutexInfo
	case MESG_PIPE_INFO:
		return &c.MsgpipeInfo
	case CALLBACK_INFO:
		return &c.CallbackInfo
	case TIMER_INFO:
		return &c.TimerInfo
	case RWLOCK_INFO:
		return &c.RwlockInfo
	case CONDVAR_INFO:
		return &c.CondvarInfo
	case LWCONDVAR_INFO:
		return &c.LwcondvarInfo
	case FIBER_INFO:
		return &c.FiberInfo
	case ULT_INFO:
		return &c.UltInfo
	case META_DATA_INFO:
		return nil
	case HW_INFO:
		return &c.HwInfo
	case STACK_INFO:
		return &c.StackInfo
	case APP_INFO:
		return &c.AppInfo
	case BUILD_VER_INFO:
		return &c.BuildVerInfo
	case EXTNL_PROC_INFO:
		return &c.ExtnlProcessInfo
	case BUDGET_INFO:
		return &c.BudgetInfo
	case APP_LIST_INFO:
		return &c.AppListInfo
	case DEVICE_INFO:
		return &c.DeviceInfo
	case USER_INFO:
		return nil
	case ULT_SEMA_INFO:
		return &c.UltSemaphoreInfo
	case ULT_MUTEX_INFO:
		return &c.UltMutexInfo
	case ULT_Q_POOL_INFO:
		return &c.UltQpoolInfo
	case ULT_WQPOOL_INFO:
		return &c.UltWqpoolInfo
	case ULT_QUEUE_INFO:
		return &c.UltQueueInfo
	case ULT_RWLOCK_INFO:
		return &c.UltRwlockInfo
	case ULT_COND_INFO:
		return &c.UltCondvarInfo
	case TTY_INFO:
		return &c.TtyInfo
	case SCREENSHOT_INFO:
		return &c.ScreenshotInfo
	case EVENT_LOG_INFO:
		return &c.EventLogInfo
	case SYSTEM_INFO2:
		return nil
	case SUMMARY_INFO:
		return nil
	case SYS_DEVICE_INFO:
		return &c.SysDeviceInfo
	case SMPL_EVENT_INFO:
		return &c.SimpleeventInfo
	case TTY_INFO2:
		return &c.TtyInfo2
	case GPU_INFO:
		return &c.GpuInfo
	case GPU_ACT_INFO:
		return nil
	case KERNEL_INFO:
		return nil
	}
	return nil
}
