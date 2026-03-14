package types

type Flag uint64

const (
	FlagSniff     Flag = 0x0001
	FlagDrop      Flag = 0x0002
	FlagRecvOnly  Flag = 0x0004
	FlagReadOnly       = FlagRecvOnly
	FlagSendOnly  Flag = 0x0008
	FlagWriteOnly      = FlagSendOnly
	FlagNoInstall Flag = 0x0010
	FlagFragments Flag = 0x0020
)

func FlagsAll() Flag {
	return FlagSniff | FlagDrop | FlagRecvOnly | FlagSendOnly | FlagNoInstall | FlagFragments
}

func flagsExclude(flags, flag1, flag2 Flag) bool {
	return (flags & (flag1 | flag2)) != (flag1 | flag2)
}

func (f Flag) Exclude(flag1, flag2 Flag) bool {
	return flagsExclude(f, flag1, flag2)
}

func flagsValid(flags Flag) bool {
	return ((flags & ^FlagsAll()) == 0) &&
		flagsExclude(flags, FlagSniff, FlagDrop) &&
		flagsExclude(flags, FlagRecvOnly, FlagSendOnly)
}

func (f Flag) Valid() bool {
	return flagsValid(f)
}
