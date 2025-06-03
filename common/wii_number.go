package common

func getByteU64(value uint64, shift uint8) uint8 {
	return (uint8)(value >> (shift * 8))
}

func insertByte64(value uint64, shift uint8, byte uint8) uint64 {
	var mask uint64 = 0x00000000000000FF << (shift * 8)
	var inst uint64 = uint64(byte) << (shift * 8)
	return (value & ^mask) | inst
}

var (
	cfcTable2 = [8]uint8{0x1, 0x5, 0x0, 0x4, 0x2, 0x3, 0x6, 0x7}
	cfcTable1 = [16]uint8{0x4, 0xB, 0x7, 0x9, 0xF, 0x1, 0xD, 0x3,
		0xC, 0x2, 0x6, 0xE, 0x8, 0x0, 0xA, 0x5}
	cfcTable1Inv = [16]uint8{0xD, 0x5, 0x9, 0x7, 0x0, 0xF, // 0xE?
		0xA, 0x2,
		0xC, 0x3, 0xE, 0x1, 0x8, 0x6, 0xB, 0x4}
)

func checkCRC(mix_id uint64) uint64 {
	var ctr int = 0
	for ctr = 0; ctr <= 42; ctr++ {
		var value uint64 = mix_id >> uint64(52-ctr)
		if value&1 != 0 {
			value = 0x0000000000000635 << uint64(42-ctr)
			mix_id ^= value
		}
	}
	return mix_id
}

func getUnscrambleID(nwc24Id uint64) uint64 {
	var mixId uint64 = nwc24Id

	mixId &= 0x001FFFFFFFFFFFFF
	mixId ^= 0x00005E5E5E5E5E5E
	mixId &= 0x001FFFFFFFFFFFFF

	var mixIdCopy2 uint64 = mixId

	mixIdCopy2 ^= 0xFF
	mixIdCopy2 = (mixId << 5) & 0x20

	mixId |= mixIdCopy2 << 48
	mixId >>= 1

	mixIdCopy2 = mixId

	for i := 0; i <= 5; i++ {
		mixId = insertByte64(mixId, uint8(i), uint8(mixIdCopy2>>(i*8)))
	}

	for i := 0; i <= 5; i++ {
		v := uint8(mixId >> (i * 8))
		v = ((cfcTable1Inv[(v>>4)&0xF]) << 4) | (cfcTable1Inv[v&0xF])
		mixId = insertByte64(mixId, uint8(i), v&0xff)
	}

	mixIdCopy3 := mixId >> 0x20
	mixIdCopy4 := mixId>>0x16 | (mixIdCopy3&0x7FF)<<10
	mixId = mixId*0x400 | (mixIdCopy3 >> 0xb & 0x3FF)
	mixId = (mixIdCopy4 << 32) | mixId
	return mixId ^ 0x0000B3B3B3B3B3B3
}

func DecodeWiiNumber(cfc uint64, hollywoodId *uint32, idCtr *uint16, hardwareModel *uint8, areaCode *uint8, crc *uint16) uint64 {
	var unscrambled uint64 = getUnscrambleID(cfc)
	if hardwareModel != nil {
		*hardwareModel = uint8((unscrambled >> 47) & 7)
	}
	if areaCode != nil {
		*areaCode = uint8((unscrambled >> 50) & 7)
	}
	if hollywoodId != nil {
		*hollywoodId = uint32((unscrambled >> 15) & 0xFFFFFFFF)
	}
	if idCtr != nil {
		*idCtr = uint16((unscrambled >> 10) & 0x1F)
	}
	if crc != nil {
		*crc = uint16(cfc & 0x3FF)
	}
	return unscrambled
}
