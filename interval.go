package main

import (
	"bytes"
	"errors"
	"sort"
	"strings"
)

type Interval struct {
	start, end uint32
}

type Union struct {
	intervals       []*Interval // 未合并的区间集合
	mergedIntervals []*Interval // 合并后的区间集合
}

func New() *Union {
	union := new(Union)
	union.intervals = make([]*Interval, 0)
	union.mergedIntervals = make([]*Interval, 0)
	return union
}

var (
	InvalidIPAddress = errors.New("IP address or mask was invalid")
)

func (union *Union) addRange(startIp, endIp string) error {
	if strings.ContainsAny(startIp, ".") || strings.ContainsAny(endIp, ".") {
		return InvalidIPAddress
	}
	start, err := loadip4([]byte(startIp))
	if nil != err {
		return err
	}
	end, err := loadip4([]byte(endIp))
	if nil != err {
		return err
	}
	return union.insert(&Interval{start, end})
}

func (union *Union) addCidr(cidr string) error {
	return union.addCidrByte([]byte(cidr))
}

func (union *Union) addCidrByte(cidr []byte) error {
	if bytes.IndexByte(cidr, '.') <= 0 {
		return InvalidIPAddress
	}
	start, end, err := parsecidr4(cidr)
	if nil != err {
		return err
	}
	return union.insert(&Interval{start, end})
}

func (union *Union) findByString(target string) bool {
	ipInt, err := loadip4([]byte(target))
	if nil != err {
		return false
	}
	return union.find(ipInt)
}

func (union *Union) find(target uint32) bool {
	for i := 0; i < len(union.intervals); i++ {
		if target >= union.intervals[i].start && target <= union.intervals[i].end {
			return true
		}
	}
	return false
}

func (union *Union) insert(newInterval *Interval) error {
	union.intervals = append(union.intervals, newInterval)
	left, right := newInterval.start, newInterval.end
	merged := false
	intervals := union.mergedIntervals
	res := make([]*Interval, 0)
	for _, interval := range intervals {
		if interval.start > right {
			if !merged {
				res = append(res, &Interval{left, right})
				merged = true
			}
			res = append(res, interval)
		} else if interval.end < left {
			res = append(res, interval)
		} else {
			left = min(left, interval.start)
			right = max(right, interval.end)
		}
	}
	if !merged {
		res = append(res, &Interval{left, right})
	}
	union.mergedIntervals = res
	return nil
}

func (union *Union) merge() error {
	intervals := union.intervals
	sort.Slice(intervals, func(i, j int) bool {
		return intervals[i].start < intervals[j].start || (intervals[i].start == intervals[j].start && intervals[i].end < intervals[j].end)
	})
	union.mergedIntervals = make([]*Interval, 0)
	for _, interval := range intervals {
		if len(union.mergedIntervals) == 0 || union.mergedIntervals[len(union.mergedIntervals)-1].end < interval.start {
			union.mergedIntervals = append(union.mergedIntervals, interval)
		} else {
			union.mergedIntervals[len(union.mergedIntervals)-1].end = max(union.mergedIntervals[len(union.mergedIntervals)-1].end, interval.end)
		}
	}
	return nil
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func max(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func parsecidr4(cidr []byte) (uint32, uint32, error) {
	var mask uint32
	p := bytes.IndexByte(cidr, '/')
	if p > 0 {
		for _, c := range cidr[p+1:] {
			if c < '0' || c > '9' {
				return 0, 0, InvalidIPAddress
			}
			mask = mask*10 + uint32(c-'0')
		}
		mask = 0xffffffff << (32 - mask)
		cidr = cidr[:p]
	} else {
		mask = 0xffffffff
	}
	ip, err := loadip4(cidr)
	if err != nil {
		return 0, 0, err
	}
	return ip, mask, nil
}

// loadip4 ip转int
func loadip4(ipstr []byte) (uint32, error) {
	var (
		ip  uint32
		oct uint32
		b   byte
		num byte
	)
	for _, b = range ipstr {
		switch {
		case b == '.':
			num++
			if 0xffffffff-ip < oct {
				return 0, InvalidIPAddress
			}
			ip = ip<<8 + oct
			oct = 0
		case b >= '0' && b <= '9':
			oct = oct*10 + uint32(b-'0')
			if oct > 255 {
				return 0, InvalidIPAddress
			}
		default:
			return 0, InvalidIPAddress
		}
	}
	if num != 3 {
		return 0, InvalidIPAddress
	}
	if 0xffffffff-ip < oct {
		return 0, InvalidIPAddress
	}
	return ip<<8 + oct, nil
}
