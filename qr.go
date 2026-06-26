package main

import "fmt"

var gfExp [512]int
var gfLog [256]int

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[gfLog[a]+gfLog[b]]
}

func rsGenPoly(degree int) []int {
	g := []int{1}
	for i := 0; i < degree; i++ {

		ng := make([]int, len(g)+1)
		for j := 0; j < len(g); j++ {
			ng[j] ^= g[j]
			ng[j+1] ^= gfMul(g[j], gfExp[i])
		}
		g = ng
	}
	return g
}

func rsEncode(data []int, ecLen int) []int {
	gen := rsGenPoly(ecLen)
	res := make([]int, len(data)+ecLen)
	copy(res, data)
	for i := 0; i < len(data); i++ {
		coef := res[i]
		if coef != 0 {
			for j := 0; j < len(gen); j++ {
				res[i+j] ^= gfMul(gen[j], coef)
			}
		}
	}
	return res[len(data):]
}

type ecSpec struct {
	ecPerBlock int
	groups     [][2]int
}

var ecTable = [2][]ecSpec{
	{
		{7, [][2]int{{1, 19}}},
		{10, [][2]int{{1, 34}}},
		{15, [][2]int{{1, 55}}},
		{20, [][2]int{{1, 80}}},
		{26, [][2]int{{1, 108}}},
		{18, [][2]int{{2, 68}}},
		{20, [][2]int{{2, 78}}},
		{24, [][2]int{{2, 97}}},
		{30, [][2]int{{2, 116}}},
		{18, [][2]int{{2, 68}, {2, 69}}},
		{20, [][2]int{{4, 81}}},
		{24, [][2]int{{2, 92}, {2, 93}}},
		{26, [][2]int{{4, 107}}},
		{30, [][2]int{{3, 115}, {1, 116}}},
		{22, [][2]int{{5, 87}, {1, 88}}},
		{24, [][2]int{{5, 98}, {1, 99}}},
		{28, [][2]int{{1, 107}, {5, 108}}},
		{30, [][2]int{{5, 120}, {1, 121}}},
		{28, [][2]int{{3, 113}, {4, 114}}},
		{28, [][2]int{{3, 107}, {5, 108}}},
	},
	{
		{10, [][2]int{{1, 16}}},
		{16, [][2]int{{1, 28}}},
		{26, [][2]int{{1, 44}}},
		{18, [][2]int{{2, 32}}},
		{24, [][2]int{{2, 43}}},
		{16, [][2]int{{4, 27}}},
		{18, [][2]int{{4, 31}}},
		{22, [][2]int{{2, 38}, {2, 39}}},
		{22, [][2]int{{3, 36}, {2, 37}}},
		{26, [][2]int{{4, 43}, {1, 44}}},
		{30, [][2]int{{1, 50}, {4, 51}}},
		{22, [][2]int{{6, 36}, {2, 37}}},
		{22, [][2]int{{8, 37}, {1, 38}}},
		{24, [][2]int{{4, 40}, {5, 41}}},
		{24, [][2]int{{5, 41}, {5, 42}}},
		{28, [][2]int{{7, 45}, {3, 46}}},
		{28, [][2]int{{10, 46}, {1, 47}}},
		{26, [][2]int{{9, 43}, {4, 44}}},
		{26, [][2]int{{3, 44}, {11, 45}}},
		{26, [][2]int{{3, 41}, {13, 42}}},
	},
}

func (s ecSpec) totalDataCW() int {
	n := 0
	for _, g := range s.groups {
		n += g[0] * g[1]
	}
	return n
}

var alignPos = [][]int{
	{}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42},
	{6, 26, 46}, {6, 28, 50}, {6, 30, 54}, {6, 32, 58}, {6, 34, 62}, {6, 26, 46, 66},
	{6, 26, 48, 70}, {6, 26, 50, 74}, {6, 30, 54, 78}, {6, 30, 56, 82}, {6, 30, 58, 86}, {6, 34, 62, 90},
}

func remainderBits(v int) int {
	switch {
	case v == 1:
		return 0
	case v >= 2 && v <= 6:
		return 7
	case v >= 7 && v <= 13:
		return 0
	default:
		return 3
	}
}

func bch(data, poly int) int {
	d := data
	g := poly
	gBits := bitLen(g)
	for bitLen(d) >= gBits {
		d ^= g << (bitLen(d) - gBits)
	}
	return d
}
func bitLen(x int) int {
	n := 0
	for x != 0 {
		n++
		x >>= 1
	}
	return n
}

func formatBits(levelIdx, mask int) int {

	lvl := map[int]int{0: 0b01, 1: 0b00}[levelIdx]
	data := (lvl << 3) | mask
	rem := bch(data<<10, 0b10100110111)
	return ((data << 10) | rem) ^ 0b101010000010010
}

func versionBits(v int) int {
	rem := bch(v<<12, 0b1111100100101)
	return (v << 12) | rem
}

func buildCodewords(text string, levelIdx, version int) []int {
	spec := ecTable[levelIdx][version-1]
	totalData := spec.totalDataCW()

	var bits []int
	put := func(val, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (val>>i)&1)
		}
	}
	put(0b0100, 4)
	countBits := 8
	if version >= 10 {
		countBits = 16
	}
	put(len(text), countBits)
	for _, b := range []byte(text) {
		put(int(b), 8)
	}

	for i := 0; i < 4 && len(bits) < totalData*8; i++ {
		bits = append(bits, 0)
	}

	for len(bits)%8 != 0 {
		bits = append(bits, 0)
	}

	var cw []int
	for i := 0; i < len(bits); i += 8 {
		v := 0
		for j := 0; j < 8; j++ {
			v = (v << 1) | bits[i+j]
		}
		cw = append(cw, v)
	}

	pad := []int{0xEC, 0x11}
	for i := 0; len(cw) < totalData; i++ {
		cw = append(cw, pad[i%2])
	}

	var dataBlocks, ecBlocks [][]int
	idx := 0
	for _, g := range spec.groups {
		for b := 0; b < g[0]; b++ {
			blk := cw[idx : idx+g[1]]
			idx += g[1]
			dataBlocks = append(dataBlocks, blk)
			ecBlocks = append(ecBlocks, rsEncode(blk, spec.ecPerBlock))
		}
	}

	var out []int
	maxData := 0
	for _, b := range dataBlocks {
		if len(b) > maxData {
			maxData = len(b)
		}
	}
	for i := 0; i < maxData; i++ {
		for _, b := range dataBlocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := 0; i < spec.ecPerBlock; i++ {
		for _, b := range ecBlocks {
			out = append(out, b[i])
		}
	}
	return out
}

type qrMat struct {
	size int
	mod  [][]bool
	res  [][]bool
}

func newMat(size int) *qrMat {
	m := &qrMat{size: size}
	m.mod = make([][]bool, size)
	m.res = make([][]bool, size)
	for i := range m.mod {
		m.mod[i] = make([]bool, size)
		m.res[i] = make([]bool, size)
	}
	return m
}

func (m *qrMat) set(r, c int, dark, reserved bool) {
	m.mod[r][c] = dark
	if reserved {
		m.res[r][c] = true
	}
}

func (m *qrMat) placeFinder(r, c int) {
	for dr := -1; dr <= 7; dr++ {
		for dc := -1; dc <= 7; dc++ {
			rr, cc := r+dr, c+dc
			if rr < 0 || rr >= m.size || cc < 0 || cc >= m.size {
				continue
			}
			dark := false
			if dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 {

				if dr == 0 || dr == 6 || dc == 0 || dc == 6 ||
					(dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4) {
					dark = true
				}
			}
			m.set(rr, cc, dark, true)
		}
	}
}

func (m *qrMat) placeAlignment(r, c int) {
	for dr := -2; dr <= 2; dr++ {
		for dc := -2; dc <= 2; dc++ {
			dark := dr == -2 || dr == 2 || dc == -2 || dc == 2 || (dr == 0 && dc == 0)
			m.set(r+dr, c+dc, dark, true)
		}
	}
}

func buildMatrix(text string, levelIdx, version int) *qrMat {
	size := 17 + 4*version
	m := newMat(size)

	m.placeFinder(0, 0)
	m.placeFinder(0, size-7)
	m.placeFinder(size-7, 0)

	for i := 8; i < size-8; i++ {
		dark := i%2 == 0
		if !m.res[6][i] {
			m.set(6, i, dark, true)
		}
		if !m.res[i][6] {
			m.set(i, 6, dark, true)
		}
	}

	pos := alignPos[version-1]
	n := len(pos)
	for i, r := range pos {
		for j, c := range pos {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			m.placeAlignment(r, c)
		}
	}

	m.set(4*version+9, 8, true, true)

	reserveFormat(m)

	if version >= 7 {
		reserveVersion(m)
	}

	cw := buildCodewords(text, levelIdx, version)
	placeData(m, cw)

	best, bestPen := 0, 1<<30
	var bestMat *qrMat
	for mask := 0; mask < 8; mask++ {
		cand := m.clone()
		applyMask(cand, mask)
		placeFormat(cand, levelIdx, mask)
		if version >= 7 {
			placeVersion(cand, version)
		}
		if p := penalty(cand); p < bestPen {
			bestPen, best, bestMat = p, mask, cand
		}
	}
	_ = best
	return bestMat
}

func (m *qrMat) clone() *qrMat {
	n := newMat(m.size)
	for r := 0; r < m.size; r++ {
		copy(n.mod[r], m.mod[r])
		copy(n.res[r], m.res[r])
	}
	return n
}

func reserveFormat(m *qrMat) {
	s := m.size
	for i := 0; i <= 8; i++ {
		if i != 6 {
			markRes(m, 8, i)
			markRes(m, i, 8)
		}
	}
	for i := 0; i < 8; i++ {
		markRes(m, 8, s-1-i)
		markRes(m, s-1-i, 8)
	}
}
func markRes(m *qrMat, r, c int) { m.res[r][c] = true }

func reserveVersion(m *qrMat) {
	s := m.size
	for r := 0; r < 6; r++ {
		for c := s - 11; c < s-8; c++ {
			m.res[r][c] = true
			m.res[c][r] = true
		}
	}
}

func placeData(m *qrMat, cw []int) {
	s := m.size

	bitAt := func(i int) bool {
		byteI := i / 8
		if byteI >= len(cw) {
			return false
		}
		return (cw[byteI]>>(7-(i%8)))&1 == 1
	}
	bitIdx := 0
	up := true
	for col := s - 1; col > 0; col -= 2 {
		if col == 6 {
			col--
		}
		for i := 0; i < s; i++ {
			var row int
			if up {
				row = s - 1 - i
			} else {
				row = i
			}
			for _, c := range []int{col, col - 1} {
				if !m.res[row][c] {
					m.mod[row][c] = bitAt(bitIdx)
					bitIdx++
				}
			}
		}
		up = !up
	}
}

func maskFn(mask, r, c int) bool {
	switch mask {
	case 0:
		return (r+c)%2 == 0
	case 1:
		return r%2 == 0
	case 2:
		return c%3 == 0
	case 3:
		return (r+c)%3 == 0
	case 4:
		return (r/2+c/3)%2 == 0
	case 5:
		return (r*c)%2+(r*c)%3 == 0
	case 6:
		return ((r*c)%2+(r*c)%3)%2 == 0
	case 7:
		return ((r+c)%2+(r*c)%3)%2 == 0
	}
	return false
}

func applyMask(m *qrMat, mask int) {
	for r := 0; r < m.size; r++ {
		for c := 0; c < m.size; c++ {
			if !m.res[r][c] && maskFn(mask, r, c) {
				m.mod[r][c] = !m.mod[r][c]
			}
		}
	}
}

func placeFormat(m *qrMat, levelIdx, mask int) {
	bitsVal := formatBits(levelIdx, mask)
	s := m.size
	get := func(i int) bool { return (bitsVal>>(14-i))&1 == 1 }

	for i := 0; i <= 5; i++ {
		m.mod[8][i] = get(i)
	}
	m.mod[8][7] = get(6)
	m.mod[8][8] = get(7)
	m.mod[7][8] = get(8)
	for i := 9; i <= 14; i++ {
		m.mod[14-i][8] = get(i)
	}

	for i := 0; i <= 7; i++ {
		m.mod[s-1-i][8] = get(i)
	}
	for i := 8; i <= 14; i++ {
		m.mod[8][s-15+i] = get(i)
	}

	m.mod[s-8][8] = true
}

func placeVersion(m *qrMat, version int) {
	bitsVal := versionBits(version)
	s := m.size
	for i := 0; i < 18; i++ {
		bit := (bitsVal>>i)&1 == 1
		r, c := i/3, i%3
		m.mod[r][s-11+c] = bit
		m.mod[s-11+c][r] = bit
	}
}

func penalty(m *qrMat) int {
	s := m.size
	pen := 0

	for r := 0; r < s; r++ {
		run, prev := 0, false
		for c := 0; c < s; c++ {
			if c == 0 || m.mod[r][c] == prev {
				run++
			} else {
				run = 1
			}
			prev = m.mod[r][c]
			if run == 5 {
				pen += 3
			} else if run > 5 {
				pen++
			}
		}
	}
	for c := 0; c < s; c++ {
		run, prev := 0, false
		for r := 0; r < s; r++ {
			if r == 0 || m.mod[r][c] == prev {
				run++
			} else {
				run = 1
			}
			prev = m.mod[r][c]
			if run == 5 {
				pen += 3
			} else if run > 5 {
				pen++
			}
		}
	}

	for r := 0; r < s-1; r++ {
		for c := 0; c < s-1; c++ {
			v := m.mod[r][c]
			if m.mod[r][c+1] == v && m.mod[r+1][c] == v && m.mod[r+1][c+1] == v {
				pen += 3
			}
		}
	}

	pat1 := []bool{true, false, true, true, true, false, true, false, false, false, false}
	pat2 := []bool{false, false, false, false, true, false, true, true, true, false, true}
	match := func(line []bool, start int, pat []bool) bool {
		for k := 0; k < len(pat); k++ {
			if line[start+k] != pat[k] {
				return false
			}
		}
		return true
	}
	for r := 0; r < s; r++ {
		line := m.mod[r]
		for c := 0; c+11 <= s; c++ {
			if match(line, c, pat1) || match(line, c, pat2) {
				pen += 40
			}
		}
	}
	for c := 0; c < s; c++ {
		col := make([]bool, s)
		for r := 0; r < s; r++ {
			col[r] = m.mod[r][c]
		}
		for r := 0; r+11 <= s; r++ {
			if match(col, r, pat1) || match(col, r, pat2) {
				pen += 40
			}
		}
	}

	dark := 0
	for r := 0; r < s; r++ {
		for c := 0; c < s; c++ {
			if m.mod[r][c] {
				dark++
			}
		}
	}
	ratio := dark * 100 / (s * s)
	dev := abs(ratio-50) / 5
	pen += dev * 10
	return pen
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func qrMatrix(text string) (*qrMat, error) {
	for version := 1; version <= 20; version++ {
		for _, levelIdx := range []int{1, 0} {
			spec := ecTable[levelIdx][version-1]
			countBits := 8
			if version >= 10 {
				countBits = 16
			}
			capacityBits := spec.totalDataCW()*8 - 4 - countBits
			if len(text)*8 <= capacityBits {
				return buildMatrix(text, levelIdx, version), nil
			}
		}
	}
	return nil, fmt.Errorf("data too long (exceeds qr v20)")
}