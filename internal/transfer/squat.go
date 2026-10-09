package transfer

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
)

type squatGuard struct {
	mu         sync.Mutex
	strikes    map[uint32]int
	banned     map[uint32]struct{}
	kickedByUs map[uint32]struct{}
	maxStrikes int
	file       string
	log        *logx.Logger
}

func newSquatGuard(file string, maxStrikes int, log *logx.Logger) *squatGuard {
	g := &squatGuard{
		strikes:    map[uint32]int{},
		banned:     map[uint32]struct{}{},
		kickedByUs: map[uint32]struct{}{},
		maxStrikes: maxStrikes,
		file:       file,
		log:        log,
	}
	g.load()
	return g
}

func (g *squatGuard) load() {
	raw, err := os.ReadFile(g.file)
	if err != nil {
		return
	}
	var ids []uint32
	if err := json.Unmarshal(raw, &ids); err != nil {
		g.log.Warnf("读取占位黑名单失败：%v", err)
		return
	}
	for _, id := range ids {
		g.banned[id] = struct{}{}
	}
	g.log.Debugf("已读取占位黑名单，共%d人", len(ids))
}

func (g *squatGuard) save() {
	g.mu.Lock()
	defer g.mu.Unlock()
	ids := make([]uint32, 0, len(g.banned))
	for id := range g.banned {
		ids = append(ids, id)
	}
	raw, err := json.Marshal(ids)
	if err != nil {
		return
	}
	if err := os.WriteFile(g.file, raw, 0o644); err != nil {
		g.log.Warnf("保存占位黑名单失败：%v", err)
	}
}

func (g *squatGuard) IsBanned(uid uint32) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.banned[uid]
	return ok
}

func (g *squatGuard) Strike(uid uint32) (int, bool) {
	g.mu.Lock()
	g.kickedByUs[uid] = struct{}{}
	g.strikes[uid]++
	n := g.strikes[uid]
	newlyBanned := false
	if n >= g.maxStrikes {
		if _, ok := g.banned[uid]; !ok {
			g.banned[uid] = struct{}{}
			newlyBanned = true
		}
	}
	g.mu.Unlock()
	if newlyBanned {
		g.save()
	}
	return n, newlyBanned
}

func (g *squatGuard) Succeeded(uid uint32) {
	g.mu.Lock()
	delete(g.strikes, uid)
	delete(g.kickedByUs, uid)
	g.mu.Unlock()
}

func (g *squatGuard) Left(uid uint32) {
	g.mu.Lock()
	if _, ours := g.kickedByUs[uid]; ours {
		delete(g.kickedByUs, uid)
	} else {
		delete(g.strikes, uid)
	}
	g.mu.Unlock()
}
