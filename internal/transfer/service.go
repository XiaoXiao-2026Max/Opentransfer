package transfer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
	"sync"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/auth"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/config"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/lobby"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/netease"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/signaling"
	"github.com/pion/webrtc/v4"
)

type Service struct {
	ctx     context.Context
	cancel  context.CancelFunc
	closing bool
	dumpMu  sync.Mutex
	cfg     *config.Config
	log     *logx.Logger
	rng     *mathrand.Rand

	protocolID int
	localID    uint64
	server     netease.TransferServer
	creds      auth.Credentials

	lobbyCli lobbyConnection
	sig      *signaling.Client
	script   *script
	squat    *squatGuard

	mu       sync.Mutex
	guests   map[uint32]*guest
	byRemote map[uint64]*guest
	ice      []webrtc.ICEServer
	capacity byte
	roomID   uint32

	staleRetries int

	fatal chan error
}

type peerConnection interface {
	Send([]byte) error
	Close()
	HandleSignal(string)
}

type lobbyConnection interface {
	CreateRoom(lobby.RoomOptions) error
	CloseRoom() error
	KickOut(uint32) error
	SayReady(string, string, string, string, bool) error
	ChangeRoomInfo(lobby.ChangeRoomInfo) error
	SetTagList([]byte) error
	SetDisplayModList([]uint64) error
	UpdatePerformance(byte, byte) error
	Closed() <-chan struct{}
	Close() error
}

type backendConnection interface {
	Send([]byte) error
	Close() error
}

type guest struct {
	ctx               context.Context
	cancel            context.CancelFunc
	closed            bool
	transferAttempted bool
	backendConnecting bool
	pendingBytes      int
	uid               uint32
	remote            uint64
	peer              peerConnection
	timer             *time.Timer

	mu          sync.Mutex
	negotiated  bool
	scriptSent  bool
	inbound     int
	transferred bool
	target      target

	backendSendMu sync.Mutex
	rak           backendConnection
	rakReady      bool
	pending       [][]byte
}

func New(cfg *config.Config) (*Service, error) {
	log := logx.New("service")
	rng := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	sc, err := buildScript(cfg, rng, log)
	if err != nil {
		return nil, err
	}
	return &Service{
		cfg:      cfg,
		ctx:      context.Background(),
		log:      log,
		rng:      rng,
		script:   sc,
		squat:    newSquatGuard(cfg.Kick.SquatBanFile, cfg.Kick.SquatStrikes, logx.New("squat")),
		guests:   map[uint32]*guest{},
		byRemote: map[uint64]*guest{},
		capacity: cfg.CapacityValue(),
		fatal:    make(chan error, 1),
	}, nil
}

func randomNethernetID() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano() & 0x7FFFFFFFFFFFFFFE)
	}
	return binary.BigEndian.Uint64(b[:]) % 9223372036854775806
}

func (s *Service) Run(ctx context.Context) error {
	for attempt := 0; ; attempt++ {

		run, err := New(s.cfg)
		if err != nil {
			return err
		}
		run.squat = s.squat
		run.ctx, run.cancel = context.WithCancel(ctx)
		err = run.runOnce(run.ctx)
		run.cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return nil
		}
		delay := time.Duration(attempt+1) * 3 * time.Second
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		s.log.Warnf("大厅连接中断，%v 后重新建房：%v", delay, err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

func (s *Service) runOnce(ctx context.Context) error {
	s.mu.Lock()
	s.guests = map[uint32]*guest{}
	s.byRemote = map[uint64]*guest{}
	s.roomID = 0
	s.staleRetries = 0
	s.capacity = s.cfg.CapacityValue()
	s.mu.Unlock()
	s.fatal = make(chan error, 1)

	if err := s.resolveProtocolID(ctx); err != nil {
		return err
	}
	if err := s.pickLobbyServer(ctx); err != nil {
		return err
	}
	s.localID = randomNethernetID()

	if err := s.resolveCredentials(ctx); err != nil {
		return err
	}

	address := s.cfg.LobbyAddress
	if address == "" {
		address = s.server.Address(s.rng)
	}
	s.log.Debugf("连接大厅：%s，信令端口：%d", address, s.signalPort())

	cli, err := lobby.Dial(ctx, address, lobby.Auth{
		UID:      s.creds.UID,
		TokenMD5: s.creds.TokenMD5(),
		Nickname: s.nickname(),
		Platform: s.platformByte(),
	}, lobby.Handlers{
		OnLoggedIn: func() { s.onLoggedIn(ctx) },
		OnLoginFailed: func(code byte) {
			if code == lobby.ErrForbidden {
				s.log.Errorf("大厅拒绝登录，请检查账号昵称")
			}
			s.failf("大厅登录失败，错误码：%d（%s）", code, lobby.ErrCodeText(code))
		},
		OnCreateRoom: s.onCreateRoom,
		OnGuestJoin:  s.onGuestJoin,
		OnGuestLeave: s.onGuestLeave,
		OnDisconnect: func(err error) { s.failf("大厅连接断开: %v", err) },
	})
	if err != nil {
		return err
	}
	s.lobbyCli = cli
	cli.SendLoginProfile = s.cfg.SendLoginProfileValue()
	defer s.shutdown()

	if err := cli.Login(); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-s.fatal:
		return err
	case <-cli.Closed():
		return fmt.Errorf("大厅连接已关闭: %v", cli.Err())
	}
}

func (s *Service) failf(format string, args ...any) {
	err := fmt.Errorf(format, args...)
	select {
	case s.fatal <- err:
	default:
	}
}

func (s *Service) shutdown() {
	s.mu.Lock()
	s.closing = true
	if s.cancel != nil {
		s.cancel()
	}
	guests := make([]*guest, 0, len(s.guests))
	for _, g := range s.guests {
		guests = append(guests, g)
	}
	s.guests = map[uint32]*guest{}
	s.byRemote = map[uint64]*guest{}
	sig := s.sig
	s.mu.Unlock()

	for _, g := range guests {
		s.closeGuest(g)
	}
	if sig != nil {
		_ = sig.Close()
	}
	if s.lobbyCli != nil {
		if s.roomID != 0 {
			if err := s.lobbyCli.CloseRoom(); err != nil {
				s.log.Warnf("关闭房间失败：%v", err)
			} else {
				s.log.Infof("房间%d已关闭", s.roomID)
				time.Sleep(400 * time.Millisecond)
			}
		}
		_ = s.lobbyCli.Close()
	}
}
