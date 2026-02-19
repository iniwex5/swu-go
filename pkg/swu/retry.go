package swu

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/iniwex5/swu-go/pkg/logger"
)

// RetryConfig 重传配置
type RetryConfig struct {
	MaxRetries     int           // 最大重试次数
	InitialTimeout time.Duration // 初始超时时间
	MaxTimeout     time.Duration // 最大超时时间
	BackoffFactor  float64       // 退避因子
}

// DefaultRetryConfig 默认重传配置
// 对齐 strongSwan 默认值 (retransmit_timeout=4s, retransmit_base=1.8, retransmit_tries=5)
// 超时序列: 4s, 7.2s, 12.96s, 23.3s, 42s, 75.6s → 总计约 165s
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:     5,
		InitialTimeout: 4 * time.Second,
		MaxTimeout:     0, // 0 表示无上限，与 strongSwan retransmit_limit=0 一致
		BackoffFactor:  1.8,
	}
}

// RetryState 重传状态
type RetryState int

const (
	RetryStateOK       RetryState = iota // 成功
	RetryStateTimeout                    // 超时
	RetryStateMaxRetry                   // 达到最大重试次数
	RetryStateError                      // 其他错误
)

// RetryContext 重传上下文
type RetryContext struct {
	ctx            context.Context
	config         *RetryConfig
	currentRetry   int
	currentTimeout time.Duration
	lastMessage    []byte

	totalAttempts uint64
	totalTimeouts uint64
	totalFailures uint64
	totalSuccess  uint64
}

// NewRetryContext 创建重传上下文
func NewRetryContext(ctx context.Context, config *RetryConfig) *RetryContext {
	if config == nil {
		config = DefaultRetryConfig()
	}
	return &RetryContext{
		ctx:            ctx,
		config:         config,
		currentRetry:   0,
		currentTimeout: config.InitialTimeout,
	}
}

// SendWithRetry 发送消息并等待响应，支持超时重传
func (rc *RetryContext) SendWithRetry(
	send func([]byte) error,
	receive func(timeout time.Duration) ([]byte, error),
	message []byte,
) ([]byte, error) {
	rc.lastMessage = message
	rc.currentRetry = 0
	rc.currentTimeout = rc.config.InitialTimeout

	for rc.currentRetry <= rc.config.MaxRetries {
		// 检查 context 是否已取消
		select {
		case <-rc.ctx.Done():
			return nil, rc.ctx.Err()
		default:
		}

		// 发送消息
		if err := send(message); err != nil {
			atomic.AddUint64(&rc.totalFailures, 1)
			return nil, err
		}
		atomic.AddUint64(&rc.totalAttempts, 1)

		logger.Debug("发送消息",
			logger.Int("attempt", rc.currentRetry+1),
			logger.Int("maxAttempts", rc.config.MaxRetries+1),
			logger.Duration("timeout", rc.currentTimeout))

		// 等待响应
		response, err := receive(rc.currentTimeout)
		if err == nil {
			atomic.AddUint64(&rc.totalSuccess, 1)
			return response, nil
		}

		// 检查是否是超时
		if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
			atomic.AddUint64(&rc.totalTimeouts, 1)
			rc.currentRetry++
			// 指数退避: timeout = initialTimeout * (backoffFactor ^ try)
			rc.currentTimeout = time.Duration(float64(rc.currentTimeout) * rc.config.BackoffFactor)
			if rc.config.MaxTimeout > 0 && rc.currentTimeout > rc.config.MaxTimeout {
				rc.currentTimeout = rc.config.MaxTimeout
			}
			logger.Debug("超时，准备重传")
			continue
		}

		// 其他错误
		atomic.AddUint64(&rc.totalFailures, 1)
		return nil, err
	}

	atomic.AddUint64(&rc.totalFailures, 1)
	return nil, errors.New("达到最大重试次数")
}

type RetryStats struct {
	TotalAttempts uint64
	TotalTimeouts uint64
	TotalFailures uint64
	TotalSuccess  uint64
}

func (rc *RetryContext) Stats() RetryStats {
	return RetryStats{
		TotalAttempts: atomic.LoadUint64(&rc.totalAttempts),
		TotalTimeouts: atomic.LoadUint64(&rc.totalTimeouts),
		TotalFailures: atomic.LoadUint64(&rc.totalFailures),
		TotalSuccess:  atomic.LoadUint64(&rc.totalSuccess),
	}
}

// isTimeoutError 检查是否是超时错误
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "i/o timeout" ||
		err.Error() == "read timeout" ||
		errors.Is(err, context.DeadlineExceeded)
}

// 状态机状态定义
const (
	StateOK                          = 0
	StateTimeout                     = 1
	StateRepeat                      = 2
	StateDecodingError               = 3
	StateMandatoryInformationMissing = 4
	StateOtherError                  = 5
	StateRepeatCookie                = 6
)

// StateTransition 状态转换
type StateTransition struct {
	CurrentState int
	Event        int
	NextState    int
	Action       func() error
}

// StateMachine IKEv2 状态机
type StateMachine struct {
	currentState int
	transitions  []StateTransition
	retryCtx     *RetryContext
}

// NewStateMachine 创建状态机
func NewStateMachine(retryCtx *RetryContext) *StateMachine {
	return &StateMachine{
		currentState: StateOK,
		retryCtx:     retryCtx,
	}
}

// ProcessEvent 处理事件
func (sm *StateMachine) ProcessEvent(event int) error {
	for _, t := range sm.transitions {
		if t.CurrentState == sm.currentState && t.Event == event {
			sm.currentState = t.NextState
			if t.Action != nil {
				return t.Action()
			}
			return nil
		}
	}
	return errors.New("无效的状态转换")
}
