// SPDX-License-Identifier: AGPL-3.0-only
// Provenance-includes-location: https://github.com/cortexproject/cortex/blob/master/pkg/util/push/push.go
// Provenance-includes-license: Apache-2.0
// Provenance-includes-copyright: The Cortex Authors.

package distributor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-kit/log/level"
	"github.com/grafana/dskit/httpgrpc"
	"github.com/grafana/dskit/middleware"
	"github.com/grafana/dskit/tenant"

	"github.com/grafana/mimir/pkg/mimirpb"
	"github.com/grafana/mimir/pkg/util"
	"github.com/grafana/mimir/pkg/util/globalerror"
	"github.com/grafana/mimir/pkg/util/log"
	"github.com/grafana/mimir/pkg/util/validation"
)

// PushFunc defines the type of the push. It is similar to http.HandlerFunc.
type PushFunc func(ctx context.Context, req *Request) error

// parserFunc defines how to read the body the request from an HTTP request
type parserFunc func(ctx context.Context, r *http.Request, maxSize int, buffer []byte, req *mimirpb.PreallocWriteRequest) ([]byte, error)

// Wrap a slice in a struct so we can store a pointer in sync.Pool
type bufHolder struct {
	buf []byte
}

var bufferPool = sync.Pool{
	New: func() interface{} { return &bufHolder{buf: make([]byte, 256*1024)} },
}

const (
	SkipLabelNameValidationHeader = "X-Mimir-SkipLabelNameValidation"
	statusClientClosedRequest     = 499
)

// Handler is a http.Handler which accepts WriteRequests.
func Handler(
	maxRecvMsgSize int,
	sourceIPs *middleware.SourceIPExtractor,
	allowSkipLabelNameValidation bool,
	limits *validation.Overrides,
	retryCfg *RetryConfig,
	push PushFunc,
) http.Handler {
	return handler(maxRecvMsgSize, sourceIPs, allowSkipLabelNameValidation, limits, retryCfg, push, func(ctx context.Context, r *http.Request, maxRecvMsgSize int, dst []byte, req *mimirpb.PreallocWriteRequest) ([]byte, error) {
		res, err := util.ParseProtoReader(ctx, r.Body, int(r.ContentLength), maxRecvMsgSize, dst, req, util.RawSnappy)
		if errors.Is(err, util.MsgSizeTooLargeErr{}) {
			err = distributorMaxWriteMessageSizeErr{actual: int(r.ContentLength), limit: maxRecvMsgSize}
		}
		return res, err
	})
}

type distributorMaxWriteMessageSizeErr struct {
	actual, limit int
}

func (e distributorMaxWriteMessageSizeErr) Error() string {
	msgSizeDesc := fmt.Sprintf(" of %d bytes", e.actual)
	if e.actual < 0 {
		msgSizeDesc = ""
	}
	return globalerror.DistributorMaxWriteMessageSize.MessageWithPerInstanceLimitConfig(fmt.Sprintf("the incoming push request has been rejected because its message size%s is larger than the allowed limit of %d bytes", msgSizeDesc, e.limit), "distributor.max-recv-msg-size")
}

func handler(
	maxRecvMsgSize int,
	sourceIPs *middleware.SourceIPExtractor,
	allowSkipLabelNameValidation bool,
	limits *validation.Overrides,
	retryCfg *RetryConfig,
	push PushFunc,
	parser parserFunc,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := log.WithContext(ctx, log.Logger)
		if sourceIPs != nil {
			source := sourceIPs.Get(r)
			if source != "" {
				ctx = util.AddSourceIPsToOutgoingContext(ctx, source)
				logger = log.WithSourceIPs(source, logger)
			}
		}
		supplier := func() (*mimirpb.WriteRequest, func(), error) {
			bufHolder := bufferPool.Get().(*bufHolder)
			var req mimirpb.PreallocWriteRequest
			buf, err := parser(ctx, r, maxRecvMsgSize, bufHolder.buf, &req)
			if err != nil {
				// Check for httpgrpc error, default to client error if parsing failed
				if _, ok := httpgrpc.HTTPResponseFromError(err); !ok {
					err = httpgrpc.Errorf(http.StatusBadRequest, err.Error())
				}

				bufferPool.Put(bufHolder)
				return nil, nil, err
			}
			// If decoding allocated a bigger buffer, put that one back in the pool.
			if buf = buf[:cap(buf)]; len(buf) > len(bufHolder.buf) {
				bufHolder.buf = buf
			}

			if allowSkipLabelNameValidation {
				req.SkipLabelNameValidation = req.SkipLabelNameValidation && r.Header.Get(SkipLabelNameValidationHeader) == "true"
			} else {
				req.SkipLabelNameValidation = false
			}

			cleanup := func() {
				mimirpb.ReuseSlice(req.Timeseries)
				bufferPool.Put(bufHolder)
			}
			return &req.WriteRequest, cleanup, nil
		}
		req := newRequest(supplier)
		if err := push(ctx, req); err != nil {
			if errors.Is(err, context.Canceled) {
				http.Error(w, err.Error(), statusClientClosedRequest)
				level.Warn(logger).Log("msg", "push request canceled", "err", err)
				return
			}
			var (
				code int
				msg  string
			)
			if resp, ok := httpgrpc.HTTPResponseFromError(err); ok {
				code, msg = int(resp.Code), string(resp.Body)
			} else {
				code, msg = toHTTPStatus(ctx, err, limits), err.Error()
			}
			if code != 202 {
				level.Error(logger).Log("msg", "push error", "err", err)
			}

			if code == http.StatusTooManyRequests || code >= 500 && retryCfg != nil {
				// If we are going to retry, set the Retry-After header.
				// This is used by the client to determine how long to wait before retrying.
				retrySeconds := calculateRetryAfter(r, retryCfg)
				logger.Log("msg", "get retry-after", "retry-after", retrySeconds, "strategy", retryCfg.Strategy, "maxDelay", retryCfg.MaxDelay)
				w.Header().Set("Retry-After", retrySeconds)
			}
			http.Error(w, msg, code)
		}
	})
}

// think about add another middlewre, in the end of middleware chain, to add retry-after header in response

func calculateRetryAfter(req *http.Request, retryCfg *RetryConfig) string {
	attemps := req.Header.Get("Retry-Attempt")
	// default to Retry-Attempt 1
	attemp := "1"
	if attemps != "" {
		attemp = attemps
	}

	// If retry-attemp is not valid, set it to default 1
	retryAttemp, err := strconv.Atoi(attemp)
	if attemp == "" || err != nil {
		retryAttemp = 1
	}
	// the default value of base is RetryBase
	base := retryCfg.Base

	switch retryCfg.Strategy {
	case 1:
		base = retryCfg.Base * time.Duration(retryAttemp)
	case 2:
		base = retryCfg.Base * time.Duration(math.Pow(2, float64(retryAttemp-1)))
	}

	if base > retryCfg.MaxDelay {
		base = retryCfg.MaxDelay
	}

	// the delaySeconds is a random number between 1 and base
	delaySeconds := rand.Intn(int(base.Seconds())) + 1

	return strconv.Itoa(delaySeconds)
}

// toHTTPStatus converts the given error into an appropriate HTTP status corresponding
// to that error, if the error is one of the errors from this package. Otherwise, an
// http.StatusInternalServerError is returned.
func toHTTPStatus(ctx context.Context, pushErr error, limits *validation.Overrides) int {
	if errors.Is(pushErr, context.DeadlineExceeded) {
		return http.StatusInternalServerError
	}

	var distributorErr distributorError
	if errors.As(pushErr, &distributorErr) {
		switch distributorErr.errorCause() {
		case mimirpb.BAD_DATA:
			return http.StatusBadRequest
		case mimirpb.INGESTION_RATE_LIMITED:
			// Return a 429 here to tell the client it is going too fast.
			// Client may discard the data or slow down and re-send.
			// Prometheus v2.26 added a remote-write option 'retry_on_http_429'.
			return http.StatusTooManyRequests
		case mimirpb.REQUEST_RATE_LIMITED:
			serviceOverloadErrorEnabled := false
			userID, err := tenant.TenantID(ctx)
			if err == nil {
				serviceOverloadErrorEnabled = limits.ServiceOverloadStatusCodeOnRateLimitEnabled(userID)
			}
			// Return a 429 or a 529 here depending on configuration to tell the client it is going too fast.
			// Client may discard the data or slow down and re-send.
			// Prometheus v2.26 added a remote-write option 'retry_on_http_429'.
			if serviceOverloadErrorEnabled {
				return StatusServiceOverloaded
			}
			return http.StatusTooManyRequests
		case mimirpb.REPLICAS_DID_NOT_MATCH:
			return http.StatusAccepted
		case mimirpb.TOO_MANY_CLUSTERS:
			return http.StatusBadRequest
		case mimirpb.TSDB_UNAVAILABLE:
			return http.StatusServiceUnavailable
		}
	}

	return http.StatusInternalServerError
}
