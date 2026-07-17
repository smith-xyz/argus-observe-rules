package gogrpctlsoverride

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func withInsecure() {
	// Pattern: grpc.WithInsecure() - line 14
	opts := []grpc.DialOption{grpc.WithInsecure()}
	_ = opts
}

func withInsecureCredentials() {
	// Pattern: grpc.WithTransportCredentials(insecure.NewCredentials()) - line 19
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	_ = opts
}

func conditionalWithInsecure() {
	var opts []grpc.DialOption

	// Pattern: conditional grpc.WithInsecure - line 26
	if isDev() {
		opts = append(opts, grpc.WithInsecure())
	}
	_ = opts
}

func conditionalInsecureCredentials() {
	var creds credentials.TransportCredentials

	// Pattern: conditional insecure.NewCredentials - line 35
	if isDev() {
		creds = insecure.NewCredentials()
	}
	_ = creds
}

func interceptorBypass() {
	// Pattern: unary interceptor with WithInsecure - line 42
	grpc.WithUnaryInterceptor(func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if bypassTLS() {
			opts = append(opts, grpc.WithInsecure())
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	})
}

func insecureServer() {
	// Pattern: grpc.NewServer with insecure creds - line 59
	_ = grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
}

func funcResultInsecure() {
	var opts []grpc.DialOption

	// Pattern: insecure from function result - line 66
	insecure := getInsecureFlag()
	if insecure {
		opts = append(opts, grpc.WithInsecure())
	}
	_ = opts
}

func isDev() bool {
	return true
}

func bypassTLS() bool {
	return true
}

func getInsecureFlag() bool {
	return true
}
