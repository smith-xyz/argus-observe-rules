package main

import (
	"context"
	"net/http"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctutil"
	"github.com/google/certificate-transparency-go/jsonclient"
	ct "github.com/google/certificate-transparency-go"
)

func ctClientOperations(ctx context.Context, url string, chain []ct.ASN1Cert, hash []byte, start, end int64, treeSize uint64) {
	httpClient := &http.Client{}
	ctClient, _ := client.New(url, httpClient, jsonclient.Options{})
	sth, _ := ctClient.GetSTH(ctx)
	entries, _ := ctClient.GetEntries(ctx, start, end)
	proof, _ := ctClient.GetProofByHash(ctx, hash, treeSize)
	sct, _ := ctClient.AddChain(ctx, chain)
	_, _, _, _, _ = sth, entries, proof, sct, ctClient
}

func ctPrechainUpload(ctx context.Context, ctClient *client.LogClient, chain []ct.ASN1Cert) {
	_, _ = ctClient.AddPreChain(ctx, chain)
}

func sctVerification(logKey, sct, chain interface{}) {
	_ = ctutil.VerifySCT(logKey, sct, chain)
}
