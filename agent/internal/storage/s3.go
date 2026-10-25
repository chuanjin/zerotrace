package storage

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/chuanjin/zerotrace/agent/internal/config"
)

// S3Client is a zero-dependency AWS Signature V4 client compatible with AWS S3, Cloudflare R2, Hetzner, and MinIO.
type S3Client struct {
	endpoint  string
	bucket    string
	region    string
	accessKey string
	secretKey string
	client    *http.Client
}

func NewS3Client(cfg config.StorageConf) *S3Client {
	region := cfg.Region
	if region == "" {
		region = "auto" // Cloudflare R2 default
	}
	return &S3Client{
		endpoint:  strings.TrimRight(cfg.Endpoint, "/"),
		bucket:    cfg.Bucket,
		region:    region,
		accessKey: cfg.AccessKey,
		secretKey: cfg.SecretKey,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *S3Client) Enabled() bool {
	return c != nil && c.endpoint != "" && c.bucket != "" && c.accessKey != "" && c.secretKey != ""
}

func (c *S3Client) objectURL(key string) string {
	key = strings.TrimLeft(key, "/")
	if key == "" {
		return fmt.Sprintf("%s/%s", c.endpoint, c.bucket)
	}
	return fmt.Sprintf("%s/%s/%s", c.endpoint, c.bucket, key)
}

// PutObject uploads bytes to S3/R2 using AWS SigV4 authentication.
func (c *S3Client) PutObject(key string, contentType string, body []byte) error {
	if !c.Enabled() {
		return nil
	}
	target := c.objectURL(key)
	req, err := http.NewRequest(http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	c.signRequest(req, body)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("s3 PUT %s status %d: %s", key, resp.StatusCode, string(respBody))
	}
	return nil
}

// EnsureBucketAndCORS creates the bucket (if needed) and applies browser CORS rules for DuckDB-Wasm HTTP Range reads.
func (c *S3Client) EnsureBucketAndCORS() error {
	if !c.Enabled() {
		return fmt.Errorf("S3/R2 credentials not configured")
	}
	// 1. Create Bucket (ignore 409 BucketAlreadyOwnedByYou)
	bURL := c.objectURL("")
	req, err := http.NewRequest(http.MethodPut, bURL, nil)
	if err != nil {
		return err
	}
	c.signRequest(req, nil)
	if resp, err := c.client.Do(req); err == nil {
		resp.Body.Close()
	}

	// 2. Apply CORS configuration so DuckDB-Wasm in browser can issue GET/HEAD Range requests
	corsXML := `<?xml version="1.0" encoding="UTF-8"?>
<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <CORSRule>
    <AllowedOrigin>*</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedMethod>HEAD</AllowedMethod>
    <AllowedHeader>*</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
    <ExposeHeader>Content-Length</ExposeHeader>
    <ExposeHeader>Content-Range</ExposeHeader>
    <ExposeHeader>Accept-Ranges</ExposeHeader>
    <MaxAgeSeconds>3600</MaxAgeSeconds>
  </CORSRule>
</CORSConfiguration>`

	corsURL := bURL + "?cors="
	corsReq, err := http.NewRequest(http.MethodPut, corsURL, bytes.NewReader([]byte(corsXML)))
	if err != nil {
		return err
	}
	corsReq.Header.Set("Content-Type", "application/xml")
	c.signRequest(corsReq, []byte(corsXML))
	resp, err := c.client.Do(corsReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to set S3 CORS (status %d): %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *S3Client) signRequest(req *http.Request, payload []byte) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payloadHash := sha256Hex(payload)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("Host", req.URL.Host)

	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(signedHeaders)

	var canonicalHeaders strings.Builder
	for _, h := range signedHeaders {
		var val string
		if h == "host" {
			val = req.URL.Host
		} else {
			val = strings.TrimSpace(req.Header.Get(h))
		}
		canonicalHeaders.WriteString(h + ":" + val + "\n")
	}

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := canonicalizeQuery(req.URL.Query())
	signedHeadersStr := strings.Join(signedHeaders, ";")

	canonicalReq := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeadersStr,
		payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalReq)),
	}, "\n")

	signingKey := getSignatureKey(c.secretKey, dateStamp, c.region, "s3")
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKey, credentialScope, signedHeadersStr, signature)
	req.Header.Set("Authorization", authHeader)
}

func canonicalizeQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func getSignatureKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}
