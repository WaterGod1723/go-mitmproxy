package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/lqqyt2423/go-mitmproxy/cert"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	log "github.com/sirupsen/logrus"
	lua "github.com/yuin/gopher-lua"
)

type RewriteAndMock struct {
	proxy.BaseAddon
	mockDir       string
	luaScriptPath string
	luaPool       sync.Pool
}

// 创建新的RewriteAndMock实例
func NewRewriteAndMock(mockDir string, luaScriptPath string) *RewriteAndMock {
	// 确保mock目录存在
	if _, err := os.Stat(mockDir); os.IsNotExist(err) {
		os.MkdirAll(mockDir, 0755)
		log.Infof("Created mock directory: %s", mockDir)
	}

	// 创建Lua解释器池
	pool := sync.Pool{
		New: func() interface{} {
			L := lua.NewState()
			// 为每个新创建的Lua解释器加载脚本
			if luaScriptPath != "" {
				if err := L.DoFile(luaScriptPath); err != nil {
					log.Errorf("Failed to load Lua script: %v", err)
				}
			}
			return L
		},
	}

	return &RewriteAndMock{
		mockDir:       mockDir,
		luaScriptPath: luaScriptPath,
		luaPool:       pool,
	}
}

// ClientConnected 客户端连接时调用
func (a *RewriteAndMock) ClientConnected(client *proxy.ClientConn) {
	// 禁用上游证书检查
	client.UpstreamCert = false
}

// Requestheaders 请求头处理
func (a *RewriteAndMock) Requestheaders(f *proxy.Flow) {
	// 打印原始请求信息
	log.Infof("Original Request: %s %s://%s%s", f.Request.Method, f.Request.URL.Scheme, f.Request.URL.Host, f.Request.URL.Path)

	// 1. 检查是否需要返回mock文件
	mockFile := a.getMockFile(f.Request.Method, f.Request.URL.Host, f.Request.URL.Path)
	if mockFile != "" {
		log.Infof("Returning mock file for: %s %s://%s%s", f.Request.Method, f.Request.URL.Scheme, f.Request.URL.Host, f.Request.URL.Path)
		resp := a.createMockResponse(mockFile)
		if resp != nil {
			f.Response = resp
			return // 直接返回mock响应，不再继续处理
		}
	}

	// 2. 执行Lua脚本修改请求
	if a.luaScriptPath != "" {
		// 从池中获取Lua解释器实例
		L := a.luaPool.Get().(*lua.LState)
		// 使用完毕后放回池中
		defer a.luaPool.Put(L)

		// 将请求信息传递给Lua脚本
		L.SetGlobal("method", lua.LString(f.Request.Method))
		L.SetGlobal("url", lua.LString(f.Request.URL.String()))
		L.SetGlobal("scheme", lua.LString(f.Request.URL.Scheme))
		L.SetGlobal("host", lua.LString(f.Request.URL.Host))
		L.SetGlobal("path", lua.LString(f.Request.URL.Path))
		L.SetGlobal("query", lua.LString(f.Request.URL.RawQuery))

		// 执行Lua脚本中的rewrite_request函数
		if err := L.CallByParam(lua.P{Fn: L.GetGlobal("rewrite_request"), NRet: 4, Protect: true}); err != nil {
			log.Errorf("Failed to execute Lua script: %v", err)
		} else {
			// 获取Lua脚本的返回值
			newScheme := L.CheckString(1)
			newHost := L.CheckString(2)
			newPath := L.CheckString(3)
			newQuery := L.CheckString(4)

			// 清理栈
			L.Pop(4)

			// 如果返回值不为空，则更新请求
			if newScheme != "" {
				f.Request.URL.Scheme = newScheme
				log.Infof("Lua script rewrote scheme to: %s", newScheme)
			}
			if newHost != "" {
				f.Request.URL.Host = newHost
				log.Infof("Lua script rewrote host to: %s", newHost)
			}
			if newPath != "" {
				f.Request.URL.Path = newPath
				log.Infof("Lua script rewrote path to: %s", newPath)
			}
			if newQuery != "" {
				f.Request.URL.RawQuery = newQuery
				log.Infof("Lua script rewrote query to: %s", newQuery)
			}
		}
	}

	// 3. 重写规则示例（仍然保留作为默认规则）
	// 重写特定域名
	if f.Request.URL.Host == "example.com" {
		f.Request.URL.Host = "www.example.org"
		log.Infof("Rewrote host from example.com to www.example.org")
	}

	// 重写特定路径
	if strings.HasPrefix(f.Request.URL.Path, "/api/v1/") {
		f.Request.URL.Path = strings.Replace(f.Request.URL.Path, "/api/v1/", "/api/v2/", 1)
		log.Infof("Rewrote path to: %s", f.Request.URL.Path)
	}

	// 打印重写后的请求信息
	log.Infof("Processed Request: %s %s://%s%s", f.Request.Method, f.Request.URL.Scheme, f.Request.URL.Host, f.Request.URL.Path)
}

// 根据请求信息获取mock文件路径
func (a *RewriteAndMock) getMockFile(method, host, path string) string {
	// 将host转换为文件名安全的格式
	safeHost := strings.ReplaceAll(host, ".", "_")

	// 将path转换为文件名安全的格式，替换/为_，去掉开头的/
	safePath := strings.TrimPrefix(path, "/")
	safePath = strings.ReplaceAll(safePath, "/", "_")

	// 如果path为空，使用root
	if safePath == "" {
		safePath = "root"
	}

	// 构建mock文件路径，格式：{mockDir}/{safeHost}/{method}_{safePath}.json
	mockFile := filepath.Join(a.mockDir, safeHost, method+"_"+safePath+".json")

	// 检查文件是否存在
	if _, err := os.Stat(mockFile); err == nil {
		return mockFile
	}

	return ""
}

// 创建mock响应
func (a *RewriteAndMock) createMockResponse(mockFile string) *proxy.Response {
	// 读取mock文件内容
	body, err := os.ReadFile(mockFile)
	if err != nil {
		log.Errorf("Failed to read mock file %s: %v", mockFile, err)
		return nil
	}

	// 创建响应
	return &proxy.Response{
		StatusCode: 200,
		Header: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: body,
	}
}

// CustomCA 实现 cert.CA 接口，使用现有的证书文件
type CustomCA struct {
	rootCert   *x509.Certificate
	privateKey interface{}
	certCache  *lru.Cache
	mutex      sync.RWMutex
}

// NewCustomCA 创建一个新的 CustomCA 实例
func NewCustomCA(certPath, keyPath string) (cert.CA, error) {
	// 加载证书和私钥
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	// 解析根证书
	rootCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, err
	}

	// 初始化证书缓存，最多缓存100个证书
	certCache := lru.New(100)

	return &CustomCA{
		rootCert:   rootCert,
		privateKey: tlsCert.PrivateKey,
		certCache:  certCache,
	}, nil
}

// GetRootCA 返回根证书
func (ca *CustomCA) GetRootCA() *x509.Certificate {
	return ca.rootCert
}

// GetCert 返回证书，使用根证书为不同域名生成不同的证书
func (ca *CustomCA) GetCert(commonName string) (*tls.Certificate, error) {
	// 先尝试从缓存获取证书
	ca.mutex.RLock()
	if cert, ok := ca.certCache.Get(commonName); ok {
		ca.mutex.RUnlock()
		return cert.(*tls.Certificate), nil
	}
	ca.mutex.RUnlock()

	// 缓存中没有，生成新证书
	cert, err := ca.generateCert(commonName)
	if err != nil {
		return nil, err
	}

	// 缓存新生成的证书
	ca.mutex.Lock()
	ca.certCache.Add(commonName, cert)
	ca.mutex.Unlock()

	return cert, nil
}

// generateCert 为指定域名生成证书
func (ca *CustomCA) generateCert(commonName string) (*tls.Certificate, error) {
	// 生成随机序列号
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	// 设置证书模板
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
			Organization: []string{
				"Go-MITMProxy",
			},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // 证书有效期1天
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{commonName},
	}

	// 生成RSA私钥
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// 使用根证书签名新证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.rootCert, &privKey.PublicKey, ca.privateKey)
	if err != nil {
		return nil, err
	}

	// 构建完整的证书链
	certChain := [][]byte{certDER, ca.rootCert.Raw}

	return &tls.Certificate{
		Certificate: certChain,
		PrivateKey:  privKey,
	}, nil
}

func main() {
	// 设置日志级别
	log.SetLevel(log.DebugLevel)

	// 创建mock目录
	mockDir := filepath.Join(os.TempDir(), "go-mitmproxy-mock")

	// Lua脚本路径（可以通过命令行参数或配置文件传递）
	luaScriptPath := "rewrite_rules.lua"

	// 证书文件路径
	certPath := filepath.Join("cert", "cert.pem")
	keyPath := filepath.Join("cert", "key.pem")

	// 创建代理选项
	opts := &proxy.Options{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
		// 设置自定义CA函数
		NewCaFunc: func() (cert.CA, error) {
			return NewCustomCA(certPath, keyPath)
		},
	}

	// 创建代理实例
	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	// 添加自定义addon，传入mock目录和Lua脚本路径
	p.AddAddon(NewRewriteAndMock(mockDir, luaScriptPath))
	// 添加日志addon
	p.AddAddon(&proxy.LogAddon{})

	log.Info("Proxy server starting on http://localhost:9080")
	log.Infof("Mock directory: %s", mockDir)
	log.Infof("Lua script path: %s", luaScriptPath)
	log.Info("To use this proxy, configure your browser or application to use http://localhost:9080")
	log.Info("Example mock file: ", filepath.Join(mockDir, "example_com", "GET_hello.json"))
	log.Info("Example Lua script: rewrite_rules.lua should contain rewrite_request function")

	// 启动代理
	log.Fatal(p.Start())
}
