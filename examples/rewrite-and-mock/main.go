package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/golang/groupcache/lru"
	"github.com/lqqyt2423/go-mitmproxy/cert"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	log "github.com/sirupsen/logrus"
	lua "github.com/yuin/gopher-lua"
)

// 全局变量，用于跟踪当前运行的代理实例
var currentProxy *proxy.Proxy

// Config 配置文件结构体
type Config struct {
	Addr              string `json:"addr"`
	MockDir           string `json:"mock_dir"`
	LuaScriptPath     string `json:"lua_script_path"`
	CertPath          string `json:"cert_path"`
	KeyPath           string `json:"key_path"`
	StreamLargeBodies int    `json:"stream_large_bodies"`
}

// 默认配置
var defaultConfig = Config{
	Addr:              ":9080",
	MockDir:           filepath.Join(os.TempDir(), "go-mitmproxy-mock"),
	LuaScriptPath:     "rewrite_rules.lua",
	CertPath:          filepath.Join("cert", "cert.pem"),
	KeyPath:           filepath.Join("cert", "key.pem"),
	StreamLargeBodies: 5 * 1024 * 1024, // 5MB
}

// 从文件加载配置
func loadConfig(filename string) (*Config, error) {
	config := defaultConfig

	if filename == "" {
		return &config, nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

type RewriteAndMock struct {
	proxy.BaseAddon
	mockDir       string
	luaScriptPath string
	luaPool       sync.Pool
	config        *Config
}

// 创建新的RewriteAndMock实例
func NewRewriteAndMock(config *Config) *RewriteAndMock {
	// 确保mock目录存在
	if _, err := os.Stat(config.MockDir); os.IsNotExist(err) {
		os.MkdirAll(config.MockDir, 0755)
		log.Infof("Created mock directory: %s", config.MockDir)
	}

	return &RewriteAndMock{
		mockDir:       config.MockDir,
		luaScriptPath: config.LuaScriptPath,
		luaPool: sync.Pool{
			New: func() interface{} {
				L := lua.NewState()
				// 为每个新创建的Lua解释器加载脚本
				if config.LuaScriptPath != "" {
					if err := L.DoFile(config.LuaScriptPath); err != nil {
						log.Errorf("Failed to load Lua script: %v", err)
					}
				}
				return L
			},
		},
		config: config,
	}
}

// 监听配置文件变化
func watchConfigFile(configPath string, reloadFunc func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// 监控配置文件
	if err := watcher.Add(configPath); err != nil {
		watcher.Close()
		return err
	}

	// 监控配置文件所在目录
	configDir := filepath.Dir(configPath)
	if err := watcher.Add(configDir); err != nil {
		watcher.Close()
		return err
	}

	go func() {
		defer watcher.Close()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// 只处理配置文件的修改事件
				if filepath.Clean(event.Name) == filepath.Clean(configPath) &&
					(event.Op&fsnotify.Write == fsnotify.Write ||
						event.Op&fsnotify.Create == fsnotify.Create) {
					log.Infof("Config file changed: %s", event.Name)
					reloadFunc()
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Errorf("Error watching config file: %v", err)
			}
		}
	}()

	return nil
}

// 监听Lua脚本变化
func watchLuaScript(scriptPath string, reloadFunc func()) error {
	if scriptPath == "" {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// 监控Lua脚本文件
	if err := watcher.Add(scriptPath); err != nil {
		watcher.Close()
		return err
	}

	// 监控Lua脚本所在目录
	scriptDir := filepath.Dir(scriptPath)
	if err := watcher.Add(scriptDir); err != nil {
		watcher.Close()
		return err
	}

	go func() {
		defer watcher.Close()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// 只处理Lua脚本文件的修改事件
				if filepath.Clean(event.Name) == filepath.Clean(scriptPath) &&
					(event.Op&fsnotify.Write == fsnotify.Write ||
						event.Op&fsnotify.Create == fsnotify.Create) {
					log.Infof("Lua script changed: %s", event.Name)
					reloadFunc()
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Errorf("Error watching Lua script: %v", err)
			}
		}
	}()

	return nil
}

// 重启代理服务
func restartProxy(configPath string) {
	log.Info("Restarting proxy server...")

	// 加载新配置
	config, err := loadConfig(configPath)
	if err != nil {
		log.Errorf("Failed to load new config: %v", err)
		return
	}

	// 创建新的代理实例
	opts := &proxy.Options{
		Addr:              config.Addr,
		StreamLargeBodies: int64(config.StreamLargeBodies),
		// 设置自定义CA函数
		NewCaFunc: func() (cert.CA, error) {
			return NewCustomCA(config.CertPath, config.KeyPath)
		},
	}

	newProxy, err := proxy.NewProxy(opts)
	if err != nil {
		log.Errorf("Failed to create new proxy: %v", err)
		return
	}

	// 添加addons
	newProxy.AddAddon(NewRewriteAndMock(config))
	newProxy.AddAddon(&proxy.LogAddon{})

	// 关闭旧代理
	if currentProxy != nil {
		log.Info("Closing old proxy instance...")
		if err := currentProxy.Close(); err != nil {
			log.Errorf("Failed to close old proxy: %v", err)
		} else {
			log.Info("Old proxy instance closed successfully")
		}
	}

	// 更新全局代理实例
	currentProxy = newProxy

	// 启动新代理
	go func() {
		log.Infof("Proxy server restarted on http://localhost%s", config.Addr)
		if err := newProxy.Start(); err != nil {
			log.Errorf("Proxy server error: %v", err)
		}
	}()
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
			}
			if newHost != "" {
				f.Request.URL.Host = newHost
			}
			if newPath != "" {
				f.Request.URL.Path = newPath
			}
			if newQuery != "" {
				f.Request.URL.RawQuery = newQuery
			}
		}
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
	mockFile := filepath.Join(a.mockDir, safeHost, method+"_"+safePath)

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

	// 配置文件路径（默认同目录下的config.json）
	configPath := "config.json"

	// 加载配置
	config, err := loadConfig(configPath)
	if err != nil {
		log.Warnf("Failed to load config file %s, using default config: %v", configPath, err)
		config = &defaultConfig
	}

	// 创建代理选项
	opts := &proxy.Options{
		Addr:              config.Addr,
		StreamLargeBodies: int64(config.StreamLargeBodies),
		// 设置自定义CA函数
		NewCaFunc: func() (cert.CA, error) {
			return NewCustomCA(config.CertPath, config.KeyPath)
		},
	}

	// 创建代理实例
	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	// 更新全局代理实例
	currentProxy = p

	// 添加addons
	p.AddAddon(NewRewriteAndMock(config))
	p.AddAddon(&proxy.LogAddon{})

	log.Infof("Proxy server starting on http://localhost%s", config.Addr)
	log.Infof("Mock directory: %s", config.MockDir)
	log.Infof("Lua script path: %s", config.LuaScriptPath)
	log.Infof("Config file: %s", configPath)
	log.Info("To use this proxy, configure your browser or application to use http://localhost%s", config.Addr)
	log.Info("Example mock file: ", filepath.Join(config.MockDir, "example_com", "GET_hello.json"))
	log.Info("Example Lua script: rewrite_rules.lua should contain rewrite_request function")
	log.Info("Example config file: config.json with addr, mock_dir, lua_script_path, cert_path, key_path fields")

	// 启动代理
	go func() {
		if err := p.Start(); err != nil {
			log.Errorf("Proxy server error: %v", err)
		}
	}()

	// 监听配置文件变化
	if err := watchConfigFile(configPath, func() {
		// 重启代理服务
		restartProxy(configPath)
	}); err != nil {
		log.Warnf("Failed to watch config file: %v", err)
	} else {
		log.Infof("Watching config file: %s", configPath)
	}

	// 监听Lua脚本变化
	if config.LuaScriptPath != "" {
		if err := watchLuaScript(config.LuaScriptPath, func() {
			// 重启代理服务
			restartProxy(configPath)
		}); err != nil {
			log.Warnf("Failed to watch Lua script: %v", err)
		} else {
			log.Infof("Watching Lua script: %s", config.LuaScriptPath)
		}
	}

	// 设置信号处理，确保程序退出时关闭代理实例
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// 等待退出信号
	<-quit

	// 关闭代理实例
	if currentProxy != nil {
		log.Info("Shutting down proxy server...")
		if err := currentProxy.Close(); err != nil {
			log.Errorf("Failed to close proxy: %v", err)
		} else {
			log.Info("Proxy server shut down successfully")
		}
	}

	log.Info("Program exited")
}
