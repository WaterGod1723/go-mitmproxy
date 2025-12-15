-- rewrite_rules.lua - 示例 Lua 脚本，用于动态修改请求的 scheme、host、path 和 query

-- rewrite_request 函数将被 Go 代码调用
-- 接收参数：method, url, scheme, host, path, query（这些是全局变量，由 Go 代码设置）
-- 返回值：new_scheme, new_host, new_path, new_query
function rewrite_request()
    -- 打印原始请求信息（可选，用于调试）
    print("Original Request:", method, scheme, host, path, query)
    
    -- 初始化返回值（默认使用原始值）
    local new_scheme = scheme
    local new_host = host
    local new_path = path
    local new_query = query
    
    -- 1. 示例：重写特定域名
    if host == "example.com" then
        new_host = "www.example.org"
        print("Rewrote host from example.com to www.example.org")
    end
    
    -- 2. 示例：重写特定路径
    if string.find(path, "/api/v1/") then
        new_path = string.gsub(path, "/api/v1/", "/api/v2/")
        print("Rewrote path to:", new_path)
    end
    
    -- 3. 示例：修改协议（从 http 到 https）
    if scheme == "http" and host == "secure.example.com" then
        new_scheme = "https"
        print("Rewrote scheme from http to https")
    end
    
    -- 4. 示例：修改查询参数
    if query ~= "" and string.find(query, "version=1") then
        new_query = string.gsub(query, "version=1", "version=2")
        print("Rewrote query to:", new_query)
    end
    
    -- 5. 示例：根据请求方法修改路径
    if method == "POST" and path == "/login" then
        new_path = "/api/auth/login"
        print("Rewrote POST /login to", new_path)
    end
    
    -- 6. 示例：条件重写（基于完整URL）
    if url == "http://test.com/old-page" then
        new_scheme = "https"
        new_host = "new-test.com"
        new_path = "/new-page"
        new_query = "redirected=yes"
        print("Rewrote entire URL to:", new_scheme, new_host, new_path, new_query)
    end
    
    -- 返回修改后的参数（如果不需要修改某个参数，可以返回空字符串或原始值）
    return new_scheme, new_host, new_path, new_query
end