package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

var (
	serverAddr    = flag.String("server", "127.0.0.1:1812", "RADIUS server address (host:port)")
	secret        = flag.String("secret", "testing123", "RADIUS shared secret")
	nasIP         = flag.String("nas-ip", "192.168.1.1", "NAS IP Address to use in request")
	username      = flag.String("username", "testuser", "Username for authentication")
	password      = flag.String("password", "testpass", "Password for authentication")
	concurrency   = flag.Int("c", 100, "Number of concurrent workers")
	totalRequests = flag.Int("n", 1000, "Total number of requests to send")
	timeout       = flag.Duration("timeout", 3*time.Second, "Request timeout")
	useChap       = flag.Bool("chap", false, "Use CHAP authentication instead of PAP")
	verbose       = flag.Bool("v", false, "Verbose output (show all responses)")
)

// 性能统计结构
type stats struct {
	startTime     time.Time
	totalRequests int64
	successCount  int64
	failureCount  int64
	timeoutCount  int64
	totalDuration time.Duration
	minDuration   time.Duration
	maxDuration   time.Duration
}

func main() {
	flag.Parse()

	// 显示测试配置
	fmt.Println("RADIUS Performance Tester")
	fmt.Println("=========================")
	fmt.Printf("Server:       %s\n", *serverAddr)
	fmt.Printf("Concurrency:  %d\n", *concurrency)
	fmt.Printf("Total reqs:   %d\n", *totalRequests)
	fmt.Printf("Auth method:  %s\n", map[bool]string{true: "CHAP", false: "PAP"}[*useChap])
	fmt.Printf("Timeout:      %s\n", *timeout)
	fmt.Println("-------------------------")

	// 初始化统计
	s := &stats{
		startTime:   time.Now(),
		minDuration: time.Hour,
	}

	// 设置退出信号处理
	setupSignalHandler()

	// 创建工作池
	workCh := make(chan struct{}, *concurrency*2)
	resultCh := make(chan *radius.Packet, *concurrency*2)

	var wg sync.WaitGroup
	wg.Add(*concurrency)

	// 启动工作协程
	for i := 0; i < *concurrency; i++ {
		go worker(i, workCh, resultCh, &wg)
	}

	// 启动结果处理器
	go processResults(resultCh, s)

	// 分发工作
	go func() {
		for i := 0; i < *totalRequests; i++ {
			workCh <- struct{}{}
		}
		close(workCh)
	}()

	// 等待所有工作完成
	wg.Wait()
	close(resultCh)

	// 确保所有结果处理完毕
	time.Sleep(500 * time.Millisecond)

	// 打印最终统计
	printFinalStats(s)
}

// 设置信号处理
func setupSignalHandler() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nTest interrupted by user")
		os.Exit(0)
	}()
}

// 工作协程
func worker(id int, workCh <-chan struct{}, resultCh chan<- *radius.Packet, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &radius.Client{}

	for range workCh {
		sendRequest(id, client, resultCh)
	}
}

// 发送RADIUS请求
func sendRequest(id int, client *radius.Client, resultCh chan<- *radius.Packet) {
	packet := radius.New(radius.CodeAccessRequest, []byte(*secret))
	rfc2865.UserName_SetString(packet, *username)
	rfc2865.NASIPAddress_Set(packet, net.ParseIP(*nasIP))
	rfc2865.FramedIPAddress_Set(packet, net.ParseIP("192.168.1.2"))
	rfc2865.NASPortType_Set(packet, rfc2865.NASPortType_Value_Wireless80211)

	if *useChap {
		// CHAP认证
		chapID := byte(time.Now().UnixNano() % 256)
		chapChallenge := make([]byte, 16)
		_, _ = rand.Read(chapChallenge)

		chapResponse := createChapResponse(chapID, *password, chapChallenge)
		chapValue := append([]byte{chapID}, chapResponse...)
		rfc2865.CHAPPassword_Set(packet, chapValue)
		rfc2865.CHAPChallenge_Set(packet, chapChallenge)
	} else {
		// PAP认证
		rfc2865.UserPassword_SetString(packet, *password)
	}

	// 设置Message-Authenticator (增强安全性)
	// 实际测试中可能不需要，但真实场景推荐
	// rfc2869.MessageAuthenticator_Set(packet, make([]byte, 16))

	// 发送请求
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	response, err := client.Exchange(ctx, packet, *serverAddr)
	if err != nil {
		// 超时处理
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			resultCh <- nil // 用nil表示超时
			return
		}
		log.Printf("Worker %d error: %v", id, err)
		resultCh <- nil
		return
	}

	resultCh <- response
}

// 创建CHAP响应
func createChapResponse(id byte, password string, challenge []byte) []byte {
	// CHAP响应 = MD5(id + password + challenge)
	hash := md5.New()
	hash.Write([]byte{id})
	hash.Write([]byte(password))
	hash.Write(challenge)
	return hash.Sum(nil)
}

// 处理结果
func processResults(resultCh <-chan *radius.Packet, s *stats) {
	for response := range resultCh {
		atomic.AddInt64(&s.totalRequests, 1)
		reqStart := time.Now()

		if response == nil {
			atomic.AddInt64(&s.timeoutCount, 1)
			continue
		}

		duration := time.Since(reqStart)

		// 更新统计
		atomic.AddInt64(&s.totalRequests, 1)
		s.totalDuration += duration

		if duration < s.minDuration {
			s.minDuration = duration
		}
		if duration > s.maxDuration {
			s.maxDuration = duration
		}

		if response.Code == radius.CodeAccessAccept {
			atomic.AddInt64(&s.successCount, 1)
			if *verbose {
				fmt.Printf("Success! Response time: %v\n", duration)
			}
		} else {
			atomic.AddInt64(&s.failureCount, 1)
			if *verbose {
				fmt.Printf("Failure! (%s) Response time: %v\n", response.Code, duration)
			}
		}

		// 定期打印中间统计
		if s.totalRequests%100 == 0 {
			printIntermediateStats(s)
		}
	}
}

// 打印中间统计
func printIntermediateStats(s *stats) {
	elapsed := time.Since(s.startTime).Seconds()
	reqsPerSec := float64(s.totalRequests) / elapsed

	fmt.Printf("[Progress] Requests: %d/%d (%.1f%%) | Success: %d | Failure: %d | Timeouts: %d | RPS: %.1f\n",
		s.totalRequests, *totalRequests,
		float64(s.totalRequests)/float64(*totalRequests)*100,
		s.successCount, s.failureCount, s.timeoutCount,
		reqsPerSec)
}

// 打印最终统计
func printFinalStats(s *stats) {
	elapsed := time.Since(s.startTime).Seconds()
	reqsPerSec := float64(s.totalRequests) / elapsed
	avgDuration := time.Duration(0)
	if s.totalRequests > 0 {
		avgDuration = time.Duration(int64(s.totalDuration) / s.totalRequests)
	}

	fmt.Println("\nTest Complete")
	fmt.Println("=============")
	fmt.Printf("Total time:        %.2f seconds\n", elapsed)
	fmt.Printf("Requests sent:     %d\n", s.totalRequests)
	fmt.Printf("Successful auths:  %d (%.1f%%)\n", s.successCount,
		float64(s.successCount)/float64(s.totalRequests)*100)
	fmt.Printf("Failed auths:      %d (%.1f%%)\n", s.failureCount,
		float64(s.failureCount)/float64(s.totalRequests)*100)
	fmt.Printf("Timeouts:          %d (%.1f%%)\n", s.timeoutCount,
		float64(s.timeoutCount)/float64(s.totalRequests)*100)
	fmt.Printf("Requests per sec:  %.1f\n", reqsPerSec)
	fmt.Printf("Avg response time: %v\n", avgDuration)
	fmt.Printf("Min response time: %v\n", s.minDuration)
	fmt.Printf("Max response time: %v\n", s.maxDuration)

	// 显示内存统计
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("\nMemory usage: Alloc=%.1fMB, TotalAlloc=%.1fMB, Sys=%.1fMB\n",
		float64(m.Alloc)/1024/1024,
		float64(m.TotalAlloc)/1024/1024,
		float64(m.Sys)/1024/1024)
}
