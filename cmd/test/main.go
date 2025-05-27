package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"net"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func main() {
	// 创建RADIUS客户端
	client := radius.Client{
		Retry:           1,
		MaxPacketErrors: 5,
	}

	ctx := context.Background()

	// 配置
	authAddr := "127.0.0.1:1812"
	secret := []byte("testing123")

	// 测试PAP认证
	fmt.Println("=== 测试PAP认证 ===")
	packet := radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(packet, "testuser")
	rfc2865.UserPassword_SetString(packet, "testpass")
	rfc2865.NASIPAddress_Set(packet, net.ParseIP("192.168.1.10"))

	response, err := client.Exchange(ctx, packet, authAddr)
	if err != nil {
		fmt.Printf("PAP认证失败: %v\n", err)
	} else {
		fmt.Printf("PAP认证结果: %v\n", response.Code)
	}

	// 测试CHAP认证
	fmt.Println("\n=== 测试CHAP认证 ===")

	// 生成16字节随机挑战
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		fmt.Printf("生成CHAP挑战失败: %v\n", err)
		return
	}

	packet = radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(packet, "testuser")

	chapID := byte(1)
	chapPassword := []byte("testpass")

	// 计算CHAP响应
	h := md5.New()
	h.Write([]byte{chapID})
	h.Write(chapPassword)
	h.Write(challenge)
	chapResponse := h.Sum(nil)

	// 组装CHAP密码字段 (ID + 响应)
	fullResponse := make([]byte, 17)
	fullResponse[0] = chapID
	copy(fullResponse[1:], chapResponse)

	rfc2865.CHAPChallenge_Set(packet, challenge)
	rfc2865.CHAPPassword_Set(packet, fullResponse)
	rfc2865.NASIPAddress_Set(packet, net.ParseIP("192.168.1.10"))

	response, err = client.Exchange(ctx, packet, authAddr)
	if err != nil {
		fmt.Printf("CHAP认证失败: %v\n", err)
	} else {
		fmt.Printf("CHAP认证结果: %v\n", response.Code)
	}

	// 测试MAC认证
	fmt.Println("\n=== 测试MAC认证 ===")
	packet = radius.New(radius.CodeAccessRequest, secret)
	rfc2865.UserName_SetString(packet, "001122334455") // MAC地址作为用户名
	rfc2865.CallingStationID_SetString(packet, "00-11-22-33-44-55")
	rfc2865.NASIPAddress_Set(packet, net.ParseIP("192.168.1.10"))

	response, err = client.Exchange(ctx, packet, authAddr)
	if err != nil {
		fmt.Printf("MAC认证失败: %v\n", err)
	} else {
		fmt.Printf("MAC认证结果: %v\n", response.Code)
	}
}
