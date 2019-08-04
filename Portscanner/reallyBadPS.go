package main

import (
	"context"
	"fmt"
	"golang.org/x/sync/semaphore"
	"net"
	"os"
	// "os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortScanner struct {
	ip   string
	lock *semaphore.Weighted
}

func Ulimit() int64 {
	/*
		out, err := exec.Command("/bin/sh", "-c", "ulimit -n").Output()
		if err != nil {
			panic(err)
		}
		s := strings.TrimSpace(string(out))
		i, err := strconv.ParseInt(s, 10, 64)

		if err != nil {
			panic(err)
		}
		return i
	*/
	return 256
}

func ScanPort(ip string, port int, timeout time.Duration) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			ScanPort(ip, port, timeout)
		} else {
			fmt.Println(port, "closed")
		}
		return
	}
	conn.Close()
	fmt.Println(port, "open")
}

func (ps *PortScanner) Start(f, l int, timeout time.Duration) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	for port := f; port <= l; port++ {
		wg.Add(1)
		ps.lock.Acquire(context.TODO(), 1)

		go func(port int) {
			defer ps.lock.Release(1)
			defer wg.Done()
			ScanPort(ps.ip, port, timeout)
		}(port)
	}
}

func main() {
	var maxPorts = 65535
	if len(os.Args) < 2 {
		fmt.Println("Specify ip address")
		return
	}
	if len(os.Args) == 3 {
		ports, err := strconv.ParseInt(os.Args[2], 10, 64)
		maxPorts = int(ports)
		if err != nil {
			fmt.Println("Specify valid port")
			return
		}
	}
	ipAddr := os.Args[1]
	fmt.Println("sc")
	fmt.Println("scanning to port: ", maxPorts)
	ps := &PortScanner{
		ip:   ipAddr,
		lock: semaphore.NewWeighted(Ulimit()),
	}

	ps.Start(1, maxPorts, 500*time.Millisecond)
}
