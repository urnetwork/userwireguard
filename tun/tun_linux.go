/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

/* Implementation of the TUN device interface for linux
 */

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.zx2c4.com/wireguard/conn"

	"bringyour.com/connect"
	"bringyour.com/protocol"
)

type NATKey struct {
	IP   string
	Port int
}

type NATValue struct {
	IP net.IP
}

type NativeTun struct {
	closeOnce sync.Once
	events    chan Event // device related events
	natRcv    chan []byte

	writeOpMu sync.Mutex // writeOpMu guards toWrite
	toWrite   []int

	natTableMu sync.Mutex
	natTable   map[NATKey]NATValue

	nat       *connect.LocalUserNat
	natCancel context.CancelFunc
}

func (tun *NativeTun) MTU() int {
	return 0
}

func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	tun.writeOpMu.Lock()
	defer tun.writeOpMu.Unlock()
	var (
		errs  error
		total int
	)
	tun.toWrite = tun.toWrite[:0]
	for i := range bufs {
		tun.toWrite = append(tun.toWrite, i)
	}
	for _, bufsI := range tun.toWrite {
		packetData := bufs[bufsI][offset:] // TODO: might need to keep offset in beginning?
		packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

		// parse the IPv4 layer
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			transportLayer := packet.TransportLayer()
			if transportLayer == nil {
				errs = errors.Join(errs, fmt.Errorf("no transport layer found in packet: %+x", packetData))
				continue
			}

			ipv4 := ipv4Layer.(*layers.IPv4)
			localSrcIP := NATValue{IP: ipv4.SrcIP} // get pre NAT IP

			ipv4.SrcIP = net.IPv4(172, 245, 118, 233)
			ipv4.TTL -= 1

			natKey := NATKey{}
			natKey.IP = ipv4.SrcIP.String()

			// set network layer for transport layer's checksum and get port for NAT
			switch t := transportLayer.(type) {
			case *layers.TCP:
				t.SetNetworkLayerForChecksum(ipv4)
				natKey.Port = int(t.SrcPort)
			case *layers.UDP:
				t.SetNetworkLayerForChecksum(ipv4)
				natKey.Port = int(t.SrcPort)
			default:
				errs = errors.Join(errs, fmt.Errorf("unsupported transport layer type: %T", t))
				continue
			}

			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			err := gopacket.SerializeLayers(buffer, options, ipv4, transportLayer.(gopacket.SerializableLayer), gopacket.Payload(transportLayer.LayerPayload()))
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to serialize IPv4 packet: %w", err))
				continue
			}

			modifiedPacket := buffer.Bytes()
			ok := tun.nat.SendPacket(connect.Path{}, protocol.ProvideMode_Network, modifiedPacket, 1*time.Second)
			if !ok {
				errs = errors.Join(errs, errors.New("failed to send packet"))
			} else {
				total += 1

				// add nat entry
				tun.natTableMu.Lock()
				tun.natTable[natKey] = localSrcIP
				tun.natTableMu.Unlock()
			}
		} else {
			errs = errors.Join(errs, fmt.Errorf("failed to parse packet"))
		}
	}
	return total, errs
}

func (tun *NativeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	packetData, ok := <-tun.natRcv
	if !ok {
		return 0, os.ErrClosed // channel has been closed
	}

	readInto := bufs[0][offset:]
	n := copy(readInto, packetData) // copy packet data into the buffer

	if n > len(readInto) {
		return 0, fmt.Errorf("packet too large for buffer")
	}

	sizes[0] = n
	return 1, nil
}

func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

func (tun *NativeTun) AddEvent(event Event) {
	tun.events <- event
}

func (tun *NativeTun) Close() error {
	tun.closeOnce.Do(func() {
		if tun.events != nil {
			close(tun.events)
		}
		if tun.natRcv != nil {
			close(tun.natRcv)
		}
	})
	if tun.nat != nil {
		tun.natCancel()
		tun.nat = nil
		tun.natCancel = nil
	}
	return nil
}

func (tun *NativeTun) BatchSize() int {
	return 1
}

// CreateTUN creates a Device with the provided name and MTU.
func CreateTUN() (Device, error) {
	tun := &NativeTun{
		events:   make(chan Event, 5),
		toWrite:  make([]int, 0, conn.IdealBatchSize),
		natTable: make(map[NATKey]NATValue),
		natRcv:   make(chan []byte),
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	clientId := "test-client-id"
	tun.nat = connect.NewLocalUserNatWithDefaults(
		cancelCtx,
		clientId,
	)
	removeCallback := tun.nat.AddReceivePacketCallback(tun.natReceive)
	tun.natCancel = func() {
		removeCallback()
		cancel()
	}

	return tun, nil
}

func (tun *NativeTun) natReceive(source connect.Path, ipProtocol connect.IpProtocol, packet []byte) {
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)

	if ipv4Layer := pkt.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		transportLayer := pkt.TransportLayer()
		if transportLayer == nil {
			fmt.Printf("No transport layer found in packet: %+x", packet)
			return
		}

		ipv4 := ipv4Layer.(*layers.IPv4)

		var dstPort int
		switch t := transportLayer.(type) {
		case *layers.TCP:
			dstPort = int(t.DstPort)
		case *layers.UDP:
			dstPort = int(t.DstPort)
		default:
			fmt.Printf("unsupported transport layer type: %T", t)
			return
		}

		natKey := NATKey{
			IP:   ipv4.DstIP.String(),
			Port: dstPort,
		}

		localDstIP, found := tun.natTable[natKey]
		if !found {
			fmt.Printf("no NAT entry found for %s:%d\n", ipv4.DstIP, dstPort)
			return
		}
		ipv4.DstIP = localDstIP.IP

		// set network layer for transport layer's checksum computation
		switch t := transportLayer.(type) {
		case *layers.TCP:
			t.SetNetworkLayerForChecksum(ipv4)
		case *layers.UDP:
			t.SetNetworkLayerForChecksum(ipv4)
		default:
			fmt.Printf("unsupported transport layer type: %T\n", t)
			return
		}

		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		err := gopacket.SerializeLayers(buffer, options, ipv4, transportLayer.(gopacket.SerializableLayer), gopacket.Payload(transportLayer.LayerPayload()))
		if err != nil {
			fmt.Printf("failed to serialize modified packet: %v\n", err)
			return
		}

		modifiedPacket := buffer.Bytes()
		tun.natRcv <- modifiedPacket
	} else {
		fmt.Println("Failed to parse IPv4 layer from the packet")
	}
}
