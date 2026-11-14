package main

import (
	"fmt"
	"log"

	"icool.io/yat/edge/internal/channel/wireguard"
)

func main() {
	coordinator := wireguard.NewMeshCoordinator()

	fmt.Println("=== Step 1: Create Network ===")
	network, err := coordinator.CreateNetwork(&wireguard.CreateNetworkRequest{
		ID:                "network-001",
		Name:              "MyDevNetwork",
		CIDR:              "10.100.0.0/16",
		CoordinatorEdgeID: "edge-abc123",
		RelayMode:         wireguard.RelayModeOptional,
	})
	if err != nil {
		log.Fatalf("Create network failed: %v", err)
	}
	fmt.Printf("Network created: id=%s, name=%s, cidr=%s, status=%d\n",
		network.ID, network.Name, network.CIDR, network.Status)

	fmt.Println("\n=== Step 2: Client A joins as owner ===")
	memberA, err := coordinator.JoinNetwork(&wireguard.JoinNetworkRequest{
		MemberID:  "member-A-001",
		NetworkID: network.ID,
		ClientID:  "client-A",
	})
	if err != nil {
		log.Fatalf("Client A join failed: %v", err)
	}
	fmt.Printf("Member A joined: id=%s, clientID=%s, ip=%s, status=%d\n",
		memberA.ID, memberA.ClientID, memberA.IP, memberA.Status)

	if err := coordinator.SetMemberOnline(memberA.ID); err != nil {
		log.Fatalf("Set A online failed: %v", err)
	}
	fmt.Printf("Member A is now online\n")

	fmt.Println("\n=== Step 3: Client B joins network ===")
	memberB, err := coordinator.JoinNetwork(&wireguard.JoinNetworkRequest{
		MemberID:  "member-B-001",
		NetworkID: network.ID,
		ClientID:  "client-B",
	})
	if err != nil {
		log.Fatalf("Client B join failed: %v", err)
	}
	fmt.Printf("Member B joined: id=%s, clientID=%s, ip=%s, status=%d\n",
		memberB.ID, memberB.ClientID, memberB.IP, memberB.Status)

	if err := coordinator.SetMemberOnline(memberB.ID); err != nil {
		log.Fatalf("Set B online failed: %v", err)
	}
	fmt.Printf("Member B is now online\n")

	fmt.Println("\n=== Step 4: List online members ===")
	onlineMembers := coordinator.ListOnlineMembers(network.ID)
	fmt.Printf("Online members count: %d\n", len(onlineMembers))
	for _, m := range onlineMembers {
		fmt.Printf("  - %s (ip: %s)\n", m.ClientID, m.IP)
	}

	fmt.Println("\n=== Network Overview ===")
	overview, err := coordinator.GetNetworkOverview(network.ID)
	if err != nil {
		log.Fatalf("Get overview failed: %v", err)
	}
	fmt.Printf("Network: %s (%s)\n", overview.Network.Name, overview.Network.ID)
	fmt.Printf("Members: %d\n", len(overview.Members))
	// Sessions removed (S5-B2): old session mechanism was dead code.

	fmt.Println("\n=== Done ===")
}
